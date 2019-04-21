#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "bearssl.h"
#include "rtf.h"

#define IMAP_SERVER "mail.papamail.net"
#define IMAP_PORT 993
#define LOGIN "seanm@seanm.ca"
#define PASSWD "fcpdkj04xv"

static unsigned last_seen;

static char buf[BR_SSL_BUFSIZE_INPUT + 1];
static char *curline;
static int cmdno;

static void write_last_seen(void)
{
	char path[100];

	snprintf(path, sizeof(path), "%s/.last-seen", home);
	FILE *fp = fopen(path, "w");
	fprintf(fp, "%u\n", last_seen);
	fclose(fp);
}

static void read_last_seen(void)
{
	char path[100], buf[32];

	snprintf(path, sizeof(path), "%s/.last-seen", home);
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return;
	int n = read(fd, buf, sizeof(buf));
	close(fd);

	if (n > 0)
		last_seen = strtol(buf, NULL, 10);
	else {
		logmsg("Unable to read .last-seen");
		last_seen = 1;
	}
}

static int send_recv(const char *fmt, ...)
{
	char match[16];
	int n;

	if (fmt) {
		va_list ap;

		++cmdno;
		n = sprintf(buf, "a%03d ", cmdno);
		va_start(ap, fmt);
		n += vsnprintf(buf + n, sizeof(buf) - n - 2, fmt, ap);
		va_end(ap);
		strcpy(buf + n, "\r\n");

		n = ssl_write(buf, n + 2);
		if (n <= 0)
			return -1;

		sprintf(match, "a%03d OK", cmdno);
	} else
		strcpy(match, "* OK IMAP");

	n = ssl_read(buf, sizeof(buf) - 1);
	if (n > 0) {
		buf[n] = 0;
		if (verbose > 1)
			printf("read %d\n%s\n", n, buf);if (strstr(buf, match))
			return 0;
	}

	return -1;
}

static int fetch(int uid)
{
	char match[16];
	int n;

	curline = buf;

	++cmdno;
	n = sprintf(buf, "a%03d UID FETCH %d (BODY.PEEK[HEADER])\r\n", cmdno, uid);

	n = ssl_write(buf, n);
	if (n <= 0)
		return -1;

	/* First read contains the size */
	n = ssl_read(buf, sizeof(buf));
	if (n <= 0)
		return -1;
	buf[n] = 0;

	printf("read %d\n", n); // SAM DBG

	// SAM re?
	char *p = strchr(buf, '{');
	if (!p)
		return -1;
	int len = strtol(p + 1, &p, 10);
	if (*p != '}')
		return -1;
	printf("len %d\n", len); // SAM DBG
	p = strchr(buf, '\n');
	if (!p)
		return -1;
	len -= n - (p - buf - 1);
	printf("First line overhead %ld\n", p - buf + 1); // SAM DBBG

	if (len > sizeof(buf) - 40) {
		printf("HEADER TOO LARGE\n");
		return -1; // SAM what to do?
	}

	while (len > 0) {
		int got = ssl_read(buf + n, len);
		if (got > 0) {
			// SAM FIXME - check for buffer overflow
			n += got;
			buf[n] = 0;
			// printf("read %d\n%s\n", n, buf); // SAM DBG
			// SAM HACK what if returns !OK?
		} else if(got == 0) {
			perror("EOF");
			return -1;
		} else {
			perror("read");
			return -1;
		}

		len -= got;
		printf("read %d len now %d\n", got, len); // SAM DBG
	}

	char final[128];
	n = ssl_read(final, sizeof(final) - 1);
	if (n <= 0)
		return -1;

	final[n] = 0;
	printf("final %d\n", n); // SAM DBG

	p = final;
	if (strncmp(p, "\r\n", 2) == 0)
		p += 2;
	if (strncmp(p, ")\r\n", 3) == 0)
		p += 3;

	sprintf(match, "a%03d OK", cmdno);
	printf("<%s>", p); // SAM DBG
	if (strncmp(p, match, strlen(match))) {
		printf("FAILED\n");
		return -1;
	}

	return 0;
}

char *fetchline(char *line, int len)
{
	if (!curline)
		return NULL;

	char *end = strchr(curline, '\n');
	if (end)
		*end++ = 0;
	snprintf(line, len, "%s", curline); // SAM strlcpy
	curline = end;
	return line;
}

#define MAX_UIDS 100
static unsigned uidlist[MAX_UIDS];
static int n_uids;

static int build_list(void)
{
	n_uids = 0;

	/* We cannot wildcard the end because 1995:* will match 1994 */
	if (send_recv("UID SEARCH UID %u:%u", last_seen, last_seen + MAX_UIDS)) {
		printf("Search failed\n"); // SAM DBG
		return -1;
	}

	for (char *p = buf; (p = strstr(p, "* SEARCH")); )
		uidlist[n_uids++] = strtol(p + 8, &p, 10);

	return n_uids;
}

// Needed for logging
unsigned cur_uid;

int imap_move(const char *to)
{
	if (send_recv("UID COPY %u %s", cur_uid, to))
		return -1;

	return send_recv("UID STORE %u +FLAGS.SILENT (\\Deleted \\Seen)", cur_uid);
}

int process_list(void)
{
	int did_something = 0;

	do {
		if (build_list() < 0)
			return -1;

		for (int i = 0; i < n_uids; ++i) {
			cur_uid = uidlist[i];
			printf("Fetch %u\n", cur_uid);

			if (fetch(cur_uid)) {
				puts("FAILED"); // SAM DBG
				return -1;
			}

			filter();

			last_seen = cur_uid + 1;
			++did_something;
		}
	} while (n_uids);

	if (did_something)
		write_last_seen();

	return 0;
}

int connect_to_server(const char *server, int port,
					  const char *user, const char *passwd)
{
	int sock;

	struct hostent *host = gethostbyname(server);
	if (!host) {
		logmsg("Unable to get host %s", server);
		exit(1);
	}

again:
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		logmsg("socket: %s", strerror(errno));
		goto failed;
	}

	int flags = 1;
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flags, sizeof(flags));

	struct sockaddr_in sock_name;
	memset(&sock_name, 0, sizeof(sock_name));
	sock_name.sin_family = AF_INET;
	sock_name.sin_addr.s_addr = *(uint32_t *)host->h_addr_list[0];
	sock_name.sin_port = htons(port);

	if (connect(sock, (struct sockaddr *)&sock_name, sizeof(sock_name))) {
		logmsg("connect: %s", strerror(errno));
		goto failed;
	}

	if (ssl_open(sock, server)) {
		logmsg("ssl_open failed");
		goto failed;
	}

	if (send_recv(NULL)) {
		printf("Did not get server OK\n");
		goto failed2;
	}

	if (send_recv("LOGIN %s %s", user, passwd)) {
		printf("Login failed\n");
		goto failed2;
	}

	if (send_recv("SELECT INBOX")) {
		printf("Select failed\n");
		goto failed2;
	}

	if (last_seen == 0)
		read_last_seen();

	if (verbose)
		printf("Connected. Last seen %u\n", last_seen);

	return sock; // connected

failed2:
	ssl_close();
failed:
	close(sock);
	goto again;
}
