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

unsigned last_seen;

char buf[BR_SSL_BUFSIZE_INPUT + 1];
int cmdno;

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
		// printf("read %d\n%s\n", n, buf); // SAM DBG
		if (strstr(buf, match))
			return 0;
	}

	return -1;
}

static int fetch(int uid)
{
	char match[16];
	int n;

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
		return -1;
	}

	return 0;
}

#define MAX_UIDS 100
static unsigned uidlist[MAX_UIDS];
static int n_uids;

static int build_list(void)
{
	if (send_recv("UID SEARCH UID %d:*", last_seen)) {
		printf("Search failed\n");
		return -1;
	}

	n_uids = 0;
	for (char *p = buf; (p = strstr(p, "* SEARCH")); ) {
		if (n_uids < MAX_UIDS) {
			uidlist[n_uids++] = strtol(p + 8, &p, 10);
		}
	}

	return n_uids;
}

int process_list(void)
{
	do {
		build_list();

		for (int i = 0; i < n_uids; ++i) {
			if (fetch(uidlist[i]))
				return -1;

			// filter();

			last_seen = uidlist[i] + 1;
		}
	} while (n_uids);

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

	return sock; // connected

failed2:
	ssl_close();
failed:
	close(sock);
	goto again;
}

/*
int main(int argc, char *argv[])
{
	int sock = connect_to_server(IMAP_SERVER, IMAP_PORT, LOGIN, PASSWD);

	if (build_list() < 0)
		goto done;

	for (int i = 0; i < n_uids; ++i) {
		if (process_one(uidlist[i]) < 0)
			goto done;
	}

done:
	ssl_close();
	close(sock);

	return 0;
}
*/
