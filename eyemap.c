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

static unsigned last_seen = 1;

static char buf[8 * 1024];
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
	else
		logmsg("Unable to read .last-seen");
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

		if (verbose > 1) {
			if (strncmp(fmt, "LOGIN", 5) == 0)
				printf("C: LOGIN\n");
			else
				printf("C: %s", buf);
		}

		n = ssl_write(buf, n + 2);
		if (n <= 0)
			return -1;

		sprintf(match, "a%03d OK", cmdno);
	} else
		strcpy(match, "* OK ");

	n = ssl_read(buf, sizeof(buf) - 1);
	if (n > 0) {
		buf[n] = 0;
		if (verbose > 1)
			printf("S:%d: %s", n, buf);
		if (strstr(buf, match))
			return 0;
		return 1;
	}

	return -1;
}

static int fetch(int uid)
{
	char match[16], *p;
	int n;

	curline = buf;

	++cmdno;
	n = sprintf(buf, "a%03d UID FETCH %d (BODY.PEEK[HEADER])\r\n", cmdno, uid);

	n = ssl_write(buf, n);
	if (n <= 0)
		return -1;

#if 0
	/* First read contains the size */
	n = ssl_read(buf, sizeof(buf));
	if (n <= 0)
		return -1;
	buf[n] = 0;

	// SAM Exchange does not give a size
	// SAM re?
	char *p = strchr(buf, '{');
	if (!p)
		return -1;
	int len = strtol(p + 1, &p, 10);
	if (*p != '}')
		return -1;
	p = strchr(buf, '\n');
	if (!p)
		return -1;
	len -= n - (p - buf - 1);

	if (len > sizeof(buf) - 40) {
		printf("HEADER TOO LARGE\n");
		return -1; // SAM what to do?
	}

	while (len > 0) {
		int got = ssl_read(buf + n, len);
		if (got > 0) {
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
	}

	char final[128];
	n = ssl_read(final, sizeof(final) - 1);
	if (n <= 0)
		return -1;

	final[n] = 0;

	p = final;
	if (strncmp(p, "\r\n", 2) == 0)
		p += 2;
	if (strncmp(p, ")\r\n", 3) == 0)
		p += 3;

	sprintf(match, "a%03d OK", cmdno);
	if (strncmp(p, match, strlen(match))) {
		printf("FAILED\n"); // SAM DBG
		puts(final); // SAM DBG
		return 1; // keep going... assume it was dealt with
	}

	return 0;
#else
	sprintf(match, "\na%03d ", cmdno);

	while (1) {
		// SAM buffer overflow
		int got = ssl_read(buf + n, sizeof(buf) - 1 - n);
		if (got > 0) {
			n += got;
			buf[n] = 0;
			// printf("read %d\n%s\n", n, buf); // SAM DBG
			// SAM HACK what if returns !OK?
			if ((p = strstr(buf, match))) {
				if (strncmp(p + strlen(match), "OK", 2) == 0) {
					puts("GOOD");
					return 0;
				}
				printf("Bad '%s'", p);
				return 1; // keep going... assume it was dealt with
			}
		} else if(got == 0) {
			perror("EOF");
			return -1;
		} else {
			perror("read");
			return -1;
		}
	}
#endif
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
again:
	n_uids = 0;

	if (send_recv("UID SEARCH UID %u:*", last_seen)) {
		printf("Search failed\n"); // SAM DBG
		return -1;
	}

	/* For some reason if we get "* 1 RECENT" we don't get the
	 * UIDs. Search again and we do.
	 */
	if (strstr(buf, "RECENT"))
		goto again;

	char *p = strstr(buf, "* SEARCH ");
	if (p) {
		p += 9;
		while ((uidlist[n_uids] = strtol(p, &p, 10)) > 0)
			// SAM what if we wrap?
			if (uidlist[n_uids] >= last_seen) {
				++n_uids;
				if (n_uids >= MAX_UIDS)
					break;
			}
	}

	return n_uids;
}

static int did_delete;

// Needed for logging
unsigned cur_uid;

int imap_move(const char *to)
{
	if (*to == '+') {
		++to;

		if (send_recv("UID STORE %u +FLAGS.SILENT (\\Seen)", cur_uid))
			return -1;
	}

	if (send_recv("UID COPY %u %s", cur_uid, to))
		return -1;

	did_delete = 1;
	return send_recv("UID STORE %u +FLAGS.SILENT (\\Deleted \\Seen)", cur_uid);
}

int process_list(void)
{
	int did_something = 0;
	did_delete = 0;

	do {
		if (build_list() < 0)
			return -1;

		for (int i = 0; i < n_uids; ++i) {
			cur_uid = uidlist[i];
			printf("Fetch %u\n", cur_uid);

			switch (fetch(cur_uid)) {
			case 0:
				filter();
				logit();
				break;
			case 1:
				break;
			default:
				puts("FAILED 2"); // SAM DBG
				return -1;
			}

			last_seen = cur_uid + 1;
			++did_something;
		}
	} while (n_uids);

	if (did_something)
		write_last_seen();

	if (did_delete)
		send_recv("EXPUNGE"); // mmmm... sponge...

	return 0;
}

#define POLLING
#ifdef POLLING
void run(void)
{
	while (1) {
		if (process_list())
			return;
		sleep(60);
	}
}
#else
/* Not sure if this is worth it. Seems to take just as long to get the
 * messages and we do risk missing one.
 */
static char *nowtime(void)
{
	static char nowstr[16];
	const time_t now = time(NULL);
	struct tm *tm = localtime(&now);
	sprintf(nowstr, "%02d:%02d:%02d",
			tm->tm_hour, tm->tm_min, tm->tm_sec);
	return nowstr;
}

// SAM doesn't work with exchange
void run(void)
{
	int n;

	// run it once to catch up
	process_list();

	while (1) {
		int rc = send_recv("IDLE");
		if (rc < 0)
			return;
		if (strstr(buf, "+ idling ") == NULL && // for compliant servers
			strstr(buf, "+ IDLE ") == NULL) // for exchange
			return;

		printf(">>> %s IDLING\n", nowtime()); // SAM DBG

		while (1) {
			n = ssl_timed_read(buf, sizeof(buf), 150000); // 2.5 minutes
			if (n < 0)
				return;
			if (n == 0) {
				puts("TIMEOUT"); // SAM DBG
				break; // timeout
			}
			printf(">>> %s %s", nowtime(), buf); // SAM DBG

			if (strstr(buf, "RECENT") && !strstr(buf, "* 0 RECENT"))
				break;
		}

		if (send_recv("DONE"))
			return;

		if (process_list())
			return;
	}
}
#endif

#define HANDLE_RC(msg) do {							\
		if (rc) {									\
			logmsg(msg);							\
			if ((rc) < 0)							\
				goto failed2;						\
			exit(2);								\
		}											\
	} while (0)

int connect_to_server(const char *server, int port,
					  const char *user, const char *passwd)
{
	int sock, rc;

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

	rc = send_recv(NULL);
	HANDLE_RC("Did not get server OK");

	rc = send_recv("LOGIN %s %s", user, passwd);
	HANDLE_RC("Login failed");

	rc = send_recv("SELECT INBOX");
	HANDLE_RC("Select failed");

	if (last_seen == 1)
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
