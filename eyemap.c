#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "bearssl.h"
#include "rtf.h"

static unsigned last_seen = 1;

static char buf[BUFFER_SIZE];
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
	char match[16], *p;
	int n;

	curline = buf;

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

		sprintf(match, "a%03d ", cmdno);
	} else
		strcpy(match, "* ");

	char *cur = buf;
	int len = sizeof(buf);
	while (1) {
		n = ssl_read(cur, len - 1);
		if (n < 0)
			return -1;

		cur[n] = 0;
		if (verbose > 1)
			printf("S:%d: %s", n, cur);
		if ((p = strstr(cur, match))) {
			p += strlen(match);
			if (strncmp(p, "OK ", 3) == 0)
				return 0;
			return 1;
		}

		cur += n;
		len -= n;

		if (len < 2)
			return 0; /* try with what we have */
	}
}

char *fetchline(char *line, int len)
{
	if (!curline)
		return NULL;

	char *end = strchr(curline, '\n');
	if (end)
		*end++ = 0;
	/* We cannot overflow here since line size == buffer size */
	strcpy(line, curline);
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
			if (verbose)
				printf("Fetch %u\n", cur_uid);

			switch(send_recv("UID FETCH %d (BODY.PEEK[HEADER])", cur_uid)) {
			case 0:
				filter();
				logit();
				break;
			case 1:
				break;
			default:
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

static int reread_config;

void need_reread(int signo)
{
	reread_config = 1;
}

// Idling does not work with exchange... just poll
void run(void)
{
	while (1) {
		if (process_list())
			return;
		sleep(60);
		if (reread_config) {
			reread_config = 0;
			read_config();
		}
	}
}

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
