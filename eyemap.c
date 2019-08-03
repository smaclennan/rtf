#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "rtf.h"

char reply[BUFFER_SIZE];
static char *curline;
static int cmdno;
int is_exchange;

int send_cmd(const char *cmd)
{
	++cmdno;
	int n = sprintf(reply, "a%03d %s\r\n", cmdno, cmd);

	if (verbose > 1)
		printf("C: %s", reply);

	return ssl_write(reply, n);
}

int send_recv(const char *fmt, ...)
{
	char match[16], *p;
	int n;

	curline = reply;

	if (fmt) {
		va_list ap;

		++cmdno;
		n = sprintf(reply, "a%03d ", cmdno);
		va_start(ap, fmt);
		n += vsnprintf(reply + n, sizeof(reply) - n - 2, fmt, ap);
		va_end(ap);
		strcpy(reply + n, "\r\n");

		if (verbose > 1) {
			if (strncmp(fmt, "LOGIN", 5) == 0)
				printf("C: LOGIN\n");
			else
				printf("C: %s", reply);
		}

		n = ssl_write(reply, n + 2);
		if (n <= 0)
			return -1;

		sprintf(match, "a%03d ", cmdno);
	} else
		strcpy(match, "* ");

	char *cur = reply;
	int len = sizeof(reply);
	while (1) {
		n = ssl_read(cur, len - 1);
		if (n < 0)
			return -1;

		uid_validity();

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

/* The only purpose of this function is to not display the email
 * headers if -vv. This makes it easier to log protocol messages.
 * -vvv will display the headers.
 */
int fetch(unsigned uid)
{
	int verbose_save = verbose;

	if (verbose) {
		printf("C: UID FETCH %u (BODY.PEEK[HEADER])\n", uid);
		if (verbose == 2)
			verbose = 0;
	}

	int rc = send_recv("UID FETCH %u (BODY.PEEK[HEADER])", uid);

	verbose = verbose_save;
	if (verbose == 2) {
		char *p = strchr(reply, '\n');
		*p = 0;
		printf("S: %s\n", reply);
		*p = '\n';
	}

	return rc;
}

int fetchline(char *line, int len)
{
	if (!curline)
		return 0;

	char *end = strchr(curline, '\n');
	if (end)
		*end++ = 0;
	/* We cannot overflow here since line size == buffer size */
	strcpy(line, curline);
	curline = end;
	return 1;
}

static void get_hostip(const char *server, unsigned connected, uint32_t *host_ip)
{
	struct hostent *host = gethostbyname(server);
	if (host)
		*host_ip = *(uint32_t *)host->h_addr_list[0];
	else {
		logmsg("Unable to get host %s (%d)", server, connected);
		if (connected == 0)
			exit(1);
		// retry old host
	}
}

#define HANDLE_RC(msg) do {							\
		if (rc) {									\
			logmsg(msg);							\
			if ((rc) < 0)							\
				goto failed2;						\
			if (connected)							\
				goto failed2;						\
			exit(2);								\
		}											\
	} while (0)

int connect_to_server(const char *server, int port,
					  const char *user, const char *passwd)
{
	static unsigned connected;
	static uint32_t host_ip;

again:
	get_hostip(server, connected, &host_ip);

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		logmsg("socket: %s", strerror(errno));
		goto failed;
	}

	int flags = 1;
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flags, sizeof(flags));

	struct sockaddr_in sock_name;
	memset(&sock_name, 0, sizeof(sock_name));
	sock_name.sin_family = AF_INET;
	sock_name.sin_addr.s_addr = host_ip;
	sock_name.sin_port = htons(port);

	if (connect(sock, (struct sockaddr *)&sock_name, sizeof(sock_name))) {
		logmsg("connect: %s", strerror(errno));
		goto failed;
	}

	if (ssl_open(sock, server)) {
		logmsg("ssl_open failed");
		goto failed;
	}

	int rc = send_recv(NULL);
	HANDLE_RC("Did not get server OK");

	is_exchange = strstr(reply, "Microsoft Exchange") != NULL;

	rc = send_recv("LOGIN %s %s", user, passwd);
	HANDLE_RC("Login failed");

	rc = send_recv("SELECT INBOX");
	HANDLE_RC("Select failed");

	if (verbose)
		printf("Connected.\n");

	connected = 1;

	return sock; // connected

failed2:
	ssl_close();
failed:
	close(sock);
	sleep(5);
	goto again;
}
