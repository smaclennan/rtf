#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "bearssl.h"
#include "rtf.h"

char reply[BUFFER_SIZE];
static char *curline;
static int cmdno;

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

	if (verbose)
		printf("Connected.\n");

	return sock; // connected

failed2:
	ssl_close();
failed:
	close(sock);
	goto again;
}

static int check_one_folder(const char *folder)
{
	if (folder == NULL) return 0;
	if (strcmp(folder, "inbox") == 0) return 0;
	if (*folder == '+') ++folder;

	char *p = strstr(reply, folder);
	if (p == NULL) {
		printf("Missing %s\n", folder);
		return 1;
	}

	char *e = p + strlen(folder);
	if (*(p - 1) != ' ' || *e != '\r') {
		printf("Mismatch %s\n", folder);
		return 1;
	}

	return 0;
}

int check_folders(void)
{
	int rc = 0;
	int sock = connect_to_server(get_global("server"),
								 get_global_num("port"),
								 get_global("user"),
								 get_global("passwd"));

	send_recv("LIST \"\" \"*\"");

	for (struct entry *e = folderlist; e; e = e->next)
		rc |= check_one_folder(e->folder);

	rc |= check_one_folder(get_global("graylist"));
	rc |= check_one_folder(get_global("blacklist"));

	ssl_close();
	close(sock);
	return rc;
}
