/* rtf.c - Really Trivial Filter
 * Copyright (C) 2012-2018 Sean MacLennan <seanm@seanm.ca>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* This is a Really Trivial Filter(tm) that allows for filtering email.
 *
 * The filter lists:
 *
 * global - Global settings such as server and user
 * whitelist - To or From that should be marked ham
 * graylist - From that should be ignored
 * blacklist - From or Subject that should be marked spam
 * folders - Email filtering
 *
 * Note: To includes To, Cc, and Bcc.
 *
 * Folder rules: <match>=+?<folder>
 *
 * If a + is put before the folder, the message is also marked read.
 *
 * If folder is the special folder inbox, then we stop traversing the
 * folder list and just leave the message in the INBOX.
 * For example:
 *     [folders]
 *     john Smith=inbox
 *     smith=Smith Folder
 * This would put all Smith's in the Smith Folder except John Smith.
 */

#include "rtf.h"
#include <sys/signal.h>

#define RFC2177_TIMEOUT (29 * 60 * 1000) // 29 minutes in ms

int just_checking;
static const char *logfile;
static int log_verbose;
/* We only print the first 54 chars of subject */
static char subject[55];
static char action = '?';
static int dry_run;

static unsigned flags;
static const char *folder_match;

static const struct entry *saw_bl[2];
static int add_blacklist;

static char buff[BUFFER_SIZE];

#define MAX_UIDS 100
static unsigned uidlist[MAX_UIDS];
static int n_uids;
static int did_delete;
static int reread_config;
static unsigned last_seen = 1;
static unsigned cur_uid;

static void logit(char action, const char *subject, unsigned cur_uid)
{
	if (!logfile || (action == 'h' && !log_verbose) || dry_run)
		return;

	FILE *fp = fopen(logfile, "a");
	if (!fp) {
		syslog(LOG_ERR, "%s: %m", logfile);
		return;
	}

	if (flock(fileno(fp), LOCK_EX)) {
		syslog(LOG_ERR, "%s: flock: %m", logfile);
		/* keep going even if we don't get the lock */
	}

#define OUT(a, c) ((flags & (a)) ? (c) : '-')
	/* Last two flags are for learnem */
	fprintf(fp, "%10u %c%c%c%c%c%c%c%c--%c %c %.54s\n", cur_uid,
			'-', OUT(SAW_FROM, 'F'), OUT(SAW_DATE, 'D'),
			OUT(IS_HAM, 'H'), OUT(IS_IGNORED, 'I'), OUT(IS_SPAM, 'S'),
			'-', '-', '-', action, subject);

	if (add_blacklist) {
		int i;

		for (i = 0; i < 2; ++i)
			if (saw_bl[i])
				fprintf(fp, "%10u B%c-----%c--- %c %.54s\n", cur_uid,
						i ? 'S' : 'F', '-', action, saw_bl[i]->str);
	}

	if (ferror(fp))
		syslog(LOG_ERR, "%s: write error", logfile);

	fclose(fp);
}

static void blacklist_count(const struct entry *e, int index)
{
	saw_bl[index] = e;
}

static void safe_rename(const char *path)
{
	if (dry_run) {
		printf("Action %c\n", action);
		return;
	}

	if (*path == '+') {
		++path;

		if (send_recv("UID STORE %u +FLAGS.SILENT (\\Seen)", cur_uid))
			return;
	}

	if (send_recv("UID COPY %u %s", cur_uid, path))
		return;

	did_delete = 1;
	send_recv("UID STORE %u +FLAGS.SILENT (\\Deleted \\Seen)", cur_uid);
}

static void ham(void)
{
	if (folder_match && strcmp(folder_match, "inbox")) {
		action = 'f';
		safe_rename(folder_match);
	}
}

static inline void spam(void) { safe_rename(get_global("blacklist")); }

static inline void ignore(void) { safe_rename(get_global("graylist")); }

static const struct entry *list_filter(const char *line, struct entry * const head)
{
	struct entry *e;

	for (e = head; e; e = e->next)
		if (strcasestr(line, e->str))
			return e;

	return NULL;
}

static inline void filter_from(const char *from)
{
	const struct entry *e;

	if (list_filter(from, whitelist))
		flags |= IS_HAM;
	if (list_filter(from, graylist))
		flags |= IS_IGNORED;
	if ((e = list_filter(from, blacklist))) {
		flags |= IS_SPAM;
		blacklist_count(e, 0);
	}
}

static void normalize_subject(const char *str)
{
	str += 8; /* skip subject: */
	while (isspace(*str)) ++str;
	if (!*str) {
		strcpy(subject, "EMPTY");
		return;
	}

	int i, end = 0;
	for (i = 0; *str && i < sizeof(subject) - 1; ++i, ++str) {
		subject[i] = *str;
		if (!isspace(*str)) {
			end = i;
			if (!isprint(*str))
				subject[i] = '~';
		}
	}
	subject[end + 1] = 0;
}

static void filter(void)
{
	const struct entry *e;

	strcpy(subject, "NONE");
	flags = 0;
	folder_match = NULL;
	memset(saw_bl, 0, sizeof(saw_bl));

	while (fetchline(buff, sizeof(buff))) {
		if (strncasecmp(buff, "To:", 3) == 0 ||
				 strncasecmp(buff, "Cc:", 3) == 0 ||
				 strncasecmp(buff, "Bcc:", 4) == 0) {
			if (list_filter(buff, whitelist))
				flags |= IS_HAM;
			if ((e = list_filter(buff, folderlist)))
				folder_match = e->folder;
		} else if (strncasecmp(buff, "From:", 5) == 0) {
			flags |= SAW_FROM;
			filter_from(buff);
			if ((e = list_filter(buff, folderlist)))
				folder_match = e->folder;
		} else if (strncasecmp(buff, "Subject:", 8) == 0) {
			normalize_subject(buff);
			if ((e = list_filter(buff, blacklist))) {
				flags |= IS_SPAM;
				blacklist_count(e, 1);
			} else if ((e = list_filter(buff, folderlist)))
				folder_match = e->folder;
		} else if (strncasecmp(buff, "Date:", 5) == 0)
			flags |= SAW_DATE;
		else if (strncasecmp(buff, "List-Post:", 10) == 0) {
			if ((e = list_filter(buff, folderlist)))
				folder_match = e->folder;
		} else if (strncasecmp(buff, "Return-Path:", 12) == 0) {
			filter_from(buff);
		}
	}

	if (flags & IS_IGNORED) {
		action = 'I';
		ignore();
	} else if (flags & IS_HAM) {
		action = 'H';
		ham();
	} else if ((flags & IS_SPAM) ||
			   (flags & SAW_FROM) == 0 || (flags & SAW_DATE) == 0) {
		action = 'S';
		spam();
	} else {
		action = 'h';
		ham();
	}
}

static void read_last_seen(void)
{
	char path[100], buf[32];

	snprintf(path, sizeof(path), "%s/.last-seen", home);
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return;
	int n = read(fd, buff, sizeof(buf));
	close(fd);

	if (n > 0) {
		last_seen = strtol(buff, NULL, 10);
		if (verbose)
			printf("Last seen %u\n", last_seen);
	} else
		logmsg("Unable to read .last-seen");
}

static void write_last_seen(void)
{
	char path[100];

	snprintf(path, sizeof(path), "%s/.last-seen", home);
	FILE *fp = fopen(path, "w");
	fprintf(fp, "%u\n", last_seen);
	fclose(fp);
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

	for (struct entry *e = cleanlist; e; e = e->next)
		rc |= check_one_folder(e->str);

	rc |= check_one_folder(get_global("graylist"));
	rc |= check_one_folder(get_global("blacklist"));

	ssl_close();
	close(sock);
	return rc;
}

static void need_reread(int signo)
{
	reread_config = 1;
}

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
	if (strstr(reply, "RECENT"))
		goto again;

	char *p = strstr(reply, "* SEARCH ");
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

static int process_list(void)
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

			switch(fetch(cur_uid)) {
			case 0:
				filter();
				logit(action, subject, cur_uid);
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

static void run(void)
{
#if 0
	while (1) {
		if (process_list())
			return;
		sleep(60);
		if (reread_config) {
			reread_config = 0;
			read_config();
		}
	}
#else
	/* RFC2177 recommends timing out the idle every 29 minutes.
	 * However, exchange seems to reset the connection after
	 * about 5 minutes.
	 */
	int timeout = is_exchange ? 240000 : RFC2177_TIMEOUT;

	while (1) {
		int n;

		if (reread_config) {
			reread_config = 0;
			read_config();
		}

		if (process_list())
			return;

		if (send_cmd("IDLE") <= 0)
			return;

		n = ssl_read(buff, sizeof(buff) - 1);
		if (n <= 0)
			return;
		buff[n] = 0;
		if (verbose)
			printf("S: %s", buff);
		if (strncmp(buff, "+ idling", 8) && strncmp(buff, "+ IDLE", 6)) {
			return;
		}

		while (1) {
			n = ssl_timed_read(buff, sizeof(buff) - 1, timeout);
			if (n == 0)
				break;
			if (n < 0)
				return;
			buff[n] = 0;

			if (verbose)
				printf("S: %s", buff);

			if (strstr(buff, "RECENT"))
				break;
		}

		if (ssl_write("DONE\r\n", 6) <= 0)
			return;
		if (verbose)
			puts("C: DONE");

		n = ssl_read(buff, sizeof(buff) - 1);
		if (n <= 0)
			return;
		buff[n] = 0;

		if (verbose)
			printf("S: %s", buff);
		if (strstr(buff, " OK ") == NULL)
			return;
	}
#endif
}

static void usage(void)
{
	puts("usage:\trtf [-cdnC] [-{lL} logfile]\n"
		 "where:\t-c   add blacklist counts to logfile\n"
		 "\t-d   daemonize\n"
		 "\t-h   this help\n"
		 "\t-n   dry run\n"
		 "\t-C   just check the config file\n"
		 "-l only logs messages that match a rule, -L logs everything."
		);
}

int main(int argc, char *argv[])
{
	int c, rc, do_daemon = 0;
	while ((c = getopt(argc, argv, "cdhl:nvC")) != EOF)
		switch (c) {
		case 'c': add_blacklist = 1; break;
		case 'd': do_daemon = 1; break;
		case 'h': usage(); exit(0);
		case 'L': log_verbose = 1; // fall thru
		case 'l': logfile = optarg; break;
		case 'n': dry_run = 1; break;
		case 'v': ++verbose; break;
		case 'C': just_checking = 1; use_stderr = 1; break;
		}

	rc = read_config();
	if (rc)
		return rc;
	if (just_checking)
		return check_folders();

	if (do_daemon) {
		if (daemon(1, 0))
			logmsg("daemon: %s", strerror(errno));
	}

	signal(SIGUSR1, need_reread);

	read_last_seen();

	// Log the start
	logit('C', "Start", time(NULL));

	while (1) {
		int sock = connect_to_server(get_global("server"),
									 get_global_num("port"),
									 get_global("user"),
									 get_global("passwd"));

		// Log the connect
		flags = 0;
		logit('C', "Connect", time(NULL));

		run();

		ssl_close();
		close(sock);

		if (dry_run)
			exit(42);
	}
}
