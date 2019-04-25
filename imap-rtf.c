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
#include <sys/wait.h>

int verbose;
int just_checking;
static const char *logfile;
static int log_verbose;
const char *home;
/* We only print the first 42 chars of subject */
static char subject[48] = { 'N', 'O', 'N', 'E' };
static char action = '?';
static int use_stderr;
static int dry_run;

static unsigned flags;
static const char *folder_match;

static const struct entry *saw_bl[2];
static int add_blacklist;

static char buff[8096];

void logit(void)
{
	if (!logfile || (action == 'h' && !log_verbose))
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
	fprintf(fp, "%10u %c%c%c%c%c%c%c%c--%c %c %.42s\n", cur_uid,
			'-', OUT(SAW_FROM, 'F'), OUT(SAW_DATE, 'D'),
			OUT(IS_HAM, 'H'), OUT(IS_IGNORED, 'I'), OUT(IS_SPAM, 'S'),
			'-', '-', '-', action, subject);

	if (add_blacklist) {
		int i;

		for (i = 0; i < 2; ++i)
			if (saw_bl[i])
				fprintf(fp, "%10u B%c-----%c--- %c %.42s\n", cur_uid,
						i ? 'S' : 'F', '-', action, saw_bl[i]->str);
	}

	if (ferror(fp))
		syslog(LOG_ERR, "%s: write error", logfile);

	fclose(fp);
}

static inline int write_string(char *str)
{
	strcat(str, "\n");
	return write(2, str, strlen(str));
}

void logmsg(const char *fmt, ...)
{
	va_list ap;
	char msg[128];

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg) - 1, fmt, ap);
	va_end(ap);

	if (use_stderr)
		write_string(msg);
	else
		syslog(LOG_INFO, "%s", msg);
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
	imap_move(path);
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

void filter(void)
{
	const struct entry *e;

	folder_match = NULL;

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

	home = getenv("HOME");
	if (!home) {
		syslog(LOG_WARNING, "You are homeless!");
		return 1;
	}

	rc = read_config();
	if (rc)
		return rc;
	if (just_checking)
		return 0;

	if (do_daemon) {
		if (daemon(1, 0))
			logmsg("daemon: %s", strerror(errno));
	}

	signal(SIGUSR1, need_reread);

	while (1) {
		int sock = connect_to_server(get_global("server"),
									 get_global_num("port"),
									 get_global("user"),
									 get_global("passwd"));

		run();

		ssl_close();
		close(sock);

		if (dry_run)
			exit(42);
	}
}
