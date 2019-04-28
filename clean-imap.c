/* clean-imap.c - clean up folders
 * Copyright (C) 2019 Sean MacLennan <seanm@seanm.ca>
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

#include "rtf.h"
#include <time.h>

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

static char buff[BUFFER_SIZE];

#define MAX_UIDS 100
static unsigned uidlist[MAX_UIDS];
static int n_uids;
static int did_delete;
static int reread_config;
static unsigned last_seen = 1;
static unsigned cur_uid;

static void logit(void)
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

static const char *months[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

static char *datestr(const char *days)
{
	static char date[16];
	char *e;
	unsigned n_days = strtoul(days, &e, 10);
	if (n_days < 2 || *e) {
		printf("Bad datestr %s\n", days);
		exit(1); // SAM FIXME
	}
	time_t now = time(NULL);
	struct tm *tm = gmtime(&now);
	tm->tm_mday -= n_days;
	now = mktime(tm);
	tm = gmtime(&now);
	sprintf(date, "%d-%s-%d", tm->tm_mday, months[tm->tm_mon], tm->tm_year + 1900);
	return date;
}

int main(int argc, char *argv[])
{
	int c, rc;
	while ((c = getopt(argc, argv, "dv")) != EOF)
		switch (c) {
		case 'd': home = optarg; break;
		case 'v': ++verbose; break;
		}

	if (!home) {
		home = getenv("HOME");
		if (!home) {
			syslog(LOG_WARNING, "You are homeless!");
			return 1;
		}
	}

	rc = read_config();
	if (rc)
		return 1;

	if (!cleanlist)
		return 0; // nothing to do

	int sock = connect_to_server(get_global("server"),
								 get_global_num("port"),
								 get_global("user"),
								 get_global("passwd"));

	// SAM FIXME check returns
	rc = 1;
	for (struct entry *e = cleanlist; e; e = e->next) {
		send_recv("SELECT %s", e->str);
		send_recv("UID SEARCH SENTBEFORE %s", datestr(e->folder));
		char *p = strstr(reply, "* SEARCH ");
		if (p) {
			p += 9;
			char *e = strchr(p, '\n');
			if (e) {
				*e = 0;

				strcpy(buff, p); // save list
				p = buff;

				unsigned uid;
				while ((uid = strtol(p, &p, 10)) > 0) {
					send_recv("UID STORE %u +FLAGS.SILENT (\\Seen \\Deleted)", uid);
				}

				send_recv("EXPUNGE");
			}
		}
	}

	rc = 0;

done:
	ssl_close();
	close(sock);
	return rc;
}
