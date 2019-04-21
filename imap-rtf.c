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
 * whitelist - To or From that should be marked ham
 * blacklist - From or Subject that should be marked spam
 * ignore - From that should be ignored
 * me - list of my emails (see below)
 *
 * Note: To includes To, Cc, and Bcc.
 *
 * Descisions:
 *
 * 1) The ignore list (ignore)
 * 2) Whitelist (ham)
 * 3) Blacklist (spam)
 * 4) Check if from me (spam)
 * 5) Check if the from and/or date fields are missing (spam)
 * 6) Optionally check if not on the me list (spam)
 *
 * Actions:
 *
 * Ham moved to inbox and left as new.
 * Spam moved to spam folder and marked as read.
 * Ignore moved to ignore folder and marked as read.
 * Application attachment moved to drop folder and marked as read.
 *
 * The from me (rule 4) is probably non-intuitive. I have my last name
 * white listed. All emails legitimately from me are of the form
 * <first name> <lastname> <email>. Spams are almost always just
 * <email>. So the whitelist catches the legitimate emails and the
 * "from me" catches the spams. We do get a few false positive hams
 * because of this.
 *
 * Notes:
 *
 * If you enable app checking, we need to read the entire email to
 * check for attachments. Normally, only the header needs to be read.
 *
 * You can put regular expressions in the list match strings. Regular
 * expressions start with a plus sign (+). All other strings are
 * literal and do not go through the regexp parser.
 *
 * Note that you are given the entire header line. This means you can
 * match on the field to differentiate say To: and Cc:.
 *
 * Other features:
 *
 * - folders
 */

/* Ideas that failed:
 *
 * - filter out utf from - too many false positives
 */

#include "rtf.h"
#include <sys/wait.h>
#include <regex.h>

static int run_drop;
static int just_checking;
static const char *logfile;
static const char *home;
/* We only print the first 42 chars of subject */
static char subject[48] = { 'N', 'O', 'N', 'E' };
static char action = '?';
static int use_stderr;

/* For dry_run you probably want file mode too. */
static int dry_run;

static unsigned flags;

struct entry {
	const char *str;
	const char *folder;
	regex_t *reg;
	struct entry *next;
};

static struct entry *global;
static struct entry *melist;
static struct entry *fromlist;
static struct entry *whitelist;
static struct entry *blacklist;
static struct entry *ignorelist;
static struct entry *folderlist;
static const  char *folder_match;

static const struct entry *saw_bl[2];
static int add_blacklist;

static char buff[8096];

/* /home/<user 32>/Maildir/tmp/<time 10>.<pid 5>.<hostname 64>
 * /home/<user 32>/Maildir/.Spam/cur/<time 10>.<pid 5>.<hostname 64>:2,S
 */
#define PATH_SIZE 144

static char tmp_file[84], tmp_path[PATH_SIZE];

/* Called at exit() */
static void logit(void)
{
	if (!logfile)
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
	fprintf(fp, "%-20s %c%c%c%c%c%c%c%c--%c %c %.42s\n", tmp_file,
			OUT(IS_ME, 'M'), OUT(SAW_FROM, 'F'), OUT(SAW_DATE, 'D'),
			OUT(IS_HAM, 'H'), OUT(IS_IGNORED, 'I'), OUT(IS_SPAM, 'S'),
			OUT(FROM_ME, 'f'), OUT(BOGO_SPAM, 'B'),
			OUT(FORWARD, 'F'), action, subject);

	if (add_blacklist) {
		int i;

		for (i = 0; i < 2; ++i)
			if (saw_bl[i])
				fprintf(fp, "%-20s B%c-----%c--- %c %.42s\n", tmp_file,
						i ? 'S' : 'F', OUT(BOGO_SPAM, 'B'),
						action, saw_bl[i]->str);
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

static int globals;

static int add_global(struct entry *new, char *str)
{
	char *p = strchr(str, '=');

	if (!p) {
		if (just_checking)
			printf("Bad global line '%s'\n", str);
		else
			syslog(LOG_WARNING, "Bad global line '%s'", str);
		return 1;
	}

	*p++ = 0;
	if (strcmp(str, "server") == 0)
		globals |= 1;
	else if (strcmp(str, "user") == 0)
		globals |= 2;
	else if (strcmp(str, "passwd") == 0)
		globals |= 4;
	else if (strcmp(str, "port") == 0)
		globals |= 8;
	else {
		if (just_checking)
			printf("Unknown global '%s'\n", str);
		else
			syslog(LOG_WARNING, "Unknown global '%s'", str);
		return 1;
	}

	new->str = strdup(str);
	new->folder = strdup(p);
	if (!new->str || !new->folder) {
		syslog(LOG_ERR, "Out of memory.");
		return 1; /* not fatal */
	}

	new->next = global;
	global = new;
	return 0;
}

static const char *get_global(const char *glob)
{
	for (struct entry *e = global; e; e = e->next)
		if (strcmp(e->str, glob) == 0)
			return e->folder;
	return "bogus";
}

static int get_global_num(const char *glob)
{
	return strtoul(get_global(glob), NULL, 10);
}

static int add_folder(struct entry *new, char *str)
{
	char *p = strchr(str, ',');

	if (just_checking) {
		if (!p)
			printf("Bad folder line '%s'\n", str);
#if IMAP_CHANGE
		else {
			char path[PATH_SIZE];
			snprintf(path, sizeof(path) - strlen(tmp_file), "%s/Maildir/%s/new", home, p + 1);
			if (access(path, F_OK))
				printf("Bad folder %s\n", path);
			return 0;
		}
#endif
	}

	if (!p) {
		syslog(LOG_WARNING, "folder line missing , '%s'", str);
		return 1;
	}

	*p++ = 0;
	new->str = strdup(str);
	new->folder = strdup(p);
	if (!new->str || !new->folder) {
		syslog(LOG_ERR, "Out of memory.");
		return 1; /* not fatal */
	}

	new->next = folderlist;
	folderlist = new;
	return 0;
}

static int add_entry(struct entry **head, char *str)
{
	struct entry *new = calloc(1, sizeof(struct entry));
	if (!new) goto oom;

	if (head == &global)
		return add_global(new, str);
	if (head == &folderlist)
		return add_folder(new, str);

	if (*str == '+') {
		new->reg = malloc(sizeof(regex_t));
		if (!new->reg) goto oom;

		int rc = regcomp(new->reg, str + 1, REGEXP_FLAGS);
		if (rc) {
			char err[80];

			regerror(rc, new->reg, err, sizeof(err));
			if (just_checking)
				printf("%s: %s\n", str, err);
			else
				syslog(LOG_WARNING, "Bad regexp '%s': %s", str, err);
			free(new->reg);
			free(new);
			return 1;
		}
	}

	if (!(new->str = strdup(str)))
		goto oom;

	new->next = *head;
	*head = new;
	return 0;

oom:
	syslog(LOG_ERR, "Out of memory.");
	exit(0);
}

static void blacklist_count(const struct entry *e, int index)
{
	saw_bl[index] = e;
}

static int read_config(void)
{
	char fname[PATH_SIZE];
	struct entry **head = NULL;
	int rc = 0;

	snprintf(fname, sizeof(fname), "%s/.rtf", home);

	FILE *fp = fopen(fname, "r");
	if (!fp) {
		if (errno != ENOENT) {
			perror(fname);
			syslog(LOG_WARNING, "%s: %m", fname);
		}
		return 1;
	}

	char line[128];
	while (fgets(line, sizeof(line), fp)) {
		char *p = strtok(line, "\r\n");
		if (!p || *p == '#')
			continue;
		if (*line == '[') {
			if (strcmp(line, "[global]") == 0)
				head = &global;
			else if (strcmp(line, "[whitelist]") == 0)
				head = &whitelist;
			else if (strcmp(line, "[blacklist]") == 0)
				head = &blacklist;
			else if (strcmp(line, "[ignore]") == 0)
				head = &ignorelist;
			else if (strcmp(line, "[me]") == 0)
				head = &melist;
			else if (strcmp(line, "[fromlist]") == 0)
				head = &fromlist;
			else if (strcmp(line, "[folders]") == 0)
				head = &folderlist;
			else {
				syslog(LOG_INFO, "Unexpected: %s\n", line);
				head = NULL;
			}
		} else if (head)
			rc |= add_entry(head, line);
	}

	fclose(fp);

	if ((globals & 15) != 15) {
		if (just_checking) {
			printf("Missing required globals\n");
			rc = 1;
		} else {
			syslog(LOG_ERR, "Missing required globals\n");
			exit(1);
		}
	}

	return rc;
}

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

	atexit(write_last_seen);
}

static void _safe_rename(const char *path)
{
	if (dry_run) {
		printf("Action %c\n", action);
		exit(0);
	}
	if (rename(tmp_path, path)) {
		syslog(LOG_WARNING, "%s: %m", path);
		unlink(tmp_path);
		exit(0); /* continue */
	}
}

static void ham(void)
{
	char path[PATH_SIZE];

	if (folder_match) {
		action = 'f';
		snprintf(path, sizeof(path), "%s/Maildir/%s/new/%s", home, folder_match, tmp_file);
	} else
		snprintf(path, sizeof(path), "%s/Maildir/new/%s", home, tmp_file);

	_safe_rename(path);
	exit(99); /* don't continue - we handled it */
}

static void safe_rename(const char *subdir)
{
	char path[PATH_SIZE];
	snprintf(path, sizeof(path), "%s/Maildir/%s/cur/%s:2,S", home, subdir, tmp_file);
	_safe_rename(path);
	exit(99); /* don't continue - we handled it */
}

static inline void spam(void) { safe_rename(SPAM_DIR); }

static inline void ignore(void) { safe_rename(IGNORE_DIR); }

static inline void drop(void) { safe_rename(DROP_DIR); }

static const struct entry *list_filter(const char *line, struct entry * const head)
{
	struct entry *e;

	for (e = head; e; e = e->next) {
		if (e->reg) {
			regmatch_t match[1];

			if (regexec(e->reg, line, 1, match, 0) == 0)
				return e;
		} else if (strcasestr(line, e->str))
			return e;
	}

	return NULL;
}

static inline void filter_from(const char *from)
{
	const struct entry *e;

	if (list_filter(from, whitelist))
		flags |= IS_HAM;
	if (list_filter(from, ignorelist))
		flags |= IS_IGNORED;
	if ((e = list_filter(from, blacklist))) {
		flags |= IS_SPAM;
		blacklist_count(e, 0);
	}
	if (list_filter(from, fromlist))
		flags |= FROM_ME;
}

static int isok(char c)
{
	switch (c) {
	case 'a'...'z':
	case 'A'...'Z':
	case '0'...'9':
		return 1;
	case '"':
		return 1;
	/* for mime decode e.g. =?utf-8?Q?Apple?= */
	case '=':
	case '?':
	case '-':
		return 1;
	default:
		return 0;
	}
}

/* Check for a one name from */
static void check_one_name_from(char *subject, char *from)
{
	from += 5; /* skip From: */
	while (isspace(*from)) ++from;
	while (isok(*from)) ++from;
	while (isspace(*from)) ++from;
	if (*from && *from != '<')
		return;

	/* We have a "one name" from */

	if (add_blacklist) {
		/* Add an entry to the blacklist count */
		struct entry *e = calloc(1, sizeof(struct entry));
		if (e) {
			e->str = "one name";
			blacklist_count(e, 1);
		}
	}

	action = 'S';
	spam();
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
	char *from = NULL;
	FILE *fp = fopen(tmp_path, "r");
	if (!fp) {
		syslog(LOG_WARNING, "%s: %m", tmp_path);
		unlink(tmp_path);
		exit(0);
	}

	while (getline(buff, sizeof(buff))) {
//		if (*buff == '\n')
//			break; /* end of header */
		if (strncasecmp(buff, "To:", 3) == 0 ||
				 strncasecmp(buff, "Cc:", 3) == 0 ||
				 strncasecmp(buff, "Bcc:", 4) == 0) {
			if (list_filter(buff, whitelist))
				flags |= IS_HAM;
			if (list_filter(buff, melist))
				flags |= IS_ME;
			if ((e = list_filter(buff, folderlist)))
				folder_match = e->folder;
		} else if (strncasecmp(buff, "From:", 5) == 0) {
			flags |= SAW_FROM;
			filter_from(buff);
			from = strdup(buff);
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

	fclose(fp);

	/* Rule 1 */
	if (flags & IS_IGNORED) {
		action = 'I';
		ignore();
	}
	/* Rule 2 */
	if (flags & IS_HAM) {
		action = 'H';
		ham();
	}
	/* Rule 3, 4, 6 */
	if ((flags & (IS_SPAM | BOGO_SPAM | FROM_ME)) ||
		/* Rule 5 */
		(flags & SAW_FROM) == 0 || (flags & SAW_DATE) == 0 ||
		/* Rule 7 */
		(run_drop && (flags & IS_ME) == 0)) {
		action = 'S';
		spam();
	}

	/* SAM HACK */
	check_one_name_from(subject, from);

	action = 'h';
	ham();
}

static void run(void)
{
	while (1) {
		if (process_list())
			return;
		sleep(60);
	}
}

static void usage(void)
{
	puts("usage:\trtf [-cdnC] [-l logfile] [-F file]\n"
		 "where:\t-c   add blacklist counts to logfile\n"
		 "\t-d   mark emails not 'from me' as spam\n"
		 "\t-h   this help\n"
		 "\t-n   dry run (mainly used with -F)\n"
		 "\t-C   just check the config file\n"
		 "\t     validates any regular expressions\n"
		);
}

int main(int argc, char *argv[])
{
	int c, rc;
	while ((c = getopt(argc, argv, "cdhl:nC")) != EOF)
		switch (c) {
		case 'c': add_blacklist = 1; break;
		case 'd': run_drop = 1; break;
		case 'h': usage(); exit(0);
		case 'l': logfile = optarg; break;
		case 'n': dry_run = 1; break;
		case 'C': just_checking = 1; break;
		}

	home = getenv("HOME");
	if (!home) {
		syslog(LOG_WARNING, "You are homeless!");
		return 1;
	}

	rc = read_config();
	if (just_checking)
		return rc;

	read_last_seen();

	if (logfile)
		atexit(logit);

	while (1) {
		int sock = connect_to_server(get_global("server"),
									 get_global_num("port"),
									 get_global("user"),
									 get_global("passwd"));

		run();

		ssl_close();
		close(sock);
		write_last_seen();

		if (dry_run)
			exit(42);
	}
}