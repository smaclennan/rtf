/* rtf.c - Really Trivial Filter
 * Copyright (C) 2012-2016 Sean MacLennan <seanm@seanm.ca>
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
 * me - list of my emails (see below)
 * ignore - From that should be ignored
 *
 * Note: To includes To, Cc, and Bcc.
 *
 * Descisions:
 *
 * 1) The ignore list (ignore)
 * 2) Whitelist (ham)
 * 3) Saw application attachment (spam)
 * 4) Blacklist (spam)
 * 5) Check if the from and/or date fields are missing (spam)
 * 6) Check if from me (spam)
 * 7) Optionally check if not on the me list (spam)
 * 8) Optionally runs the emails through bogofilter (ham or spam)
 *
 * Actions:
 *
 * Ham moved to inbox and left as new.
 * Spam moved to spam folder and marked as read.
 * Ignore moved to ignore folder and marked as read.
 *
 * The from me (rule 6) is probably non-intuitive. I have my last name
 * white listed. All emails legitimately from me are of the form
 * <first name> <lastname> <email>. Spams are always just <email>. So
 * the whitelist catches the legitimate emails and the "from me"
 * catches the spams.
 */

#include "rtf.h"
#include <sys/wait.h>

#define BOGOFILTER "bogofilter"

static int run_bogo;
static int train_bogo;
static int run_drop;
static int drop_apps;
static const char *logfile;
static const char *home;
static char *subject = "NONE";
static char action = '?';

/* For dry_run you probably want file mode too. */
static int dry_run;

/* File mode is a special case for running rtf on existing email. It
 * will move the mail to the spam or drop or ignore folders but leaves
 * ham alone.
 *
 * File mode can only handle one file at a time.
 */
static const char *file_mode;

static unsigned flags;

struct entry {
	const char *str;
	struct entry *next;
};

static struct entry *melist;
static struct entry *whitelist;
static struct entry *blacklist;
static struct entry *ignorelist;

static char buff[8096];

/* /home/<user 32>/Maildir/tmp/<time 10>.<pid 5>.<hostname 64>
 * /home/<user 32>/Maildir/.Spam/cur/<time 10>.<pid 5>.<hostname 64>:2,S
 */
#define PATH_SIZE 144

static char tmp_file[84], tmp_path[PATH_SIZE];

/* Not NFS safe and I don't care. */
static int create_tmp_file(void)
{
	char hostname[64];
	if (gethostname(hostname, sizeof(hostname))) {
		syslog(LOG_ERR, "Hostname: %m");
		return -1;
	}

	const char *dtline = getenv("DTLINE");
	const char *rpline = getenv("RPLINE");
	if (!dtline || !rpline) {
		syslog(LOG_ERR, "Missing required environment variables.");
		return -1;
	}

	snprintf(tmp_file, sizeof(tmp_file), "%ld.%d.%s",
			 time(NULL), getpid(), hostname);
	snprintf(tmp_path, sizeof(tmp_path), "%s/Maildir/tmp/%s", home, tmp_file);
	int fd = creat(tmp_path, 0644);
	if (fd < 0) {
		syslog(LOG_ERR, "%s: %m", tmp_path);
		return -1;
	}

	/* Sanitize the environment variables */
	const char *p;
	for (p = rpline; *p; ++p)
		if (isascii(*p))
			if (write(fd, p, 1) != 1)
				goto write_error;
	for (p = dtline; *p; ++p)
		if (isascii(*p))
			if (write(fd, p, 1) != 1)
				goto write_error;

	/* Read the email */
	int n;
	while ((n = read(0, buff, sizeof(buff))) > 0)
		if (write(fd, buff, n) != n)
			goto write_error;

	if (n < 0)
		goto write_error;

	close(fd);

	return 0;

write_error:
	syslog(LOG_ERR, "%s: write error", tmp_path);
	close(fd);
	unlink(tmp_path);
	return -1;
}

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

	char *p = subject;
	if (strncmp(subject, "Subject: ", 9) == 0)
		p += 9;

#define OUT(a, c) ((flags & (a)) ? (c) : '-')
	/* Last two flags are for learnem */
	char spam = '-';
	switch (flags & (IS_SPAM | SAW_APP)) {
	case IS_SPAM: spam = 'S'; break;
	case SAW_APP: spam = 'A'; break;
	case IS_SPAM | SAW_APP: spam = 'Z'; break;
	}
	fprintf(fp, "%-20s %c%c%c%c%c%c%c%c-- %c %.42s\n", tmp_file,
			OUT(IS_ME, 'M'), OUT(SAW_FROM, 'F'), OUT(SAW_DATE, 'D'),
			OUT(IS_HAM, 'H'), OUT(IS_IGNORED, 'I'), spam,
			OUT(FROM_ME, 'f'), OUT(BOGO_SPAM, 'B'), action, p);

	if (ferror(fp))
		syslog(LOG_ERR, "%s: write error", logfile);

	fclose(fp);
}

static void add_entry(struct entry **head, const char *str)
{
	struct entry *new = malloc(sizeof(struct entry));
	if (!new) goto oom;

	if (!(new->str = strdup(str))) {
		free(new);
		goto oom;
	}

	new->next = *head;
	*head = new;
	return;

oom:
	syslog(LOG_WARNING, "Out of memory.");
}

static int read_config(void)
{
	char fname[PATH_SIZE];
	struct entry **head = NULL;

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
			if (strcmp(line, "[whitelist]") == 0)
				head = &whitelist;
			else if (strcmp(line, "[blacklist]") == 0)
				head = &blacklist;
			else if (strcmp(line, "[ignore]") == 0)
				head = &ignorelist;
			else if (strcmp(line, "[me]") == 0)
				head = &melist;
			else {
				syslog(LOG_INFO, "Unexpected: %s\n", line);
				head = NULL;
			}
		} else if (head)
			add_entry(head, line);
	}

	fclose(fp);
	return 0;
}

static int run_bogofilter(const char *fname, char *flags)
{
	if (run_bogo) {
		char cmd[256];
		snprintf(cmd, sizeof(cmd) - 3, "%s %s -B %s", BOGOFILTER, flags, fname);
		return WEXITSTATUS(system(cmd));
	} else
		return 1; /* mark as non-spam */
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

	exit(99); /* don't continue - we handled it */
}

static void ham(void)
{
	if (!file_mode) {
		char path[PATH_SIZE];
		snprintf(path, sizeof(path), "%s/Maildir/new/%s", home, tmp_file);
		_safe_rename(path);
	}
}

static void safe_rename(const char *subdir)
{
	char path[PATH_SIZE];
	snprintf(path, sizeof(path), "%s/Maildir/%s/cur/%s:2,S", home, subdir, tmp_file);
	_safe_rename(path);
}

static inline void spam(void) { safe_rename(SPAM_DIR); }

static inline void ignore(void) { safe_rename(IGNORE_DIR); }

static inline void drop(void) { safe_rename(DROP_DIR); }

static int list_filter(char *line, struct entry *head)
{
	struct entry *e;

	for (e = head; e; e = e->next)
		if (strcasestr(line, e->str))
			return 1;

	return 0;
}

/* Returns 1 if type should be dropped */
static int check_type(const char *type)
{
	while (isspace(*type))
		++type;

	if (strncasecmp(type, "application/", 12))
		return 0;

	type += 12;

	switch (*type) {
	case 'x':
		/* Catch x-compress and x-compressed */
		if (strncmp(type, "x-compress", 10) == 0)
			return 1;
		/* x-zip and x-zip-compressed */
		if (strncmp(type, "x-zip", 5) == 0)
			return 1;
		/* x-rar and x-rar-compressed */
		if (strncmp(type, "x-rar", 5) == 0)
			return 1;
		break;
	case 'z':
		if (strncmp(type, "zip", 3) == 0)
			return 1;
		break;
	case 'r':
		if (strncmp(type, "rar", 5) == 0)
			return 1;
		break;
	case 'v':
		/* Not sure about these... */
		if (drop_apps > 1) {
			if (strncmp(type, "vnd.ms-word.document.macroEnabled", 33) == 0)
				return 1;
			if (strncmp(type, "vnd.ms-excel", 12) == 0)
				return 1;
		}
		break;
	case 'o':
		if (strncmp(type, "octet-stream", 12) == 0)
			return 1;
		break;
	}

	return 0;
}

static void filter(void)
{
	FILE *fp = fopen(tmp_path, "r");
	if (!fp) {
		syslog(LOG_WARNING, "%s: %m", tmp_path);
		unlink(tmp_path);
		exit(0);
	}

	while (fgets(buff, sizeof(buff), fp)) {
		if (*buff == '\n')
			break; /* end of buff */
		else if (strncmp(buff, "To:", 3) == 0 ||
				 strncmp(buff, "Cc:", 3) == 0 ||
				 strncmp(buff, "CC:", 3) == 0 ||
				 strncmp(buff, "Bcc:", 4) == 0) {
			if (list_filter(buff, whitelist))
				flags |= IS_HAM;
			if (list_filter(buff, melist))
				flags |= IS_ME;
		} else if (strncmp(buff, "From:", 5) == 0) {
			flags |= SAW_FROM;
			if (list_filter(buff, whitelist))
				flags |= IS_HAM;
			if (list_filter(buff, ignorelist))
				flags |= IS_IGNORED;
			if (list_filter(buff, blacklist))
				flags |= IS_SPAM;
			if (list_filter(buff, melist))
				flags |= FROM_ME;
		} else if (strncmp(buff, "Subject:", 8) == 0) {
			if ((subject = strdup(buff)))
				strtok(subject, "\r\n");
			else
				subject = "NOMEM";
			if (list_filter(buff, blacklist))
				flags |= IS_SPAM;
		} else if (strncmp(buff, "Date:", 5) == 0)
			flags |= SAW_DATE;
		else if (strncasecmp(buff, "Content-Type:", 13) == 0) {
			if (check_type(buff + 13))
				flags |= SAW_APP;
		}
	}

	if (drop_apps && !(flags & SAW_APP))
		while (fgets(buff, sizeof(buff), fp))
			if (strncasecmp(buff, "Content-Type:", 13) == 0)
				if (check_type(buff + 13)) {
					flags |= SAW_APP;
					break;
				}

	fclose(fp);

	if (!train_bogo)
		/* Just check the mail... do not update the word lists */
		if (run_bogofilter(tmp_path, "") == 0)
			flags |= BOGO_SPAM;

	if (flags & IS_IGNORED) {
		/* Tell bogofilter this is ham */
		action = 'I';
		run_bogofilter(tmp_path, "-n");
		ignore();
	}
	if (flags & IS_HAM) {
		/* Tell bogofilter this is ham */
		action = 'H';
		run_bogofilter(tmp_path, "-n");
		ham();
	}
	if ((flags & (IS_SPAM | BOGO_SPAM | FROM_ME)) ||
		(flags & SAW_FROM) == 0 || (flags & SAW_DATE) == 0 ||
		(run_drop && (flags & IS_ME) == 0)) {
		/* Tell bogofilter this is spam */
		action = 'S';
		run_bogofilter(tmp_path, "-s");
		spam();
	}
	if (flags & SAW_APP) {
		action = 'D';
		run_bogofilter(tmp_path, "-s");
		drop();
	}

	action = 'h';
	run_bogofilter(tmp_path, "-n");
	ham();
}

static int setup_file(const char *fname)
{
	if (*fname != '/') {
		printf("File must be fully rooted!\n");
		exit(1);
	}

	/* tmp_path is just fname */
	snprintf(tmp_path, sizeof(tmp_path), "%s", fname);

	/* tmp_file must be the raw basename */
	char *p = strrchr(fname, '/');
	snprintf(tmp_file, sizeof(tmp_file), "%s", p + 1);
	p = strchr(tmp_file, ':');
	if (p)
		*p = '\0';

	return 0;
}

int main(int argc, char *argv[])
{
	int c, rc;
	while ((c = getopt(argc, argv, "abdl:nF:T")) != EOF)
		switch (c) {
		case 'a': ++drop_apps; break;
		case 'b': run_bogo = 1; break;
		case 'd': run_drop = 1; break;
		case 'l': logfile = optarg; break;
		case 'n': dry_run = 1; break;
		case 'F': file_mode = optarg; break;
		case 'T': train_bogo = run_bogo = 1; break;
		}

	home = getenv("HOME");
	if (!home) {
		syslog(LOG_WARNING, "You are homeless!");
		return 0; /* continue */
	}

	read_config();

	if (file_mode)
		rc = setup_file(file_mode);
	else
		rc = create_tmp_file();

	if (rc < 0)
		return 0; /* continue */

	if (logfile)
		atexit(logit);

	filter();
	return 0; /* unreached */
}
