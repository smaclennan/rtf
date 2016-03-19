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
 * 1) Whitelist (ham)
 * 2) The ignore list (ignore)
 * 3) Blacklist (spam)
 * 4) Check if the from and/or date fields are missing (spam)
 * 5) Optionally check if not on the me list (spam)
 * 6) Optionally runs the emails through bogofilter (ham or spam)
 *
 * Actions:
 *
 * Ham moved to inbox and left as new.
 * Spam moved to spam folder and marked as read.
 * Ignore moved to ignore folder and marked as read.
 */

#define _GNU_SOURCE /* for strcasestr */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <syslog.h>
#include <errno.h>
#include <time.h>

#define BOGOFILTER "bogofilter"
#define IGNOREDIR ".Ignore"

static int run_bogo;
static int run_drop;
static const char *logfile;
static char *subject = "NONE";

static unsigned flags;
#define IS_HAM			0x01
#define IS_IGNORED		0x02
#define IS_SPAM			0x04
#define IS_ME			0x08
#define SAW_DATE		0x10
#define SAW_FROM		0x20
#define BOGO_SPAM		0x40

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
static int create_tmp_file(const char *home)
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
	unlink(tmp_file);
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
	
	char *p = subject;
	if (strncmp(subject, "Subject: ", 9) == 0)
		p += 9;

#define OUT(a, c) ((flags & (a)) ? (c) : '-')
	fprintf(fp, "%s %c%c%c%c%c%c%c %.40s\n", tmp_file,
			OUT(IS_ME, 'M'), OUT(SAW_FROM, 'F'), OUT(SAW_DATE, 'D'),
			OUT(IS_HAM, 'H'), OUT(IS_IGNORED, 'I'), OUT(IS_SPAM, 'S'),
			OUT(BOGO_SPAM, 'B'), p);

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

static int read_config(const char *fname)
{
	struct entry **head = NULL;

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
		char *p = strtok(line, " \t\r\n");
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

static void safe_rename(const char *path)
{
	if (rename(tmp_path, path)) {
		syslog(LOG_WARNING, "%s: %m", path);
		unlink(tmp_path);
		exit(0); /* continue */
	}

	exit(99); /* don't continue - we handled it */
}

static void ham(const char *home)
{
	char path[PATH_SIZE];
	snprintf(path, sizeof(path), "%s/Maildir/new/%s", home, tmp_file);
	safe_rename(path);
}

static void spam(const char *home)
{
	char path[PATH_SIZE];
	snprintf(path, sizeof(path), "%s/Maildir/.Spam/cur/%s:2,S", home, tmp_file);
	safe_rename(path);
}

static void ignore(const char *home)
{   /* Move to ignore and mark as read */
	char path[PATH_SIZE];
	snprintf(path, sizeof(path), "%s/Maildir/%s/cur/%s:2,S", home, IGNOREDIR, tmp_file);
	safe_rename(path);
}

static int list_filter(char *line, struct entry *head)
{
	struct entry *e;

	for (e = head; e; e = e->next)
		if (strcasestr(line, e->str))
			return 1;

	return 0;
}

static void filter(int fd, const char *home)
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
		} else if (strncmp(buff, "Subject:", 8) == 0) {
			if ((subject = strdup(buff)))
				strtok(subject, "\r\n");
			else
				subject = "NOMEM";
			if (list_filter(buff, blacklist))
				flags |= IS_SPAM;
		} else if (strncmp(buff, "Date:", 5) == 0)
			flags |= SAW_DATE;
	}

	fclose(fp);

	if (flags & IS_HAM) {
		/* Tell bogofilter this is ham */
		run_bogofilter(tmp_path, "-n");
		ham(home);
	}
	if (flags & IS_IGNORED) {
		/* Tell bogofilter this is ham */
		run_bogofilter(tmp_path, "-n");
		ignore(home);
	}
	if ((flags & IS_SPAM) || (flags & (SAW_FROM | SAW_DATE)) == 0) {
		/* Tell bogofilter this is spam */
		run_bogofilter(tmp_path, "-s");
		spam(home);
	}
	if (run_drop && (flags & IS_ME) == 0) {
		/* Tell bogofilter this is spam */
		run_bogofilter(tmp_path, "-s");
		spam(home);
	}
}

int main(int argc, char *argv[])
{
	char path[PATH_SIZE];
	const char *home = getenv("HOME");
	if (!home) {
		syslog(LOG_WARNING, "You are homeless!");
		return 0; /* continue */
	}

	int c;
	while ((c = getopt(argc, argv, "bdl:")) != EOF)
		switch (c) {
		case 'b': run_bogo = 1; break;
		case 'd': run_drop = 1; break;
		case 'l': logfile = optarg; break;
		}

	snprintf(path, sizeof(path), "%s/.rtf", home);
	read_config(path);

	int fd = create_tmp_file(home);
	if (fd < 0)
		return 0; /* continue */

	if (logfile)
		atexit(logit);

	filter(fd, home);

	if (run_bogofilter(tmp_path, "-u") == 0) {
		flags |= BOGO_SPAM;
		spam(home);
	}

	ham(home);
	return 0; /* unreached */
}
