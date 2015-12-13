/* rtf.c - Really Trivial Filter
 * Copyright (C) 2012-2015 Sean MacLennan <seanm@seanm.ca>
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

/* This is a Really Trivial Filter(tm) that catches some very common
 * spams that bogofilter cannot. It checks for keywords in the From
 * and Subject fields and for the existence of From and Date fields.
 *
 * $HOME/.rtf can have both a blacklist and a whitelist.
 *
 * If bogofilter finds spam, it is moved to $HOME/Maildir/.Spam/cur
 * and is marked as read.
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

#define BOGOFILTER "bogofilter -u"

struct entry {
	const char *str;
	struct entry *next;
};

struct entry *whitelist;
struct entry *blacklist;

static char header[8096];

/* /home/<user 32>/Maildir/tmp/<time 10>.<pid 5>.<hostname 64> */
#define PATH_SIZE 136

static char tmp_file[84], tmp_path[PATH_SIZE];

/* Not NFS safe and I don't care */
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

	do {
		int n, len = strlen(header);
		if ((n = write(fd, header, len)) != len)
			goto write_error;
	} while (fgets(header, sizeof(header), stdin));

	close(fd);
	return 0;

write_error:
	syslog(LOG_ERR, "%s: write error", tmp_path);
	close(fd);
	unlink(tmp_file);
	return -1;
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
			else if (strcmp(line, "[filter]") == 0)
				head = &blacklist;
		} else if (head)
			add_entry(head, line);
	}

	fclose(fp);
	return 0;
}

static int whitelist_filter(char *line)
{
	struct entry *e;

	for (e = whitelist; e; e = e->next)
		if (strcasestr(line, e->str))
			return 1; /* white listed */

	return 0;
}

static int blacklist_filter(char *line)
{
	struct entry *e;

	for (e = blacklist; e; e = e->next)
		if (strcasestr(line, e->str))
			return 1; /* black listed */

	return 0;
}

static void filter(const char *home)
{
	char *line = header;
	int n, len = sizeof(header), spam = 0;
	int saw_from = 0, saw_date = 0;

	while (fgets(line, len, stdin)) {
		if (*line == '\n')
			break; /* end of header */
		else if (strncmp(line, "From:", 5) == 0) {
			if (whitelist_filter(line))
				exit(0); /* continue */
			else if (blacklist_filter(line))
				spam = 1; /* spam */
			saw_from = 1;
		} else if (strncmp(line, "Subject:", 8) == 0) {
			if (whitelist_filter(line))
				exit(0); /* continue */
			else if (blacklist_filter(line))
				spam = 1; /* spam */
		} else if (strncmp(line, "Date:", 5) == 0)
			saw_date = 1;

		n = strlen(line);
		line += n;
		len -= n;
	}

	if (spam == 1 || saw_from == 0 || saw_date == 0) {
		char path[PATH_SIZE];

		if (create_tmp_file(home))
			exit(0); /* continue */

		snprintf(path, sizeof(path), "%s/Maildir/.Spam/cur/%s:2,S", home, tmp_file);
		if (rename(tmp_path, path)) {
			syslog(LOG_WARNING, "%s: %m", path);
			unlink(tmp_path);
			exit(0); /* continue */
		}

		exit(99); /* don't continue - we handled it */
	}
}

static int run_bogofilter(const char *fname)
{
	char cmd[256];
	snprintf(cmd, sizeof(cmd), "%s -B %s", BOGOFILTER, fname);
	return WEXITSTATUS(system(cmd));
}

int main(int argc, char *argv[])
{
	char path[PATH_SIZE];
	const char *home = getenv("HOME");
	int run_bogo = argc > 1 && strcmp(argv[1], "-b") == 0;

	if (!home) {
		syslog(LOG_WARNING, "You are homeless!");
		return 0; /* continue */
	}

	snprintf(path, sizeof(path), "%s/.rtf", home);
	read_config(path);

	if (whitelist || blacklist)
		filter(home);

	if (run_bogo) {
		if (create_tmp_file(home))
			return 0; /* continue */

		if (run_bogofilter(tmp_path) == 0)
			/* spam */
			snprintf(path, sizeof(path), "%s/Maildir/.Spam/cur/%s:2,S", home, tmp_file);
		else
			/* good */
			snprintf(path, sizeof(path), "%s/Maildir/new/%s", home, tmp_file);

		if (rename(tmp_path, path)) {
			syslog(LOG_WARNING, "%s: %m", path);
			unlink(tmp_path);
			return 0; /* continue */
		}

		return 99; /* don't continue - we handled it */
	}

	return 0; /* continue */
}

/*
 * Local Variables:
 * compile-command: "gcc -O3 -Wall rtf.c -o rtf"
 * End:
 */
