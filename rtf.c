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
 * It has both a blacklist and a whitelist and looks in $HOME/.rtf.
 *
 * It returns 0 if the email is a spam, 1 if it is ham.
 *
 * I use it with a condredirect from my .qmail file.
 */

#define _GNU_SOURCE /* for strcasestr */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <syslog.h>

#define BOGOFILTER "bogofilter -u"

struct entry {
	const char *str;
	struct entry *next;
};

struct entry *whitelist;
struct entry *blacklist;

static char header[8096];

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

static void read_config(const char *fname)
{
	struct entry **head = NULL;

	FILE *fp = fopen(fname, "r");
	if (!fp) {
		syslog(LOG_WARNING, "%s: %m", fname);
		exit(0);
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
}

static int filter(char *line)
{
	struct entry *e;

	for (e = whitelist; e; e = e->next)
		if (strcasestr(line, e->str))
			return 0; /* not spam */

	for (e = blacklist; e; e = e->next)
		if (strcasestr(line, e->str))
			return 1; /* spam */

	return 0;
}


static int run_bogofilter(void)
{
	FILE *pfp = popen(BOGOFILTER, "w");
	if (!pfp) {
		syslog(LOG_WARNING, "bogofilter failed to start");
		return 0;
	}

	fputs(header, pfp);

	char line[1024];
	while (fgets(line, sizeof(line), stdin))
		fputs(line, pfp);

	return WEXITSTATUS(pclose(pfp));
}

int main(int argc, char *argv[])
{
	char *line = header;
	int n, len = sizeof(header);
	int saw_from = 0, saw_date = 0;

	snprintf(line, sizeof(line), "%s/.rtf", getenv("HOME"));
	read_config(line);

	while (fgets(line, len, stdin)) {
		if (*line == '\n')
			break; /* end of header */
		else if (strncmp(line, "From:", 5) == 0) {
			if (filter(line))
				return 0; /* spam */
			else
				saw_from = 1;
		} else if (strncmp(line, "Subject:", 8) == 0) {
			if (filter(line))
				return 0; /* spam */
		} else if (strncmp(line, "Date:", 5) == 0)
			saw_date = 1;

		n = strlen(line);
		line += n;
		len -= n;
	}

	if (saw_from == 0 || saw_date == 0)
		return 0; /* spam */

#if 0
	return 1; /* don't redirect */
#else
	return run_bogofilter();
#endif
}

/*
 * Local Variables:
 * compile-command: "gcc -O3 -Wall rtf.c -o rtf"
 * End:
 */
