/* rtf.c - Really Trivial Filter
 * Copyright (C) 2012 Sean MacLennan <seanm@seanm.ca>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this project; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

/* This is a Really Trivial Filter(tm) that catches some very common
 * spams that bogofilter cannot. It checks for keywords in the From
 * and Subject fields and for the existence of a From field.
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


static char *flist[] = { "vigara", "viagra", "data entry", NULL };

static char *wlist[] = { "enbridge", "linkedin", NULL };

#define BOGOFILTER "bogofilter -u"

static char header[8096];


static int filter(char *line)
{
	int i;

	for (i = 0; flist[i]; ++i)
		if (strcasestr(line, flist[i]))
			return 1; /* spam */

	return 0;
}

static int whitelist(char *line)
{
	int i;

	for (i = 0; wlist[i]; ++i)
		if (strcasestr(line, wlist[i]))
			return 1; /* whitelisted */

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
	int len = sizeof(header);
	int saw_from = 0, saw_date = 0;

	while (fgets(line, len, stdin)) {
		if (*line == '\n')
			break; /* end of header */
		else if (strncmp(line, "From:", 5) == 0) {
			if (filter(line))
				return 0; /* spam */
			else
				saw_from = 1;
			if (whitelist(line))
				return 1; /* don't redirect, don't run though bogofilter */
		} else if (strncmp(line, "Subject:", 8) == 0) {
			if (filter(line))
				return 0; /* spam */
		} else if (strncmp(line, "Date:", 5) == 0)
			saw_date = 1;

		int n = strlen(line);
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
