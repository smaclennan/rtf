/* whitelist.c - Email Whitelist
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


/* SAM hardcode for now... */
static char *whitelist[] = { "enbridge", "linkedin", NULL };


static int filter(char *line)
{
	int i;

	for (i = 0; whitelist[i]; ++i)
		if (strcasestr(line, whitelist[i]))
			return 1; /* whitelisted */

	return 0;
}

int main(int argc, char *argv[])
{
	char line[1024];

	while (fgets(line, sizeof(line), stdin))
		if (*line == '\n')
			break; /* end of header */
		else if (strncmp(line, "From:", 5) == 0)
			if (filter(line))
				return 99; /* whitelist */

	return 0; /* continue processing */
}

/*
 * Local Variables:
 * compile-command: "gcc -O3 -Wall whitelist.c -o whitelist"
 * End:
 */
