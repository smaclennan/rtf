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


int main(int argc, char *argv[])
{
	int c;
	while ((c = getopt(argc, argv, "v")) != EOF)
		if (c == 'v')
			++verbose;

	if (argc == optind) {
		puts("I need a uid");
		exit(1);
	}

	if (read_config())
		exit(1);

	int sock = connect_to_server(get_global("server"),
								 get_global_num("port"),
								 get_global("user"),
								 get_global("passwd"));


	int rc = fetch(strtol(argv[optind], NULL, 0));

	ssl_close();
	close(sock);

	if (rc == 0)
		puts(reply);

	return rc;
}
