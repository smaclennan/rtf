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

/* Remove mail from folder that is older than a given number of
 * days. If no days are specified, then the default it one week (7
 * days).
 *
 * This is meant to be called from cron. Depending on your cron
 * program you may need '-d $HOME' to specify the home directory.
 *
 * Example:
 *    [clean]
 *    Spam
 *    Mailing List=30
 * Says to delete spam after 7 days, but keep messages in the "Mailing
 * List" folder for up to 30 days. Note: Unread messages are never
 * removed.
 */

#include "rtf.h"
#include <time.h>

static char buff[BUFFER_SIZE];

static const char *months[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

static char *datestr(const char *days)
{
	static char date[16];
	unsigned n_days = 7;

	if (days) {
		char *e;
		n_days = strtoul(days, &e, 10);
		if (n_days == 0 || *e) {
			logmsg("Bad datestr %s", days);
			return NULL;
		}
	}

	time_t now = time(NULL);
	struct tm *tm = gmtime(&now);
	tm->tm_mday -= n_days;
	now = mktime(tm);
	tm = gmtime(&now);
	sprintf(date, "%d-%s-%d", tm->tm_mday, months[tm->tm_mon], tm->tm_year + 1900);
	return date;
}

void uid_validity(void) {} /* Don't care */

int main(int argc, char *argv[])
{
	int c, rc, dry_run = 0;
	while ((c = getopt(argc, argv, "dnv")) != EOF)
		switch (c) {
		case 'd': home = optarg; break;
		case 'n': dry_run = 1; break;
		case 'v': ++verbose; break;
		}

	rc = read_config();
	if (rc) {
		printf("Read config failed\n");
		return 1;
	}

	if (!cleanlist)
		return 0; // nothing to do

	int sock = connect_to_server(get_global("server"),
								 get_global_num("port"),
								 get_global("user"),
								 get_global("passwd"));

	for (struct entry *e = cleanlist; e; e = e->next) {
		char *date = datestr(e->folder);
		if (!date) continue;

		rc = send_recv("SELECT %s", e->str);
		if (rc < 0)
			goto failed;
		if (rc > 0) {
			printf("Unable to select %s\n", e->str);
			continue;
		}
		rc = send_recv("UID SEARCH SENTBEFORE %s SEEN", date);
		if (rc < 0)
			goto failed;
		if (rc > 0) {
			printf("Search failed for %s\n", e->str);
			continue;
		}

		int found = 0;
		while (fetchline(buff, sizeof(buff))) {
			if (strncmp(buff, "* SEARCH", 8) == 0) {
				found = 1;
				break;
			}
		}

		if (dry_run) {
			if (found)
				printf("%s: %s\n", e->str, buff);
			else
				printf("%s: Bad search reply\n", e->str);
			continue;
		}

		if (found && buff[8] == ' ') {
			char *p = buff + 9;

			unsigned uid;
			while ((uid = strtol(p, &p, 10)) > 0) {
				rc = send_recv("UID STORE %u +FLAGS.SILENT (\\Seen \\Deleted)", uid);
				if (rc < 0)
					goto failed;
				if (rc)
					printf("%s: UID STORE failed:\n%s", e->str, reply);
			}

			rc = send_recv("EXPUNGE");
			if (rc < 0)
				goto failed;
			if (rc)
				printf("%s: EXPUNGE failed:\n%s", e->str, reply);
		}
	}

	ssl_close();
	close(sock);
	return 0;

failed:
	printf("Connection to server failed\n");
	ssl_close();
	close(sock);
	return 1;
}
