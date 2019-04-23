#include "rtf.h"
#include <limits.h>

struct entry *global;
struct entry *melist;
struct entry *fromlist;
struct entry *whitelist;
struct entry *blacklist;
struct entry *ignorelist;
struct entry *folderlist;

static int generation;

const char *get_global(const char *glob)
{
	for (struct entry *e = global; e; e = e->next)
		if (strcmp(e->str, glob) == 0)
			return e->folder;
	return "bogus";
}

int get_global_num(const char *glob)
{
	return strtoul(get_global(glob), NULL, 10);
}

static int add_entry(struct entry **head, char *str)
{
	char *p = NULL;
	int need_p = 0;

	if (head == &global) {
		p = strchr(str, '=');
		need_p = 1;
	}
	if (head == &folderlist) {
		p = strchr(str, '=');
		need_p = 1;
	}

	if (need_p) {
		if (p)
			*p++ = 0;
		else {
			if (just_checking)
				printf("Bad line '%s'\n", str);
			else
				syslog(LOG_WARNING, "Bad line '%s'", str);
			return 1;
		}
	}

	for (struct entry *e = *head; e; e = e->next)
		if (strcmp(e->str, str) == 0) {
			if (p && strcmp(e->folder, p)) {
				free((char *)e->folder);
				if (!(e->folder = strdup(p)))
					goto oom;
			}
			e->generation = generation;
			return 0;
		}

	struct entry *new = calloc(1, sizeof(struct entry));
	if (!new)
		goto oom;

	if (!(new->str = strdup(str)))
		goto oom;
	if (p)
		if (!(new->folder = strdup(p)))
			goto oom;

	new->generation = generation;
	new->next = *head;
	*head = new;
	return 0;

oom:
	syslog(LOG_ERR, "Out of memory.");
	exit(1);
}

static void check_list(struct entry **head)
{
	struct entry *prev = NULL;
	struct entry *e = *head;

	while (e) {
		struct entry *next = e->next;

		if (e->generation != generation) {
			if (prev)
				prev->next = next;
			else
				*head = next;
			printf("FREE %s\n", e->str); // SAM DBG
			free((char *)e->str);
			free((char *)e->folder);
			free(e);
		} else
			prev = e;

		e = next;
	}
}

int read_config(void)
{
	char fname[128];
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

	check_list(&global);
	check_list(&melist);
	check_list(&fromlist);
	check_list(&whitelist);
	check_list(&blacklist);
	check_list(&ignorelist);
	check_list(&folderlist);

	++generation;

	return rc;
}
