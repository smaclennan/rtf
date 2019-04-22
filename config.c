#include "rtf.h"
#include <limits.h>

struct entry *global;
struct entry *melist;
struct entry *fromlist;
struct entry *whitelist;
struct entry *blacklist;
struct entry *ignorelist;
struct entry *folderlist;

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

	if (!(new->str = strdup(str)))
		goto oom;

	new->next = *head;
	*head = new;
	return 0;

oom:
	syslog(LOG_ERR, "Out of memory.");
	exit(0);
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
