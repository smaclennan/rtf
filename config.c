#include "rtf.h"
#include <limits.h>
#include <dirent.h>

struct entry *global;
struct entry *whitelist;
struct entry *graylist;
struct entry *blacklist;
struct entry *folderlist;
struct entry *cleanlist;

static int generation;

const char *get_global(const char *glob)
{
	for (struct entry *e = global; e; e = e->next)
		if (strcmp(e->str, glob) == 0)
			return e->folder;
	return NULL;
}

int get_global_num(const char *glob)
{
	const char *str = get_global(glob);
	if (str)
		return strtoul(get_global(glob), NULL, 10);
	return 0;
}

static int add_entry(struct entry **head, char *str)
{
	char *p = NULL;
	int need_p = 0;
	struct entry *tail = NULL;

	if (*str == '\\') ++str;

	if (head == &global || head == &folderlist) {
		p = strchr(str, '=');
		need_p = 1;
	}
	if (head == &cleanlist) {
		p = strchr(str, '=');
		if (p) need_p = 1;
	}

	if (need_p) {
		if (p)
			*p++ = 0;
		else {
			logmsg("Bad line '%s'", str);
			return 1;
		}
	}

	for (struct entry *e = *head; e; e = e->next) {
		if (strcmp(e->str, str) == 0) {
			if (p && strcmp(e->folder, p)) {
				free((char *)e->folder);
				if (!(e->folder = strdup(p)))
					goto oom;
			}
			e->generation = generation;
			return 0;
		}
		tail = e;
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
	if (tail) {
		tail->next = new;
		tail = new;
	} else
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
			free((char *)e->str);
			free((char *)e->folder);
			free(e);
		} else
			prev = e;

		e = next;
	}
}

static int read_config_file(const char *fname)
{
	struct entry **head = NULL;
	int rc = 0;

	FILE *fp = fopen(fname, "r");
	if (!fp) {
		if (errno == ENOENT)
			return 0;

		perror(fname);
		syslog(LOG_WARNING, "%s: %m", fname);
		return 1;
	}

	if (verbose)
		printf("Reading %s\n", fname);

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
			else if (strcmp(line, "[graylist]") == 0)
				head = &graylist;
			else if (strcmp(line, "[blacklist]") == 0)
				head = &blacklist;
			else if (strcmp(line, "[folders]") == 0)
				head = &folderlist;
			else if (strcmp(line, "[clean]") == 0)
				head = &cleanlist;
			else {
				syslog(LOG_INFO, "Unexpected: %s\n", line);
				head = NULL;
			}
		} else if (head)
			rc |= add_entry(head, line);
	}

	fclose(fp);

	return rc;
}

int read_config(void)
{
	char fname[128];
	int rc;

	snprintf(fname, sizeof(fname), "%s/.rtf", home);
	rc = read_config_file(fname);

	snprintf(fname, sizeof(fname), "%s/.rtf.d", home);
	DIR *dir = opendir(fname);
	if (dir) {
		struct dirent *ent;
		while ((ent = readdir(dir))) {
			if (*ent->d_name == '.')
				continue;
			snprintf(fname, sizeof(fname), "%s/.rtf.d/%s", home, ent->d_name);
			rc |= read_config_file(fname);
		}
		closedir(dir);
	}

	// Do not delete working globals
	check_list(&whitelist);
	check_list(&graylist);
	check_list(&blacklist);
	check_list(&folderlist);

	if (generation == 0)
		if (!get_global("server") ||
			get_global_num("port") == 0 ||
			!get_global("user") ||
			!get_global("passwd")) {
			logmsg("Missing required global(s)");
			rc = 1;
		}

	if (graylist && !get_global("graylist")) {
		logmsg("graylist global missing");
		rc = 1;
	}
	if (blacklist && !get_global("blacklist")) {
		logmsg("blacklist global missing");
		rc = 1;
	}

	++generation;

	return rc;
}
