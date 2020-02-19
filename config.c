#include "rtf.h"
#include <limits.h>
#include <dirent.h>
#include <pwd.h>

struct entry *global;
struct entry *whitelist;
struct entry *graylist;
struct entry *blacklist;
struct entry *folderlist;
struct entry *cleanlist;

char *home;
int verbose;
int use_stderr;
const char *diary;
static int generation;

static inline int write_string(char *str)
{
	strcat(str, "\n");
	return write(2, str, strlen(str));
}

void logmsg(int type, const char *fmt, ...)
{
	va_list ap;
	char msg[128];

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg) - 1, fmt, ap);
	va_end(ap);

	if (use_stderr)
		write_string(msg);
	else
		syslog(type, "%s", msg);
}

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
			logmsg(LOG_INFO, "Bad line '%s'", str);
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
		new->prev = tail;
		tail->next = new;
		tail = new;
	} else
		*head = new;
	return 0;

oom:
	logmsg(LOG_ERR, "Out of memory.");
	exit(1);
}

static int check_entry(struct entry **head, struct entry *e)
{
	if (e->generation != generation) {
		if (e->prev)
			e->prev->next = e->next;
		else
			*head = e->next;
		free((char *)e->str);
		free((char *)e->folder);
		free(e);
		return 0;
	}

	return 1;
}

static void check_list(struct entry **head)
{
	struct entry *e = *head;

	while (e) {
		struct entry *next = e->next;
		check_entry(head, e);
		e = next;
	}
}

static struct entry *check_global(const char *glob)
{
	for (struct entry *e = global; e; e = e->next)
		if (strcmp(e->str, glob) == 0)
			return check_entry(&global, e) ? e : NULL;
	return NULL;
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
		logmsg(LOG_WARNING, "%s: %m", fname);
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
				logmsg(LOG_INFO, "Unexpected: %s\n", line);
				head = NULL;
			}
		} else if (head)
			rc |= add_entry(head, line);
	}

	fclose(fp);

	return rc;
}

static void get_home(void)
{	/* HOME env may not be available, or worse might be wrong */
	struct passwd *ent = getpwuid(getuid());
	if (ent) {
		home = strdup(ent->pw_dir);
		if (home)
			return;
	}

	logmsg(LOG_ERR, "You do not exist!");
	exit(1);
}

int read_config(void)
{
	char fname[128];
	int rc;

	if (!home)
		get_home();

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
			if (strncmp(ent->d_name, "cert", 4) == 0)
				rc |= ssl_read_cert(fname);
			else
				rc |= read_config_file(fname);
		}
		closedir(dir);
	}

	// Do not delete working globals except diary
	struct entry *e = check_global("diary");
	if (e)
		diary = e->folder;

	check_list(&whitelist);
	check_list(&graylist);
	check_list(&blacklist);
	check_list(&folderlist);

	if (!get_global("server") ||
		get_global_num("port") == 0 ||
		!get_global("user") ||
		!get_global("passwd")) {
		logmsg(LOG_ERR, "Missing required global(s)");
		rc = 1;
	}

	if (graylist && !get_global("graylist")) {
		logmsg(LOG_ERR, "graylist global missing");
		rc = 1;
	}
	if (blacklist && !get_global("blacklist")) {
		logmsg(LOG_ERR, "blacklist global missing");
		rc = 1;
	}

	++generation;

	return rc;
}
