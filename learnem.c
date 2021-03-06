#include "rtf.h"

#include <poll.h>
#include <dirent.h>
#ifdef __linux__
#include <sys/inotify.h>
#else
#include <sys/event.h>
#endif

#define INOTIFY_MASK IN_MOVED_TO

#ifdef __linux__
#define QUEUE_TIMEOUT 30000 /* in ms */
#define HOURLY_TIMEOUT (60 * 60 * 1000)

#define TIMEOUT int
#else
static struct timespec queue_timeout  = { .tv_sec = 30 };
static struct timespec hourly_timeout = { .tv_sec = 60 * 60 * 1000 };

#define QUEUE_TIMEOUT  &queue_timeout
#define HOURLY_TIMEOUT &hourly_timeout

#define TIMEOUT struct timespec *
#endif

/* Paths are /home/<user>/Maildir/<folder>/cur/<fname>
 * user is max 64, folder lets say 16, fname about 48. This gives
 * about 148.... so 256 should be more than adequate.
 */
#define MY_PATH_MAX 256

static char learn_dir[MY_PATH_MAX];
static char ham_dir[MY_PATH_MAX];
static char spam_dir[MY_PATH_MAX];
static char ignore_dir[MY_PATH_MAX];
static char config_dir[MY_PATH_MAX];
static char *logfile;
static int run_bogo;

static time_t max_age;

static void logit(const char *tmp_file, char flag)
{
	if (!logfile)
		return;

	FILE *fp = fopen(logfile, "a");
	if (!fp) {
		syslog(LOG_ERR, "%s: %m", logfile);
		return;
	}

	if (flock(fileno(fp), LOCK_EX)) {
		syslog(LOG_ERR, "%s: flock: %m", logfile);
		fclose(fp);
		return;
	}
	
	/* Remove special chars from tmp_file to match rtf */
	char tmp[24], *p;
	snprintf(tmp, sizeof(tmp), "%s", tmp_file);
	if ((p = strchr(tmp, ':'))) *p = 0;

	/* Last two flags are for learnem */
	fprintf(fp, "%-20s --------L%c\n", tmp, flag);

	if (ferror(fp))
		syslog(LOG_ERR, "%s: write error", logfile);

	fclose(fp);
}

static void do_bogofilter(const char *old, int spam)
{
	if (!run_bogo)
		return;

	char cmd[512];

	snprintf(cmd, sizeof(cmd), "/usr/bin/bogofilter %s -d %s -B -e '%s'",
			 spam ? "-Ns" : "-Sn", config_dir, old);
	int rc = system(cmd);
	if (rc < 0 || rc > 2)
		syslog(LOG_ERR, "bogofilter failed on %s!", old);
}

static void handle_spam(void)
{
	DIR *dir = opendir(learn_dir);
	if (!dir) {
		syslog(LOG_ERR, "opendir %s: %s", learn_dir, strerror(errno));
		return;
	}

	struct dirent *ent;
	while ((ent = readdir(dir))) {
		if (*ent->d_name == '.') continue;

		char old[MY_PATH_MAX], new[MY_PATH_MAX], *p;
		snprintf(old, sizeof(old), "%s/%s", learn_dir, ent->d_name);
		do_bogofilter(old, 1);

		/* Move to spam and mark read */
		p = ent->d_name + strlen(ent->d_name) - 1;
		if (*p == ',')
			snprintf(new, sizeof(new) - 3, "%s/%sS", spam_dir, ent->d_name);
		else
			snprintf(new, sizeof(new) - 3, "%s/%s,S", spam_dir, ent->d_name);
		if (rename(old, new))
			syslog(LOG_ERR, "rename(%s, %s) failed", old, new);
		else
			logit(ent->d_name, 'S');
	}

	closedir(dir);
}

static void handle_ham(void)
{
	DIR *dir = opendir(ham_dir);
	if (!dir) {
		syslog(LOG_ERR, "opendir %s: %s", ham_dir, strerror(errno));
		return;
	}

	struct dirent *ent;
	while ((ent = readdir(dir))) {
		if (*ent->d_name == '.') continue;

		char old[MY_PATH_MAX];
		snprintf(old, sizeof(old), "%s/%s", ham_dir, ent->d_name);
		do_bogofilter(old, 0);

		/* Just remove it */
		if (unlink(old))
			syslog(LOG_ERR, "unlink %s: %s", old, strerror(errno));
		else
			logit(ent->d_name, 'H');
	}

	closedir(dir);
}

static int cleanup_dir(const char *dname)
{
	unsigned did_something = 0;

	DIR *dir = opendir(dname);
	if (!dir) {
		syslog(LOG_ERR, "opendir %s: %m", dname);
		return 0;
	}

	time_t now = time(NULL);
	time_t old = now - max_age;

	struct dirent *ent;
	while ((ent = readdir(dir))) {
		if (*ent->d_name == '.') continue;

		char path[MY_PATH_MAX];
		snprintf(path, sizeof(path), "%s/%s", dname, ent->d_name);

		struct stat sbuf;
		if (stat(path, &sbuf)) {
			syslog(LOG_ERR, "stat %s: %m", path);
			continue;
		}

		if (sbuf.st_ctime < old || sbuf.st_mtime < old) {
			if (unlink(path) == 0)
				++did_something;
			else
				syslog(LOG_WARNING, "unlink %s: %m", path);
		}
	}

	closedir(dir);

	return did_something;
}

static void handle_cleanup_dirs(void)
{
	unsigned did_something = 0;

	did_something += cleanup_dir(spam_dir);
	did_something += cleanup_dir(ignore_dir);

	if (did_something) {
		char str[32];
		snprintf(str, sizeof(str), "%ld.%09u", time(NULL), did_something);
		logit(str, 'D');
	}
}

#ifdef __linux__
static int setup_inotify(const char *dir)
{
	int fd = inotify_init();
	if (fd < 0) {
		perror("inotify_init");
		exit(1);
	}

	if (access(dir, F_OK)) {
		printf("Warning: No %s directory.\n", dir);
		return -1;
	}

	if (inotify_add_watch(fd, dir, INOTIFY_MASK) < 0) {
		printf("Unable to add %s\n", dir);
		exit(1);
	}

	return fd;
}
#else
static void setup_kevent(int kq, struct kevent *event, const char *dir)
{
	int fd = open(dir, O_RDONLY);
	if (fd < 0) {
		perror(dir);
		exit(1);
	}

	EV_SET(event, fd, EVFILT_VNODE, EV_ADD | EV_CLEAR, NOTE_WRITE, 0, NULL);
}
#endif

static void set_max_age(const char *days)
{
	max_age = strtol(days, NULL, 0);
	if (max_age < 2) {
		syslog(LOG_WARNING, "Warning: setting age to 2 days.");
		max_age = 2;
	} else if (max_age > 365) {
		syslog(LOG_WARNING, "Warning: setting age to 365 days.");
		max_age = 365;
	}

	max_age *= 24 * 60 * 60; /* convert to seconds */
}

int main(int argc, char *argv[])
{
	int do_delete = 0, foreground = 0;

	char *home = getenv("HOME");
	if (!home) {
		syslog(LOG_ERR, "You are homeless.");
		exit(1);
	}

	int c;
	while ((c = getopt(argc, argv, "bd:fl:")) != EOF)
		switch (c) {
		case 'b': run_bogo = 1; break;
		case 'd': do_delete = 1; set_max_age(optarg); break;
		case 'f': foreground = 1; break;
		case 'l': logfile = optarg; break;
		default: puts("Sorry!"); exit(1);
		}

	snprintf(config_dir, sizeof(config_dir), "%s/.bogofilter", home);
	snprintf(spam_dir, sizeof(spam_dir), "%s/Maildir/%s/cur", home, SPAM_DIR);
	snprintf(learn_dir, sizeof(learn_dir), "%s/Maildir/%s/cur", home, LEARN_DIR);
	snprintf(ham_dir, sizeof(ham_dir), "%s/Maildir/%s/cur", home, HAM_DIR);
	snprintf(ignore_dir, sizeof(ham_dir), "%s/Maildir/%s/cur", home, IGNORE_DIR);

	if (!foreground && daemon(0, 0))
		syslog(LOG_WARNING, "Unable to daemonize\n");

#ifdef __linux__
#define MAX_FDS 2
	struct pollfd fds[MAX_FDS];

	fds[0].events = POLLIN;
	fds[0].fd = setup_inotify(learn_dir);

	fds[1].events = POLLIN;
	fds[1].fd = setup_inotify(ham_dir);

	uint8_t event[sizeof(struct inotify_event) + NAME_MAX + 1];
#else
	int kq = kqueue();
	if (kq < 0) {
		perror("kqueue");
		exit(1);
	}

	struct kevent events[2];
	setup_kevent(kq, &events[0], learn_dir);
	setup_kevent(kq, &events[1], ham_dir);
#endif

	/* Run through the directories once */
	handle_spam();
	handle_ham();
	if (do_delete)
		handle_cleanup_dirs();

	/* Trivial queuing. Since I tend to handle spam in chunks... hold
	 * off and handle multiple messages at once. We switch to a more
	 * aggressive timeout when we have something to process.
	 */
	TIMEOUT timeout = HOURLY_TIMEOUT;

	while (1) {
#ifdef __linux__
		int n = poll(fds, MAX_FDS, timeout);
#else
		int n = kevent(kq, events, 2, NULL, 1, timeout);
#endif

		if (n == 0) {
			handle_spam();
			handle_ham();
			if (do_delete && timeout == HOURLY_TIMEOUT)
				handle_cleanup_dirs();
			timeout = HOURLY_TIMEOUT;
		} else if (n > 0) {
#ifdef __linux__
			int i;

			for (i = 0; i < MAX_FDS; ++i)
				if (fds[i].revents)
					n = read(fds[i].fd, event, sizeof(event));
#endif
			timeout = QUEUE_TIMEOUT;
		}
	}

	return 0;
}
