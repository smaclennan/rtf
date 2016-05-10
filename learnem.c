#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <poll.h>
#include <dirent.h>
#include <syslog.h>
#include <sys/file.h>
#ifdef __linux__
#include <sys/inotify.h>
#else
#include <sys/event.h>
#endif

#define LEARN_DIR ".LearnSPAM"
#define HAM_DIR ".Ham"
#define SPAM_DIR ".Spam"

#define INOTIFY_MASK IN_MOVED_TO

#ifdef __linux__
#define QUEUE_TIMEOUT 10000 /* in ms */
#define HOURLY_TIMEOUT (60 * 60 * 1000)

#define TIMEOUT int
#else
static struct timespec queue_timeout  = { .tv_sec = 10 };
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
static char config_dir[MY_PATH_MAX];
static char *logfile;

static void logit(const char *tmp_file, int is_spam)
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
	fprintf(fp, "%-20s --------L%c\n", tmp, is_spam ? 'S' : 'H');

	if (ferror(fp))
		syslog(LOG_ERR, "%s: write error", logfile);

	fclose(fp);
}

static void handle_spam(void)
{
	char cmd[512];
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
		snprintf(cmd, sizeof(cmd), "/usr/bin/bogofilter -Ns -d %s -B '%s'", config_dir, old);
		int rc = system(cmd);
		if (rc < 0 || rc > 2) {
			syslog(LOG_ERR, "bogofilter failed on %s!", old);
			continue;
		}

		/* Move to spam and mark read */
		int n = snprintf(new, sizeof(new) - 3, "%s/%s", spam_dir, ent->d_name);
		if ((p = strchr(new, ','))) {
			if (!strchr(p, 'S'))
				snprintf(new + n, sizeof(new) - n, "S");
		} else
			snprintf(new + n, sizeof(new) - n, ",S");
		if (rename(old, new))
			syslog(LOG_ERR, "rename(%s, %s) failed", old, new);
		else
			logit(ent->d_name, 1);
	}

	closedir(dir);
}

static void handle_ham(void)
{
	char cmd[512];
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
		snprintf(cmd, sizeof(cmd), "/usr/bin/bogofilter -Sn -d %s -e -B '%s'", config_dir, old);
		int rc = system(cmd);
		if (rc < 0 || rc > 2) {
			syslog(LOG_ERR, "bogofilter failed on %s!", old);
			continue;
		}

		/* Just remove it */
		if (unlink(old))
			syslog(LOG_ERR, "unlink %s: %s", old, strerror(errno));
		else
			logit(ent->d_name, 0);
	}

	closedir(dir);
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

int main(int argc, char *argv[])
{
	char *home = getenv("HOME");
	if (!home) {
		syslog(LOG_ERR, "You are homeless.");
		exit(1);
	}

	int c;
	while ((c = getopt(argc, argv, "l:")) != EOF)
		if (c == 'l')
			logfile = optarg;

	snprintf(config_dir, sizeof(config_dir), "%s/.bogofilter", home);
	snprintf(spam_dir, sizeof(spam_dir), "%s/Maildir/%s/cur", home, SPAM_DIR);
	snprintf(learn_dir, sizeof(learn_dir), "%s/Maildir/%s/cur", home, LEARN_DIR);
	snprintf(ham_dir, sizeof(ham_dir), "%s/Maildir/%s/cur", home, HAM_DIR);

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

	/* Trivial queuing. Since I tend to handle spam in chunks... hold
	 * off and handle multiple messages at once. */
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
			timeout = HOURLY_TIMEOUT;
		} else if (n > 0) {
#ifdef __linux__
			int i;

			for (i = 0; i < MAX_FDS; ++i)
				if (fds[i].revents)
					read(fds[i].fd, event, sizeof(event));
#endif
			timeout = QUEUE_TIMEOUT;
		}
	}

	return 0;
}
