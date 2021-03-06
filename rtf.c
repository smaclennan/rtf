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
 * whitelist - To or From that should be marked ham
 * blacklist - From or Subject that should be marked spam
 * ignore - From that should be ignored
 * me - list of my emails (see below)
 *
 * Note: To includes To, Cc, and Bcc.
 *
 * Descisions:
 *
 * 1) The ignore list (ignore)
 * 2) Whitelist (ham)
 * 3) Blacklist (spam)
 * 4) Check if from me (spam)
 * 5) Check if the from and/or date fields are missing (spam)
 * 6) Optionally runs the emails through bogofilter (ham or spam)
 * 7) Optionally check if not on the me list (spam)
 * 8) Optionally check if saw application attachment (app)
 *
 * Actions:
 *
 * Ham moved to inbox and left as new.
 * Spam moved to spam folder and marked as read.
 * Ignore moved to ignore folder and marked as read.
 * Application attachment moved to drop folder and marked as read.
 *
 * The from me (rule 4) is probably non-intuitive. I have my last name
 * white listed. All emails legitimately from me are of the form
 * <first name> <lastname> <email>. Spams are almost always just
 * <email>. So the whitelist catches the legitimate emails and the
 * "from me" catches the spams. We do get a few false positive hams
 * because of this.
 *
 * Notes:
 *
 * If you enable app checking, we need to read the entire email to
 * check for attachments. Normally, only the header needs to be read.
 *
 * You can put regular expressions in the list match strings. Regular
 * expressions start with a plus sign (+). All other strings are
 * literal and do not go through the regexp parser.
 *
 * Note that you are given the entire header line. This means you can
 * match on the field to differentiate say To: and Cc:.
 *
 * Other features:
 *
 * - mail forwarding
 * - folders
 */

/* Ideas that failed:
 *
 * - filter out utf from - too many false positives
 */

#include "rtf.h"
#include <sys/wait.h>
#include <regex.h>

#define BOGOFILTER "bogofilter"

static int run_bogo;
static int train_bogo;
static int run_drop;
static int drop_apps;
static int forward;
static int just_checking;
static const char *logfile;
static const char *home;
/* We only print the first 42 chars of subject */
static char subject[48] = { 'N', 'O', 'N', 'E' };
static char action = '?';
static char *sender;

/* For dry_run you probably want file mode too. */
static int dry_run;

/* File mode is a special case for running rtf on existing email. It
 * will move the mail to the spam or drop or ignore folders but leaves
 * ham alone.
 *
 * File mode can only handle one file at a time.
 */
static const char *file_mode;

static unsigned flags;

struct entry {
	const char *str;
	const char *folder;
	regex_t *reg;
	struct entry *next;
};

static struct entry *melist;
static struct entry *fromlist;
static struct entry *whitelist;
static struct entry *blacklist;
static struct entry *graylist;
static struct entry *forwardlist;
static struct entry *forwardfilter;
static struct entry *folderlist;
static const  char *folder_match;

static const struct entry *saw_bl[2];
static int add_blacklist;

static char buff[8096];

/* /home/<user 32>/Maildir/tmp/<time 10>.<pid 5>.<hostname 64>
 * /home/<user 32>/Maildir/.Spam/cur/<time 10>.<pid 5>.<hostname 64>:2,S
 */
#define PATH_SIZE 144

static char tmp_file[84], tmp_path[PATH_SIZE];

#ifdef WANT_FORWARDING
#include <curl/curl.h>

#define LINE_SIZE 4096

struct user_data {
	const char *fname;
	FILE *fp;
	int output;
};

static size_t read_callback(char *output, size_t size, size_t nmemb, void *datap)
{
	struct user_data *data = datap;
	int ch;
	size_t n = 0;

	/* I have always seen size == 1 */
	if (size == 1)
		size = nmemb;
	else
		size *= nmemb;
	if (size > 0)
		--size; /* we need room for possible \r\n */

	if (data->output == 0) {
		/* We need to find the first "real" header line */
		while (fgets(output, size, data->fp))
			if (!isspace(*output) &&
				strncmp(output, "Received:", 9) &&
				strncmp(output, "Return-Path:", 12) &&
				strncmp(output, "Delivered-To:", 13)) {
				data->output = 1;
				char *p = strchr(output, '\n');
				if (p) *p = 0;
				strcat(output, "\r\n");
				n = strlen(output);
				output += n;
				break;
			}
	}

	while (n < size && (ch = fgetc(data->fp)) != EOF) {
		if (ch == '\n') {
			*output++ = '\r';
			++n;
		}
		*output++ = ch;
		++n;
	}

	return n;
}

static void forward_log(void)
{
#if 1
	char fname[256], *p;

	if (!logfile) {
		syslog(LOG_INFO, "No logfile"); // SAM DBG
		return;
	}

	snprintf(fname, sizeof(fname) - 11, "%s", logfile);
	p = strrchr(fname, '/');
	if (p) {
		strcpy(p, "/forward.log");
		FILE *fp = fopen(fname, "a");
		if (fp) {
			fprintf(fp, "%s\n", sender);
			fclose(fp);
		} else
			syslog(LOG_INFO, "%s: %m", fname); // SAM DBG
	} else
		syslog(LOG_INFO, "%s: invalid", logfile); // SAM DBG
#endif
}

static int forward_filter(void)
{
	struct entry *ff;

	for (ff = forwardfilter; ff; ff = ff->next)
		if (strcasestr(sender, ff->str))
			return 1;

	return 0;
}

static int filter_to(const char *to)
{   /* sanitize the to */
	char sane[1024], *p;

	snprintf(sane, sizeof(sane), "%s", to);
	if ((p = strrchr(sane, '>'))) *p = 0;
	p = *sane == '<' ? sane + 1 : sane;
	return strcmp(p, sender) == 0;
}

static void do_forward(const char *fname)
{
	CURL *curl = NULL;
	struct curl_slist *recipients = NULL;
	struct entry *e;
	int ok = 1; /* we currently always have sender */
	struct user_data upload_ctx;
	CURLcode res;
	char from[128];

	if (forward_filter())
		return;

	upload_ctx.fname = fname;
	upload_ctx.output = 0;
	upload_ctx.fp = fopen(fname, "r");
	if (!upload_ctx.fp) {
		syslog(LOG_ERR, "tmpfile %s: %m", fname);
		return;
	}

	curl = curl_easy_init();
	if(!curl) {
		syslog(LOG_ERR, "Unable to initialize curl");
		goto cleanup;
	}

	/* parse the forward list */
	for (e = forwardlist; e; e = e->next)
		if (strncmp(e->str, "smtp=", 5) == 0) {
			curl_easy_setopt(curl, CURLOPT_URL, e->str + 5);
			ok |= 2;
		} else if (strncmp(e->str, "to=", 3) == 0) {
			recipients = curl_slist_append(recipients, e->str + 3);
			ok |= 4;
			if (filter_to(e->str + 3))
				goto cleanup;
		}

	if (ok != 7) {
		syslog(LOG_ERR, "Invalid configuraton: %d", ok);
		goto cleanup;
	}

	curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

	snprintf(from, sizeof(from), "<%s>", sender);
	curl_easy_setopt(curl, CURLOPT_MAIL_FROM, from);

	curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
	curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
	curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

	/* Send the message */
	res = curl_easy_perform(curl);
	if(res != CURLE_OK)
		syslog(LOG_ERR, "curl_easy_perform() failed: %s", curl_easy_strerror(res));

	flags |= FORWARD;

	forward_log();

cleanup:
	fclose(upload_ctx.fp);
	curl_slist_free_all(recipients);
	curl_easy_cleanup(curl);
}
#else
#define do_forward(f)
#endif

/* Should be NFS safe iff all hostnames are unique. */
static int create_tmp_file(void)
{
	char hostname[64];
	if (gethostname(hostname, sizeof(hostname))) {
		syslog(LOG_ERR, "Hostname: %m");
		return -1;
	}

	const char *dtline = getenv("DTLINE");
	const char *rpline = getenv("RPLINE");
	if (!dtline || !rpline) {
		syslog(LOG_ERR, "Missing required environment variables.");
		return -1;
	}

	snprintf(tmp_file, sizeof(tmp_file), "%ld.%d.%s",
			 time(NULL), getpid(), hostname);
	snprintf(tmp_path, sizeof(tmp_path), "%s/Maildir/tmp/%s", home, tmp_file);
	int fd = creat(tmp_path, 0644);
	if (fd < 0) {
		syslog(LOG_ERR, "%s: %m", tmp_path);
		return -1;
	}

	/* Sanitize the environment variables */
	const char *p;
	for (p = rpline; *p; ++p)
		if (isascii(*p))
			if (write(fd, p, 1) != 1)
				goto write_error;
	for (p = dtline; *p; ++p)
		if (isascii(*p))
			if (write(fd, p, 1) != 1)
				goto write_error;

	/* Read the email */
	int n;
	while ((n = read(0, buff, sizeof(buff))) > 0)
		if (write(fd, buff, n) != n)
			goto write_error;

	if (fsync(fd))
		goto write_error;

	if (close(fd)) {
		fd = -1;
		goto write_error;
	}

	if (n < 0)
		goto read_error;

	return 0;

write_error:
	syslog(LOG_ERR, "%s: write error", tmp_path);
	if (fd != -1)
		close(fd);
	unlink(tmp_path);
	return -1;

read_error:
	syslog(LOG_ERR, "%s: read error", tmp_path);
	unlink(tmp_path);
	return -1;
}

/* Called at exit() */
static void logit(void)
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
		/* keep going even if we don't get the lock */
	}

#define OUT(a, c) ((flags & (a)) ? (c) : '-')
	/* Last two flags are for learnem */
	char spam = '-';
	switch (flags & (IS_SPAM | SAW_APP)) {
	case IS_SPAM: spam = 'S'; break;
	case SAW_APP: spam = 'A'; break;
	case IS_SPAM | SAW_APP: spam = 'Z'; break;
	}
	fprintf(fp, "%-20s %c%c%c%c%c%c%c%c--%c %c %.42s\n", tmp_file,
			OUT(IS_ME, 'M'), OUT(SAW_FROM, 'F'), OUT(SAW_DATE, 'D'),
			OUT(IS_HAM, 'H'), OUT(IS_IGNORED, 'I'), spam,
			OUT(FROM_ME, 'f'), OUT(BOGO_SPAM, 'B'),
			OUT(FORWARD, 'F'), action, subject);

	if (add_blacklist) {
		int i;

		for (i = 0; i < 2; ++i)
			if (saw_bl[i])
				fprintf(fp, "%-20s B%c-----%c--- %c %.42s\n", tmp_file,
						i ? 'S' : 'F', OUT(BOGO_SPAM, 'B'),
						action, saw_bl[i]->str);
	}

	if (ferror(fp))
		syslog(LOG_ERR, "%s: write error", logfile);

	fclose(fp);
}

static int add_folder(struct entry *new, const char *str)
{
	char *p = strchr(str, ',');

	if (just_checking) {
		if (!p)
			printf("Bad folder line '%s'\n", str);
		else {
			char path[PATH_SIZE];
			snprintf(path, sizeof(path) - strlen(tmp_file), "%s/Maildir/%s/new", home, p + 1);
			if (access(path, F_OK))
				printf("Bad folder %s\n", path);
			return 0;
		}
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

static int add_entry(struct entry **head, const char *str)
{
	struct entry *new = calloc(1, sizeof(struct entry));
	if (!new) goto oom;

	if (head == &folderlist)
		return add_folder(new, str);

	if (*str == '+') {
		new->reg = malloc(sizeof(regex_t));
		if (!new->reg) goto oom;

		int rc = regcomp(new->reg, str + 1, REGEXP_FLAGS);
		if (rc) {
			char err[80];

			regerror(rc, new->reg, err, sizeof(err));
			if (just_checking)
				printf("%s: %s\n", str, err);
			else
				syslog(LOG_WARNING, "Bad regexp '%s': %s", str, err);
			free(new->reg);
			free(new);
			return 1;
		}
	}

	if (!(new->str = strdup(str)))
		goto oom;

	new->next = *head;
	*head = new;
	return 0;

oom:
	syslog(LOG_ERR, "Out of memory.");
	exit(0);
}

static void blacklist_count(const struct entry *e, int index)
{
	saw_bl[index] = e;
}

static int read_config(void)
{
	char fname[PATH_SIZE];
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
			if (strcmp(line, "[whitelist]") == 0)
				head = &whitelist;
			else if (strcmp(line, "[blacklist]") == 0)
				head = &blacklist;
			else if (strcmp(line, "[ignore]") == 0)
				head = &graylist;
			else if (strcmp(line, "[me]") == 0)
				head = &melist;
			else if (strcmp(line, "[fromlist]") == 0)
				head = &fromlist;
			else if (strcmp(line, "[forward]") == 0)
				head = &forwardlist;
			else if (strcmp(line, "[forward_filter]") == 0)
				head = &forwardfilter;
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
	return rc;
}

static int run_bogofilter(const char *fname, char *flags)
{
	if (run_bogo) {
		char cmd[256];
		snprintf(cmd, sizeof(cmd) - 3, "%s %s -B %s", BOGOFILTER, flags, fname);
		return WEXITSTATUS(system(cmd));
	} else
		return 1; /* mark as non-spam */
}

static void _safe_rename(const char *path)
{
	if (dry_run) {
		printf("Action %c\n", action);
		exit(0);
	}
	if (rename(tmp_path, path)) {
		syslog(LOG_WARNING, "%s: %m", path);
		unlink(tmp_path);
		exit(0); /* continue */
	}
}

static void ham(void)
{
	char path[PATH_SIZE];

	if (folder_match) {
		action = 'f';
		snprintf(path, sizeof(path), "%s/Maildir/%s/new/%s", home, folder_match, tmp_file);
	} else
		snprintf(path, sizeof(path), "%s/Maildir/new/%s", home, tmp_file);

	/* We technically should forward after rename... but it is
	 * racy to forward the "real" message but safe with the tmp
	 * message.
	 */
	if (forward && !folder_match && !dry_run)
		do_forward(tmp_path);

	_safe_rename(path);
	exit(99); /* don't continue - we handled it */
}

static void safe_rename(const char *subdir)
{
	char path[PATH_SIZE];
	snprintf(path, sizeof(path), "%s/Maildir/%s/cur/%s:2,S", home, subdir, tmp_file);
	_safe_rename(path);
	exit(99); /* don't continue - we handled it */
}

static inline void spam(void) { safe_rename(SPAM_DIR); }

static inline void ignore(void) { safe_rename(IGNORE_DIR); }

static inline void drop(void) { safe_rename(DROP_DIR); }

static const struct entry *list_filter(const char *line, struct entry * const head)
{
	struct entry *e;

	for (e = head; e; e = e->next) {
		if (e->reg) {
			regmatch_t match[1];

			if (regexec(e->reg, line, 1, match, 0) == 0)
				return e;
		} else if (strcasestr(line, e->str))
			return e;
	}

	return NULL;
}

/* Returns 1 if type should be dropped */
static int check_type(const char *type)
{
	while (isspace(*type))
		++type;

	if (strncasecmp(type, "application/", 12))
		return 0;

	type += 12;

	switch (*type) {
	case 'x':
		/* Catch x-compress and x-compressed */
		if (strncmp(type, "x-compress", 10) == 0)
			return 1;
		/* x-zip and x-zip-compressed */
		if (strncmp(type, "x-zip", 5) == 0)
			return 1;
		/* x-rar and x-rar-compressed */
		if (strncmp(type, "x-rar", 5) == 0)
			return 1;
		break;
	case 'z':
		if (strncmp(type, "zip", 3) == 0)
			return 1;
		break;
	case 'r':
		if (strncmp(type, "rar", 5) == 0)
			return 1;
		break;
	case 'v':
		/* Not sure about these... */
		if (drop_apps > 1) {
			if (strncmp(type, "vnd.ms-word.document.macroEnabled", 33) == 0)
				return 1;
			if (strncmp(type, "vnd.ms-excel", 12) == 0)
				return 1;
		}
		break;
	case 'o':
		if (strncmp(type, "octet-stream", 12) == 0)
			return 1;
		break;
	}

	return 0;
}

static inline void filter_from(const char *from)
{
	const struct entry *e;

	if (list_filter(from, whitelist))
		flags |= IS_HAM;
	if (list_filter(from, graylist))
		flags |= IS_IGNORED;
	if ((e = list_filter(from, blacklist))) {
		flags |= IS_SPAM;
		blacklist_count(e, 0);
	}
	if (list_filter(from, fromlist))
		flags |= FROM_ME;
}

static int isok(char c)
{
	switch (c) {
	case 'a'...'z':
	case 'A'...'Z':
	case '0'...'9':
		return 1;
	case '"':
		return 1;
	/* for mime decode e.g. =?utf-8?Q?Apple?= */
	case '=':
	case '?':
	case '-':
		return 1;
	default:
		return 0;
	}
}

/* Check for a one name from */
static void check_one_name_from(char *subject, char *from)
{
	from += 5; /* skip From: */
	while (isspace(*from)) ++from;
	while (isok(*from)) ++from;
	while (isspace(*from)) ++from;
	if (*from && *from != '<')
		return;

	/* We have a "one name" from */

	if (add_blacklist) {
		/* Add an entry to the blacklist count */
		struct entry *e = calloc(1, sizeof(struct entry));
		if (e) {
			e->str = "one name";
			blacklist_count(e, 1);
		}
	}

	action = 'S';
	run_bogofilter(tmp_path, "-s");
	spam();
}

static void normalize_subject(const char *str)
{
	str += 8; /* skip subject: */
	while (isspace(*str)) ++str;
	if (!*str) {
		strcpy(subject, "EMPTY");
		return;
	}

	int i, end = 0;
	for (i = 0; *str && i < sizeof(subject) - 1; ++i, ++str) {
		subject[i] = *str;
		if (!isspace(*str)) {
			end = i;
			if (!isprint(*str))
				subject[i] = '~';
		}
	}
	subject[end + 1] = 0;
}

static void filter(void)
{
	const struct entry *e;
	char *from = NULL;
	FILE *fp = fopen(tmp_path, "r");
	if (!fp) {
		syslog(LOG_WARNING, "%s: %m", tmp_path);
		unlink(tmp_path);
		exit(0);
	}

	/* Also filter sender. This is mainly for mailing lists but can
	 * also catch people who fake the from.
	 */
	filter_from(sender);

	while (fgets(buff, sizeof(buff), fp)) {
		if (*buff == '\n')
			break; /* end of header */
		else if (strncasecmp(buff, "To:", 3) == 0 ||
				 strncasecmp(buff, "Cc:", 3) == 0 ||
				 strncasecmp(buff, "Bcc:", 4) == 0) {
			if (list_filter(buff, whitelist))
				flags |= IS_HAM;
			if (list_filter(buff, melist))
				flags |= IS_ME;
			if ((e = list_filter(buff, folderlist)))
				folder_match = e->folder;
		} else if (strncasecmp(buff, "From:", 5) == 0) {
			flags |= SAW_FROM;
			filter_from(buff);
			from = strdup(buff);
			if ((e = list_filter(buff, folderlist)))
				folder_match = e->folder;
		} else if (strncasecmp(buff, "Subject:", 8) == 0) {
			normalize_subject(buff);
			if ((e = list_filter(buff, blacklist))) {
				flags |= IS_SPAM;
				blacklist_count(e, 1);
			} else if ((e = list_filter(buff, folderlist)))
				folder_match = e->folder;
		} else if (strncasecmp(buff, "Date:", 5) == 0)
			flags |= SAW_DATE;
		else if (strncasecmp(buff, "Content-Type:", 13) == 0) {
			if (check_type(buff + 13))
				flags |= SAW_APP;
		} else if (strncasecmp(buff, "List-Post:", 10) == 0) {
			if ((e = list_filter(buff, folderlist)))
				folder_match = e->folder;
		}
	}

	if (drop_apps && !(flags & SAW_APP))
		while (fgets(buff, sizeof(buff), fp))
			if (strncasecmp(buff, "Content-Type:", 13) == 0)
				if (check_type(buff + 13)) {
					flags |= SAW_APP;
					break;
				}

	fclose(fp);

	if (!train_bogo)
		/* Just check the mail... do not update the word lists */
		if (run_bogofilter(tmp_path, "") == 0)
			flags |= BOGO_SPAM;

	/* Rule 1 */
	if (flags & IS_IGNORED) {
		/* Tell bogofilter this is ham */
		action = 'I';
		run_bogofilter(tmp_path, "-n");
		ignore();
	}
	/* Rule 2 */
	if (flags & IS_HAM) {
		/* Tell bogofilter this is ham */
		action = 'H';
		run_bogofilter(tmp_path, "-n");
		ham();
	}
	/* Rule 3, 4, 6 */
	if ((flags & (IS_SPAM | BOGO_SPAM | FROM_ME)) ||
		/* Rule 5 */
		(flags & SAW_FROM) == 0 || (flags & SAW_DATE) == 0 ||
		/* Rule 7 */
		(run_drop && (flags & IS_ME) == 0)) {
		/* Tell bogofilter this is spam */
		action = 'S';
		run_bogofilter(tmp_path, "-s");
		spam();
	}
	/* Rule 8 */
	if (drop_apps && (flags & SAW_APP)) {
		action = 'D';
		run_bogofilter(tmp_path, "-s");
		drop();
	}

	/* SAM HACK */
	check_one_name_from(subject, from);

	action = 'h';
	run_bogofilter(tmp_path, "-n");
	ham();
}

static int setup_file(const char *fname)
{
	if (*fname != '/') {
		printf("File must be fully rooted!\n");
		exit(1);
	}

	/* tmp_path is just fname */
	snprintf(tmp_path, sizeof(tmp_path), "%s", fname);

	/* tmp_file must be the raw basename */
	char *p = strrchr(fname, '/');
	snprintf(tmp_file, sizeof(tmp_file), "%s", p + 1);
	p = strchr(tmp_file, ':');
	if (p)
		*p = '\0';

	return 0;
}

static void usage(void)
{
	puts("usage:\trtf [-abcdfnCT] [-l logfile] [-F file]\n"
		 "where:\t-a   drop emails with app attachments\n"
		 "\t-b   run bogofilter\n"
		 "\t-c   add blacklist counts to logfile\n"
		 "\t-d   mark emails not 'from me' as spam\n"
		 "\t-f   forward emails\n"
		 "\t-h   this help\n"
		 "\t-n   dry run (mainly used with -F)\n"
		 "\t-C   just check the config file\n"
		 "\t     validates any regular expressions\n"
		 "\t-F   mainly for debugging rtf\n"
		 "\t-T   train bogofilter"
		);
}

int main(int argc, char *argv[])
{
	int c, rc;
	while ((c = getopt(argc, argv, "abcdfhl:nCF:T")) != EOF)
		switch (c) {
		case 'a': ++drop_apps; break;
		case 'b': run_bogo = 1; break;
		case 'c': add_blacklist = 1; break;
		case 'd': run_drop = 1; break;
		case 'f': forward = 1; break;
		case 'h': usage(); exit(0);
		case 'l': logfile = optarg; break;
		case 'n': dry_run = 1; break;
		case 'C': just_checking = 1; break;
		case 'F': file_mode = optarg; break;
		case 'T': train_bogo = run_bogo = 1; break;
		}

	home = getenv("HOME");
	if (!home) {
		syslog(LOG_WARNING, "You are homeless!");
		return 0; /* continue */
	}

	rc = read_config();
	if (just_checking)
		return rc;

	if (file_mode)
		sender = "good-sender";
	else {
		sender = getenv("SENDER");
		if (!sender) {
			syslog(LOG_ERR, "Email with no sender!");
			return 0;
		}
	}

	if (file_mode)
		rc = setup_file(file_mode);
	else
		rc = create_tmp_file();

	if (rc < 0)
		return 0; /* continue */

	if (logfile)
		atexit(logit);

	filter();
	return 0; /* unreached */
}
