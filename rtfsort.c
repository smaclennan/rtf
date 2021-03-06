#include "rtf.h"
#include <stdarg.h>
#include <assert.h>
#include <limits.h>
#include <pwd.h>

static struct list {
	const char *fname;
	int bad;
	struct list *next;
} *ham;

static int verbose;
static time_t start = (time_t)-1, end = (time_t)-1;
static time_t min_date = INT_MAX, max_date;

static struct passwd *user;

struct log_struct {
	char fname[80];
	unsigned flags;
};

struct sort_counts {
	/* both */
	unsigned total;
	unsigned actual_spam;

	/* only sort */
	unsigned real;
	unsigned spam;
	unsigned learned_ham;
	unsigned learned;
	unsigned not_me;
	unsigned from;
	unsigned ignored;

	/* only for actions */
	unsigned drop;
	unsigned ham;
	unsigned spam_action;
	unsigned bogo;
	unsigned bogo_total;
	unsigned ignore_action;
	unsigned learned_spam;
	unsigned def; /* default */

	/* only for check_ham */
	unsigned bad_ham;
};

static int saw_bogo;

static void add_ham(const char *fname)
{
	struct list *l = calloc(1, sizeof(struct list));
	fname = strdup(fname);
	if (!l || !fname) {
		puts("Out of memory");
		exit(1);
	}

	l->fname = fname;
	l->next = ham;
	ham = l;
}

static int check_ham(const char *fname, struct sort_counts *sc)
{
	struct list *l;

	for (l = ham; l; l = l->next)
		if (strcmp(l->fname, fname) == 0) {
			++sc->bad_ham;
			l->bad = 1;
			return 1;
		}
	return 0;
}

static int get_month(char *mstr)
{
	static char *months[] = {
		"jan", "feb", "mar", "apr", "may", "jun",
		"jul", "aug", "sep", "oct", "nov", "dec"
	};
	int i;

	for (i = 0; i < 12; ++i)
		if (strncasecmp(mstr, months[i], 3) == 0)
			return i;

	printf("Invalid month '%s'\n", mstr);
	exit(1);
}

static time_t set_date(char *arg, int end)
{
	time_t now = time(NULL);
	struct tm *tm = localtime(&now);
	char *p;

	p = strtok(arg, ", ");
	if (isalpha(*p)) {
		tm->tm_mon = get_month(p);
		if ((p = strtok(NULL, ", ")))
			tm->tm_mday = strtol(p, NULL, 10);
	} else
		tm->tm_mday = strtol(p, NULL, 10);
	if ((p = strtok(NULL, ", "))) {
		long year = strtol(p, NULL, 10);
		if (year < 1900) {
			printf("Invalid year %ld\n", year);
			exit(1);
		}
		tm->tm_year = year - 1900;
	}

	/* reset to midnight */
	tm->tm_sec = tm->tm_min = tm->tm_hour = 0;
	tm->tm_isdst = -1;
	if (end)
		++tm->tm_mday;
	return mktime(tm);
}

static void set_dates(char *arg)
{
	char *p;

	if ((p = strchr(arg, ':'))) {
		*p++ = 0;
		end = set_date(p, 1);
	}
	if (*arg)
		start = set_date(arg, 0);
	if (start != (time_t)-1 && end != (time_t)-1)
		if (start > end) {
			time_t tmp = start;
			start = end;
			end = tmp;
		}
}

static int date_in_range(char *fname)
{
	char *p;
	time_t date = strtol(fname, &p, 10);
	if (*p != '.') {
		printf("Problems with date\n");
		return 1;
	}

	if (date < min_date)
		  min_date = date;
	if (date > max_date)
		  max_date = date;

	if (start != (time_t)-1)
		if (date < start)
			return 0;

	if (end != (time_t)-1)
		if (date >= end)
			return 0;

	return 1;
}

static void handle_line(struct log_struct *l, struct sort_counts *sc)
{
	if (l->flags & LEARN_SPAM) {
		++sc->learned;
		--sc->real;
		++sc->spam;
		return;
	}
	if (l->flags & LEARN_HAM) {
		/* Don't count learning ham... it messes up the totals */
		++sc->learned_ham;
		--sc->spam;
		++sc->real;
		return;
	}

	if (l->flags & IS_IGNORED)
		++sc->ignored;
	else if (l->flags & IS_HAM)
		++sc->real;
	else if ((l->flags & IS_ME) == 0)
		++sc->not_me;
	else if ((l->flags & (BOGO_SPAM | FROM_ME)) == 0) {
		++sc->real;
	} else
		++sc->spam;
	if (l->flags & FROM_ME)
		++sc->from;
}

static void handle_actions(struct log_struct *l, struct sort_counts *sc)
{
	if (l->flags & LEARN_SPAM) {
		++sc->learned_spam;
		return;
	}
	if (l->flags & LEARN_HAM) {
		--sc->total; /* don't count learn line */
		--sc->spam_action;
		++sc->def;
		return;
	}

	if (l->flags & IS_IGNORED)
		++sc->ignore_action;
	else if (l->flags & IS_HAM)
		++sc->ham;
	else if (l->flags & SAW_APP)
		++sc->drop;
	else if ((l->flags & IS_SPAM) ||
		(l->flags & SAW_FROM) == 0 || (l->flags & SAW_DATE) == 0 ||
		(l->flags & FROM_ME) || (l->flags & IS_ME) == 0)
		++sc->spam_action;
	else if (l->flags & BOGO_SPAM)
		++sc->bogo;
	else
		++sc->def;

	if (l->flags & BOGO_SPAM) {
		saw_bogo = 1;
		++sc->bogo_total;
	}
}

static void handle_cleanup(const char *str)
{
	static time_t last_timestamp = 0;

	char *e;
	time_t timestamp = strtol(str, &e, 10);
	if (*e == '.')
		++e;
	else {
		printf("Invalid cleanup str: %s\n", str);
		return;
	}

	time_t delta = 0;
	if (last_timestamp) {
		delta = timestamp - last_timestamp;
		delta = (delta / 60 + 30) / 60; /* hours */
	}
	last_timestamp = timestamp;

	unsigned n = strtoul(e, NULL, 10);

	struct tm *tm = localtime(&timestamp);

	printf("%u/%02u/%02u %02u:%02u:%02u delta %3ld   %u\n",
		   tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
		   tm->tm_hour, tm->tm_min, tm->tm_sec,
		   delta, n);
}

static char *strdate(time_t date)
{
	struct tm *tm = localtime(&date);
	char *str = malloc(16);
	if (!str)
		  return NULL;
	snprintf(str, 16, "%d/%d/%d", 
	         tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);
    return str;
}

static struct black {
	char *str;
	char *match; /* lowercase */
	int count;
	int bogo;
	struct black *next;
} *bl_list, *bl_tail;

static struct black *add_blacklist(char *str)
{
	struct black *bl = calloc(1, sizeof(struct black));
	assert(bl);
	bl->str = strdup(str);
	bl->match = strdup(str);
	assert(bl->str && bl->match);

	char *p;
	for (p = bl->match; *p; ++p)
		*p = tolower(*p);

	if (bl_tail)
		bl_tail->next = bl;
	else
		bl_list = bl;
	bl_tail = bl;
	return bl;
}

static void blacklist_count(char *str, char whence, char bogo)
{
	struct black *bl;
	char *p;

	while (isspace(*str)) ++str;
	for (p = str; *p && *p != '\n'; ++p)
		if (isupper(*p))
			*p = tolower(*p);
	*p = 0;

	for (bl = bl_list; bl; bl = bl->next)
		if (strcmp(str, bl->match) == 0)
			goto count;

	bl = add_blacklist(str);
	if (!bl)
		return;

count:
	++bl->count;
	if (bogo == 'B')
		++bl->bogo;
}

static void blacklist_dump(int html)
{
	if (!bl_list) return;

	struct black *bl;

	if (html) {
		printf("<p><table border=0>\n<tr><th colspan=%d>Blacklist counts\n",
			   saw_bogo ? 3 : 2);
		for (bl = bl_list; bl; bl = bl->next)
			if (saw_bogo)
				printf("<tr><td class=name>%s<td width=60>%d<td width=60>%d\n",
					   bl->str, bl->count, bl->bogo);
			else
				printf("<tr><td class=name>%s<td width=60>%d\n",
					   bl->str, bl->count);
		printf("</table>\n");
	} else {
		printf("\nBlacklist counts:\n");

		for (bl = bl_list; bl; bl = bl->next)
			if (saw_bogo)
				printf("  %-42s %6d  %6d\n", bl->str, bl->count, bl->bogo);
			else
				printf("  %-42s %6d\n", bl->str, bl->count);
	}
}

static void read_blacklist(const char *dir)
{
	char line[128], *p;
	FILE *fp;
	int found = 0;

	snprintf(line, sizeof(line), "%s/.rtf", dir);
	if (!(fp = fopen(line, "r"))) {
		printf("Warning: Unable to open %s\n", line);
		return;
	}

	while (!found && fgets(line, sizeof(line), fp))
		found = strncmp(line, "[blacklist]", 11) == 0;

	if (found)
		while (fgets(line, sizeof(line), fp)) {
			if (*line == '[')
				break;
			p = strtok(line, "\r\n");
			if (!p || !*p || *p == '#')
				continue;
			add_blacklist(p);
		}

	fclose(fp);
}

static void raw_dump(struct sort_counts *sc)
{
	fprintf(stderr, "total:\t\t%6u\n", sc->total);
	fprintf(stderr, "actual_spam:\t%6u\n", sc->actual_spam);
	fprintf(stderr, "\n");
	fprintf(stderr, "real:\t\t%6u\n", sc->real);
	fprintf(stderr, "learned_ham:\t%6u\n", sc->learned_ham);
	fprintf(stderr, "spam:\t\t%6u\n", sc->spam);
	fprintf(stderr, "learned:\t%6u\n", sc->learned);
	fprintf(stderr, "not_me:\t\t%6u\n", sc->not_me);
	fprintf(stderr, "from:\t\t%6u\n", sc->from);
	fprintf(stderr, "ignored:\t%6u\n", sc->ignored);
	fprintf(stderr, "\n");
	fprintf(stderr, "drop:\t\t%6u\n", sc->drop);
	fprintf(stderr, "ham:\t\t%6u\n", sc->ham);
	fprintf(stderr, "spam_action:\t%6u\n", sc->spam_action);
	fprintf(stderr, "bogo:\t\t%6u\n", sc->bogo);
	fprintf(stderr, "bogo_total:\t%6u\n", sc->bogo_total);
	fprintf(stderr, "ignore_action:\t%6u\n", sc->ignore_action);
	fprintf(stderr, "learned_spam:\t%6u\n", sc->learned_spam);
	fprintf(stderr, "def:\t\t%6u\n", sc->def);
	fprintf(stderr, "\n");
	fprintf(stderr, "bad_ham:\t%6u\n", sc->bad_ham);
}

static void get_user(const char *user_name)
{
	char *p;

	user = getpwnam(user_name);
	if (!user) {
		perror(user_name);
		exit(1);
	}

	if ((p = strchr(user->pw_gecos, ',')))
		*p = 0;

	if (*user->pw_gecos == 0)
		user->pw_gecos = user->pw_name;

	read_blacklist(user->pw_dir);
}

static struct flag {
	unsigned flag;
	unsigned set;
	char val;
} flags[] = {
	{ IS_ME,      'M' },
	{ SAW_FROM,   'F' },
	{ SAW_DATE,   'D' },
	{ IS_HAM,     'H' },
	{ IS_IGNORED, 'I' },
	{ IS_SPAM,    'S' }, /* S or A or Z */
	{ FROM_ME,    'f' },
	{ BOGO_SPAM,  'B' },
};
#define NUM_FLAGS (sizeof(flags) / sizeof(struct flag))

static void outit(int html, const char *fmt, ...)
{
	static int first_line = 1;
	va_list ap;
	char line[256], *p, *e;

	va_start(ap, fmt);
	vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);

	if (html) {
		if (first_line) {
			fputs("<body>\n<p>", stdout);
			first_line = 0;
		}
		for (p = line; *p == ' '; ++p)
			fputs("&nbsp;&nbsp;", stdout);
		if ((e = strchr(p, '\n')))
			*e = 0;
		fputs(p, stdout);
		if (e)
			fputs("<br>\n", stdout);
	} else
		fputs(line, stdout);
}

int main(int argc, char *argv[])
{
	char line[80];
	int i, c, n, do_cleanup = 0, dump_raw = 0, html = 0;
	struct log_struct l;
	struct sort_counts sc;

	assert(NUM_FLAGS == 8);

	while ((c = getopt(argc, argv, "cd:ru:vH")) != EOF)
		switch (c) {
		case 'c':
			do_cleanup = 1;
			break;
		case 'd':
			set_dates(optarg);
			break;
		case 'r':
			dump_raw = 1;
			break;
		case 'u':
			get_user(optarg);
			break;
		case 'v':
			++verbose;
			break;
		case 'H':
			html = 1;
		}

	memset(&sc, 0, sizeof(sc));

	while (fgets(line, sizeof(line), stdin)) {
		char learn, learn_flag, forward, action;

		c = sscanf(line, "%s %c%c%c%c%c%c%c%c%c%c%c %c%n",
				   l.fname,
				   &flags[0].val, &flags[1].val, &flags[2].val, &flags[3].val,
				   &flags[4].val, &flags[5].val, &flags[6].val, &flags[7].val,
				   &learn, &learn_flag, &forward, &action, &n);

		if (action == 'C') {
			// imap-rtf connect
			continue;
		}

		if (!date_in_range(l.fname)) {
			// printf("Skipping %s\n", l.fname);
			continue;
		}

		if (flags[0].val == 'B') {
			char subject[80];

			snprintf(subject, sizeof(subject), "%s", line + n);
			blacklist_count(subject, flags[1].val, flags[7].val);
			continue;
		}

		++sc.total;

		if (c == 13) {
			assert(learn != 'L');
			if (verbose > 1)
				fputs(line, stderr);

			l.flags = 0;
			for (i = 0; i < NUM_FLAGS; ++i)
				if (flags[i].flag & IS_SPAM)
					/* Spam is special */
					switch (flags[i].val) {
					case 'S': l.flags |= IS_SPAM; break;
					case 'A': l.flags |= SAW_APP; break;
					case 'Z': l.flags |= IS_SPAM | SAW_APP; break;
					case '-': break;
					default: printf("Invalid spam flag %c\n", flags[i].val);
					}
				else if (flags[i].val == flags[i].set)
					l.flags |= flags[i].flag;
				else if (flags[i].val != '-')
					printf("Unhandled flag %c: %s\n", flags[i].val, line);

			if (l.flags & IS_HAM)
				add_ham(l.fname);
			else if (l.flags & LEARN_SPAM)
				check_ham(l.fname, &sc);

			handle_line(&l, &sc);
			handle_actions(&l, &sc);
		} else if (c == 12) {
			assert(learn == 'L');

			l.flags = 0;
			switch (learn_flag) {
			case 'S':
				l.flags |= LEARN_SPAM;
				check_ham(l.fname, &sc);
				break;
			case 'H': l.flags |= LEARN_HAM; break;
			case 'D':
				--sc.total;
				if (do_cleanup)
					handle_cleanup(l.fname);
				continue;
			default: printf("Invalid learn flags %c\n", learn_flag);
			}

			handle_line(&l, &sc);
			handle_actions(&l, &sc);
		} else
			printf("PROBS: %s", line);
	}

	if (user)
		outit(html, "Summary %s to %s for %s\n",
			  strdate(min_date), strdate(max_date), user->pw_gecos);
	else
		outit(html, "Summary %s to %s\n", strdate(min_date), strdate(max_date));

	if (sc.not_me + sc.ignored + sc.real + sc.learned + sc.spam != sc.total)
		outit(html, "Problems with total\n");
	if (sc.ignore_action + sc.ham + sc.drop + sc.spam_action + sc.bogo + sc.def +
		sc.learned_spam != sc.total)
		outit(html, "Problems with action total\n");

	outit(html, "Mail Stats:\n");
	outit(html, "  Not me %u from me %u ignored %d real %u learned %u ham %u spam %u total %u\n",
		   sc.not_me, sc.from, sc.ignored, sc.real, sc.learned, sc.learned_ham, sc.spam, sc.total);

	outit(html, "Actions:\n");
	outit(html, "  Ignored %u ham %u drop %u spam %u bogo %u real %u learned %u\n",
		   sc.ignore_action, sc.ham, sc.drop, sc.spam_action, sc.bogo, sc.def, sc.learned_spam);

	sc.actual_spam = sc.spam_action + sc.drop + sc.bogo + sc.learned_spam;

	if (saw_bogo) {
		outit(html, "We caught %.0f%% bogofilter %.0f%% missed %.0f%%.\n",
			  (double)(sc.spam_action + sc.drop) * 100.0 / (double)sc.actual_spam,
			  (double)sc.bogo_total * 100.0 / (double)sc.actual_spam,
			  (double)sc.learned_spam * 100.0 / (double)sc.actual_spam);
		outit(html, "Spam was %.0f%% (%u) of all messages. Not me %.0f%%\n",
			  (double)sc.actual_spam * 100.0 / (double)sc.total,
			  sc.actual_spam,
			  (double)sc.not_me * 100.0 / (double)sc.actual_spam);
	} else
		outit(html, "Spam was %.0f%% (%u) of all messages. We caught %.0f%%, not me %.0f%%.\n",
			  (double)sc.actual_spam * 100.0 / (double)sc.total, sc.actual_spam,
			  (double)(sc.spam_action + sc.drop) * 100.0 / (double)sc.actual_spam,
			  (double)sc.not_me * 100.0 / (double)sc.actual_spam);

	if (sc.bad_ham) {
		outit(html, " Bad ham %u.", sc.bad_ham);

		if (verbose) {
			struct list *l;

			for (l = ham; l; l = l->next)
				if (l->bad)
					outit(html, "  %s\n", l->fname);
		}
	}

	blacklist_dump(html);

	if (dump_raw)
		raw_dump(&sc);

	return 0;
}

/*
 * Local Variables:
 * compile-command: "gcc -O3 -Wall rtfsort.c -o rtfsort"
 * End:
 */
