#include "rtf.h"
#include <assert.h>
#include <limits.h>

static struct list {
	const char *fname;
	int bad;
	struct list *next;
} *ham;

static int verbose;
static time_t start = (time_t)-1, end = (time_t)-1;
static time_t min_date = INT_MAX, max_date;

struct log_struct {
	char fname[80];
	char subject[80];
	unsigned flags;
};

struct sort_counts {
	/* both */
	unsigned total;

	/* only sort */
	unsigned real;
	unsigned spam;
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
	unsigned learned_ham;
	unsigned learned_spam;
	unsigned def; /* default */

	/* only for check_ham */
	unsigned bad_ham;
};

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
		++sc->learned;
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
		++sc->learned_ham;
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

	if (l->flags & BOGO_SPAM)
		++sc->bogo_total;
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

char *strdate(time_t date)
{
	struct tm *tm = localtime(&date);
	char *str = malloc(16);
	if (!str)
		  return NULL;
	snprintf(str, 16, "%d/%d/%d", 
	         tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);
    return str;
}

static struct list *bl_list;

static void blacklist_count(const char *str, char whence)
{
	struct list *bl;

	for (bl = bl_list; bl; bl = bl->next)
		if (strcmp(str, bl->fname) == 0) {
			++bl->bad;
			return;
		}

	bl = calloc(1, sizeof(struct list));
	if (!bl)
		return;

	bl->fname = strdup(str);
	if (!bl->fname) {
		free(bl);
		return;
	}

	bl->bad = 1;
	bl->next = bl_list;
	bl_list = bl;
}

static void blacklist_dump(void)
{
	struct list *bl;

	if (bl_list)
		printf("Blacklist counts:\n");

	for (bl = bl_list; bl; bl = bl->next)
		printf("  %-.42s %6d\n", bl->fname, bl->bad);
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

int main(int argc, char *argv[])
{
	char line[80];
	int i, c, n, do_cleanup = 0;
	struct log_struct l;
	struct sort_counts sc;

	assert(NUM_FLAGS == 8);

	while ((c = getopt(argc, argv, "cd:v")) != EOF)
		switch (c) {
		case 'c':
			do_cleanup = 1;
			break;
		case 'd':
			set_dates(optarg);
			break;
		case 'v':
			++verbose;
			break;
		}

	memset(&sc, 0, sizeof(sc));

	while (fgets(line, sizeof(line), stdin)) {
		char learn, learn_flag;

		if (sscanf(line, "%s %c%c%c%c%c%c%c%c%c%c%n",
				   l.fname,
				   &flags[0].val, &flags[1].val, &flags[2].val, &flags[3].val,
				   &flags[4].val, &flags[5].val, &flags[6].val, &flags[7].val,
				   &learn, &learn_flag, &n) == 11) {
			if (!date_in_range(l.fname)) continue;
			++sc.total;
			if (verbose > 1)
				fputs(line, stderr);

			if (line[n] == ' ')
				++n;
			snprintf(l.subject, sizeof(l.subject), "%s", line + n);

			l.flags = 0;
			if (learn == 'L')
				/* learn is special */
				switch (learn_flag) {
				case 'S': l.flags |= LEARN_SPAM; break;
				case 'H': l.flags |= LEARN_HAM; break;
				case 'D':
					--sc.total;
					if (do_cleanup)
						handle_cleanup(l.fname);
					continue;
				default: printf("Invalid learn flags %c\n", learn_flag);
				}
			else if (flags[0].val == 'B')
				blacklist_count(l.subject, flags[1].val);
			else
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
		} else
			printf("PROBS: %s", line);
	}

	printf("Summary %s to %s\n", strdate(min_date), strdate(max_date));
	
	if (sc.not_me + sc.ignored + sc.real + sc.learned + sc.spam != sc.total)
		printf("Problems with total\n");

	printf("Mail Stats:\n");
	printf("  Not me %u from me %u ignored %d real %u learned %u spam %u total %u\n",
		   sc.not_me, sc.from, sc.ignored, sc.real, sc.learned, sc.spam, sc.total);

	printf("Actions:\n");
	printf("  Ignored %u ham %u drop %u spam %u bogo %u real %u learned %u\n",
		   sc.ignore_action, sc.ham, sc.drop, sc.spam_action, sc.bogo, sc.def, sc.learned_spam);

	unsigned actual_spam = sc.spam_action + sc.drop + sc.bogo + sc.learned_spam;

	printf("We caught %.0f%% bogofilter %.0f%% missed %.0f%%.",
		   (double)(sc.spam_action + sc.drop) * 100.0 / (double)actual_spam,
		   (double)sc.bogo_total * 100.0 / (double)actual_spam,
		   (double)sc.learned_spam * 100.0 / (double)actual_spam);
	if (sc.bad_ham) {
		printf(" Bad ham %u.", sc.bad_ham);

		if (verbose) {
			struct list *l;

			for (l = ham; l; l = l->next)
				if (l->bad)
					printf("  %s\n", l->fname);
		}
	}
	putchar('\n');

	printf("Spam was %.0f%% of all messages\n",
		   (double)actual_spam * 100.0 / (double)sc.total);

	blacklist_dump();

	return 0;
}

/*
 * Local Variables:
 * compile-command: "gcc -O3 -Wall rtfsort.c -o rtfsort"
 * End:
 */
