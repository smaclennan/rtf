#include "rtf.h"

static struct list {
	const char *fname;
	const char *subject;
	struct list *prev, *next;
} *head, *tail;

static int verbose;
static time_t start = (time_t)-1, end = (time_t)-1;

struct log_struct {
	char fname[80];
	char is_me;
	char saw_from;
	char saw_date;
	char is_ham;
	char is_ignore;
	char is_spam;
	char from_me;
	char bogo_spam;
	char learn;
	char learn_flag;
	char subject[80];
};

struct sort_counts {
	/* both */
	unsigned total;
	unsigned ignored;
	unsigned real;
	unsigned spam;
	unsigned learned;

	/* only sort */
	unsigned not_me;
	unsigned from;

	/* only for actions */
	unsigned drop;
	unsigned ham;
	unsigned bogo;
	unsigned bogo_total;
	unsigned learned_ham;
};

static void add_list(const char *fname, const char *subject)
{
	struct list *l = calloc(1, sizeof(struct list));
	fname = strdup(fname);
	subject = strdup(subject);
	if (!l || !fname || !subject) {
		puts("Out of memory");
		exit(1);
	}

	l->fname = fname;
	l->subject = subject;

	if (head) {
		l->prev = tail;
		tail->next = l;
	} else
		head = l;
	tail = l;
}

static int check_list(const char *fname)
{
	struct list *l;

	for (l = head; l; l = l->next)
		if (strcmp(l->fname, fname) == 0) {
			/* actually spam */
			if (l->prev)
				l->prev->next = l->next;
			if (l->next)
				l->next->prev = l->prev;
			if (l == head)
				head = l->next;
			if (l == tail)
				tail = l->prev;

			free((void *)l->fname);
			free((void *)l->subject);
			free(l);

			return 1;
		}

	return 0;
}

void dump_list(void)
{
	struct list *l;

	for (l = head; l; l = l->next)
		puts(l->subject);
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
	if (l->learn == 'L') {
		++sc->learned;
		if (l->learn_flag == 'S') {
			if (check_list(l->fname)) {
				--sc->real;
				++sc->spam;
			} else
				printf("Problems %s\n", l->fname);
		} else if (l->learn_flag == 'H') {
			--sc->spam;
			++sc->real;
		} else
			printf("Problems learn flags %c\n", l->learn_flag);
		return;
	}

	if (l->is_ignore == 'I')
		++sc->ignored;
	else if (l->is_ham == 'H') {
		++sc->real;
		add_list(l->fname, l->subject);
	} else if (l->is_me == '-')
		++sc->not_me;
	else if (l->bogo_spam == '-' && l->from_me == '-') {
		++sc->real;
		add_list(l->fname, l->subject);
	} else
		++sc->spam;
	if (l->from_me == 'f')
		++sc->from;
}

static void handle_actions(struct log_struct *l, struct sort_counts *sc)
{
	if (l->learn == 'L') {
		if (l->learn_flag == 'S')
			++sc->learned;
		else
			++sc->learned_ham;
	} else if (l->is_ignore == 'I')
		++sc->ignored;
	else if (l->is_ham == 'H')
		++sc->ham;
	else if (l->is_spam == 'A' || l->is_spam == 'Z')
		++sc->drop;
	else if (l->is_spam == 'S' ||
			 l->saw_from == '-' || l->saw_date == '-' ||
			 l->from_me == 'M' || l->is_me == '-')
		++sc->spam;
	else if (l->bogo_spam == 'B')
		++sc->bogo;
	else
		++sc->real;

	if (l->bogo_spam == 'B')
		++sc->bogo_total;
}

int main(int argc, char *argv[])
{
	char line[80];
	int c, n, do_actions = 0;
	struct log_struct l;
	struct sort_counts sc;

	while ((c = getopt(argc, argv, "ad:v")) != EOF)
		switch (c) {
		case 'a': /* count actions */
			do_actions = 1;
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
		if (sscanf(line, "%s %c%c%c%c%c%c%c%c%c%c%n",
				   l.fname, &l.is_me, &l.saw_from, &l.saw_date,
				   &l.is_ham, &l.is_ignore, &l.is_spam, &l.from_me,
				   &l.bogo_spam, &l.learn, &l.learn_flag, &n) == 11) {
			if (!date_in_range(l.fname)) continue;
			++sc.total;
			if (verbose)
				fputs(line, stderr);

			if (line[n] == ' ')
				++n;
			snprintf(l.subject, sizeof(l.subject), "%s", line + n);

			if (do_actions)
				handle_actions(&l, &sc);
			else
				handle_line(&l, &sc);
		} else
			printf("PROBS: %s", line);
	}

	if (do_actions) {
		printf("Ignored %u ham %u drop %u spam %u bogo %u real %u learned %u\n",
			   sc.ignored, sc.ham, sc.drop, sc.spam, sc.bogo, sc.real, sc.learned);

		unsigned actual_spam = sc.spam + sc.drop + sc.bogo + sc.learned;

		printf("We caught %.0f%% bogofilter %.0f%% missed %.0f%%\n",
			   (double)(sc.spam + sc.drop) * 100.0 / (double)actual_spam,
			   (double)sc.bogo_total * 100.0 / (double)actual_spam,
			   (double)sc.learned * 100.0 / (double)actual_spam);
		printf("Spam was %.0f%% of all messages\n",
			   (double)actual_spam * 100.0 / (double)sc.total);
	} else {
		if (sc.not_me + sc.ignored + sc.real + sc.learned + sc.spam != sc.total)
			printf("Problems with total\n");

		// dump_list();

		printf("Not me %u from me %u ignored %d real %u learned %u spam %u total %u\n",
			   sc.not_me, sc.from, sc.ignored, sc.real, sc.learned, sc.spam, sc.total);
	}

	return 0;
}

/*
 * Local Variables:
 * compile-command: "gcc -O3 -Wall rtfsort.c -o rtfsort"
 * End:
 */
