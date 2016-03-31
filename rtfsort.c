#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>


static struct list {
	const char *fname;
	const char *subject;
	struct list *prev, *next;
} *head, *tail;

static int verbose;
static time_t start = (time_t)-1, end = (time_t)-1;


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

int main(int argc, char *argv[])
{
	char line[80], fname[80], *subject;
	char is_me, saw_from, saw_date, is_ham, is_ignore, is_spam, bogo_spam;
	char from_me, learn, learn_flag;
	unsigned total = 0, not_me = 0, from = 0, ignored = 0, real = 0, spam = 0;
	unsigned learned = 0;
	int c, n;

	while ((c = getopt(argc, argv, "d:v")) != EOF)
		switch (c) {
		case 'd':
			set_dates(optarg);
			break;
		case 'v':
			++verbose;
			break;
		}

	while (fgets(line, sizeof(line), stdin))
		if (sscanf(line, "%s %c%c%c%c%c%c%c%c%c%c%n",
				   fname, &is_me, &saw_from, &saw_date, &is_ham,
				   &is_ignore, &is_spam, &from_me, &bogo_spam,
				   &learn, &learn_flag,
				   &n) == 11) {
			if (!date_in_range(fname)) continue;
			++total;
			if (verbose)
				fputs(line, stderr);

			if (learn == 'L') {
				++learned;
				if (learn_flag == 'S') {
					if (check_list(fname)) {
						--real;
						++spam;
					} else
						printf("Problems %s\n", fname);
				} else if (learn_flag == 'H') {
					--spam;
					++real;
				} else
						printf("Problems learn flags %c\n", learn_flag);
				continue;
			}

			subject = line + n;
			if (*subject == ' ') ++subject;

			if (is_ignore == 'I')
				++ignored;
			else if (is_ham == 'H') {
				++real;
				add_list(fname, subject);
			} else if (is_me == '-')
				++not_me;
			else if (bogo_spam == '-' && from_me == '-') {
				++real;
				add_list(fname, subject);
			} else
				++spam;
			if (from_me == 'f')
				++from;
		} else
			printf("PROBS: %s", line);

	if (not_me + ignored + real + learned + spam != total)
		printf("Problems with total\n");

	// dump_list();

	printf("Not me %u from me %u ignored %d real %u learned %u spam %u total %u\n",
		   not_me, from, ignored, real, learned, spam, total);
	return 0;
}

/*
 * Local Variables:
 * compile-command: "gcc -O3 -Wall rtfsort.c -o rtfsort"
 * End:
 */
