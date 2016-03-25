#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>


static struct list {
	const char *fname;
	const char *subject;
	struct list *prev, *next;
} *head, *tail;


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

int main(int argc, char *argv[])
{
	char line[80], fname[80], subject[80];
	char is_me, saw_from, saw_date, is_ham, is_ignore, is_spam, bogo_spam;
	char from_me, learn, learn_flag;
	unsigned total = 0, not_me = 0, from = 0, ignored = 0, real = 0, spam = 0;
	unsigned learned = 0;

	while (fgets(line, sizeof(line), stdin))
		if (sscanf(line, "%s %c%c%c%c%c%c%c%c%c%c %[^\n]",
				   fname, &is_me, &saw_from, &saw_date, &is_ham,
				   &is_ignore, &is_spam, &from_me, &bogo_spam,
				   &learn, &learn_flag,
				   subject) == 12) {
			if (learn == 'L') {
				if (learn_flag == 'S')
					if (check_list(fname)) {
						--real;
						++learned;
					}
			}
			++total;
			if (is_me == '-' && is_ignore == '-' && is_ham == '-')
				++not_me;
			else if ((is_me == 'M' || is_ham == 'H') && is_ignore == '-') {
				if (bogo_spam == '-' && from_me == '-') {
					++real;
					add_list(fname, subject);
					// puts(subject);
				} else
					++spam;
			}
			if (is_ignore == 'I')
				++ignored;
			if (from_me == 'f') {
				++from;
				// puts(subject);
			}
		} else if (sscanf(line, "%s %c%c%c%c%c%c%c%c%c%c",
						  fname, &is_me, &saw_from, &saw_date, &is_ham,
						  &is_ignore, &is_spam, &bogo_spam,
						  &from_me, &learn, &learn_flag) == 11) {
			if (learn_flag == 'S')
				if (check_list(fname)) {
					--real;
					++learned;
				}
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
