#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>


int main(int argc, char *argv[])
{
	char line[80], subject[80];
	char is_me, saw_from, saw_date, is_ham, is_ignore, is_spam, bogo_spam;
	char from_me, learn, learn_flag;
	unsigned total = 0, not_me = 0, ignored = 0, real = 0, spam = 0;

	while (fgets(line, sizeof(line), stdin))
		if (sscanf(line, "%*s %c%c%c%c%c%c%c%c%c%c %[^\n]",
				   &is_me, &saw_from, &saw_date, &is_ham,
				   &is_ignore, &is_spam, &bogo_spam,
				   &from_me, &learn, &learn_flag,
				   subject) == 11) {
			if (learn == 'L') continue; /* ignore learn for now */
			++total;
			if (is_me == '-' && is_ignore == '-' && is_ham == '-')
				++not_me;
			else if ((is_me == 'M' || is_ham == 'H') && is_ignore == '-') {
				if (bogo_spam == '-') {
					++real;
					puts(subject);
				} else
					++spam;
			}
			if (is_ignore == 'I') ++ignored;
		} else
			printf("PROBS: %s", line);

	if (not_me + ignored + real + spam != total)
		printf("Problems with total\n");

	printf("Not me %u ignored %d real %u spam %u total %u\n",
		   not_me, ignored, real, spam, total);
	return 0;
}

/*
 * Local Variables:
 * compile-command: "gcc -O3 -Wall rtfsort.c -o rtfsort"
 * End:
 */
