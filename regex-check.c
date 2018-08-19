#include "rtf.h"
#include <regex.h>


int main(int argc, char *argv[])
{
	if (argc == 1) {
		puts("I need a regular expression.");
		exit(1);
	}
	if (*argv[1] != '+') {
		puts("The regular expression must start with a +.");
		exit(1);
	}

	regex_t reg;
	regmatch_t match[1];

	int rc = regcomp(&reg, argv[1] + 1, REGEXP_FLAGS);
	if (rc) {
		char err[80];

		regerror(rc, &reg, err, sizeof(err));
		printf("%s: %s\n", argv[1], err);
		exit(1);
	}

	char line[128];
	while (fgets(line, sizeof(line), stdin))
		if (regexec(&reg, line, 1, match, 0) == 0)
			puts("Matched");
		else
			puts("No match");

	return 0;
}

/*
 * Local Variables:
 * compile-command: "gcc -O2 -Wall regex-check.c -o regex-check"
 * End:
 */
