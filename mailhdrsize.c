#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>

static int maxline;
static int max_nlines;
static int max_bytes;

static void process_file(FILE *fp)
{
	char line[1024];
	int nlines = 0, bytes = 0;

	while (fgets(line, sizeof(line), fp)) {
		int n = strlen(line);
		bytes += n;
		if (n > maxline)
			maxline = n;
		++nlines;

		if (*line == '\n')
			break; /* end of header */
	}

	printf("Lines %3d Bytes %d\n", nlines, bytes); // SAM DBG

	if (nlines > max_nlines)
		max_nlines = nlines;
	if (bytes > max_bytes)
		max_bytes = bytes;
}

int main(int argc, char *argv[])
{
	if (argc == 1)
		process_file(stdin);
	else {
		int arg;

		for (arg = 1; arg < argc; ++arg) {
			FILE *fp = fopen(argv[arg], "r");
			if (fp) {
				process_file(fp);
				fclose(fp);
			} else
				perror(argv[arg]);
		}
	}

	printf("Max line %d\n", maxline);
	printf("Max header lines %d\n", max_nlines);
	printf("Max bytes %d\n", max_bytes);

	return 0;
}

/*
 * Local Variables:
 * compile-command: "gcc -O3 -Wall mailhdrsize.c -o mailhdrsize"
 * End:
 */
