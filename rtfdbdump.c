#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>

#ifdef SAMLIB
#include <samlib.h>


int main(int argc, char *argv[])
{
	if (argc == 1) {
		puts("I need a db file name\n");
		exit(1);
	}

	if (db_open(argv[1], 0, NULL)) {
		printf("Unable to open %s\n", argv[1]);
		exit(1);
	}

	db_walk(NULL, db_walk_long);

	return 0;
}
#else
int main(int argc, char *argv[])
{
	puts("Sorry. Disabled at compile time.");
	return 1;
}
#endif
