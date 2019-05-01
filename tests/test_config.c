#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>

#define MAX_LINES 20
static char *lines[MAX_LINES];
static int  curline;

static FILE my_fp;
static FILE *my_fopen(const char *path, const char *mode) { return &my_fp; }
static char *my_fgets(char *s, int size, FILE *fp) {
	if (lines[curline]) {
		strcpy(s, lines[curline++]);
		return s;
	}
	return NULL;
}
static int my_fclose(FILE *fp) { return 0; }

#define fopen my_fopen
#define fgets my_fgets
#define fclose my_fclose
#include "../config.c"
#undef fopen
#undef fgets
#undef fclose

static void verify_list(struct entry *head, int start, int end)
{
	struct entry *e = head;
	for (int i = start; i < end; ++i) {
		assert(e);
		char *p = strchr(lines[i], '=');
		if (p) {
			int len = p - lines[i];
			assert(strncmp(e->str, lines[i], len) == 0);
			assert(strcmp(e->folder, p + 1) == 0);
		} else {
			assert(strcmp(e->str, lines[i]) == 0);
			assert(e->folder == NULL);
		}
		e = e->next;
	}
	assert(e == NULL);
}

/* Run with valgrind to make sure no memory leaked */
int main(int argc, char *argv[])
{
	/* Add some entries */
	lines[0] = "[global]";
	lines[1] = "server=bogus";
	lines[2] = "port=993";
	lines[3] = "user=me";
	lines[4] = "passwd=none of your business";
	lines[5] = "[folders]";
	lines[6] = "root=father";
	lines[7] = "[whitelist]";
	lines[8] = "everything";

	curline = 0;
	assert(read_config() == 0);

	verify_list(global, 1, 5);
	verify_list(folderlist, 6, 7);
	verify_list(whitelist, 8, 9);

	/* change the global and add some entries */
	lines[1] = "server=good";
	lines[9] = "nothing";
	lines[10] = "meh";
	lines[11] = "fred";

	curline = 0;
	assert(read_config() == 0);

	verify_list(global, 1, 5);
	verify_list(folderlist, 6, 7);
	verify_list(whitelist, 8, 12);

	/* delete a first entry */
	for (int i = 8; i <= 12; ++i)
		lines[i] = lines[i + 1];

	curline = 0;
	assert(read_config() == 0);

	verify_list(global, 1, 5);
	verify_list(folderlist, 6, 7);
	verify_list(whitelist, 8, 11);

	/* delete a middle entry */
	for (int i = 9; i <= 10; ++i)
		lines[i] = lines[i + 1];

	curline = 0;
	assert(read_config() == 0);

	verify_list(global, 1, 5);
	verify_list(folderlist, 6, 7);
	verify_list(whitelist, 8, 10);

	/* delete a last entry */
	lines[8] = NULL;

	curline = 0;
	assert(read_config() == 0);

	verify_list(global, 1, 5);
	verify_list(folderlist, 6, 7);
	assert(whitelist == NULL);

	/* delete all */
	lines[1] = NULL;

	curline = 0;
	assert(read_config() == 0);

	assert(global != NULL); // globals not deleted
	assert(folderlist == NULL);
	assert(graylist == NULL);

	puts("Success!");
	return 0;
}

/*
 * Local Variables:
 * compile-command: "gcc -I.. -DIMAP -g -Wall test_config.c -o test_config"
 * End:
 */
