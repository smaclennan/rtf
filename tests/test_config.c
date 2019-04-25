#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>

const char *home = "/home/test";
int just_checking;
int verbose;

#define MAX_LINES 10
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

static void verify_list(struct entry *head, int start)
{
	struct entry *e = head;
	for (int i = start; lines[i]; ++i) {
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
	lines[2] = "[folders]";
	lines[3] = "root=father";
	lines[4] = "[ignore]";
	lines[5] = "everything";

	curline = 0;
	assert(read_config() == 0);

	assert(global != NULL);
	assert(strcmp(global->str, "server") == 0);
	assert(strcmp(global->folder, "bogus") == 0);
	assert(global->next == NULL);

	assert(folderlist != NULL);
	assert(strcmp(folderlist->str, "root") == 0);
	assert(strcmp(folderlist->folder, "father") == 0);
	assert(folderlist->next == NULL);

	verify_list(ignorelist, 5);

	/* change the global and add some entries */
	lines[1] = "server=good";
	lines[6] = "nothing";
	lines[7] = "meh";
	lines[8] = "fred";

	curline = 0;
	assert(read_config() == 0);

	assert(global != NULL);
	assert(strcmp(global->str, "server") == 0);
	assert(strcmp(global->folder, "good") == 0);
	assert(global->next == NULL);

	assert(folderlist != NULL);
	assert(strcmp(folderlist->str, "root") == 0);
	assert(strcmp(folderlist->folder, "father") == 0);
	assert(folderlist->next == NULL);

	verify_list(ignorelist, 5);

	/* delete a first entry */
	for (int i = 5; i <= 8; ++i)
		lines[i] = lines[i + 1];

	curline = 0;
	assert(read_config() == 0);

	verify_list(ignorelist, 5);

	/* delete a middle entry */
	for (int i = 6; i <= 7; ++i)
		lines[i] = lines[i + 1];

	curline = 0;
	assert(read_config() == 0);

	verify_list(ignorelist, 5);

	/* delete a last entry */
	lines[6] = NULL;

	curline = 0;
	assert(read_config() == 0);

	verify_list(ignorelist, 5);

	/* delete the last entry */
	lines[5] = NULL;

	curline = 0;
	assert(read_config() == 0);

	verify_list(ignorelist, 5);

	/* delete all the rest */
	lines[1] = NULL;

	curline = 0;
	assert(read_config() == 0);

	assert(global == NULL);
	assert(folderlist == NULL);
	assert(ignorelist == NULL);

	/* test folderlist */
	lines[0] = "[folders]";
	lines[1] = "Review Request=+Reviews";
	lines[2] = "Confluence] BTS=inbox";
	lines[3] = "Confluence]=+Confluence";
	lines[4] = "<jirabbqnx@blackberry.com>=Bugs";
	lines[5] = NULL;

	curline = 0;
	assert(read_config() == 0);

	verify_list(folderlist, 1);

	/* delete everything again */
	lines[1] = NULL;

	curline = 0;
	assert(read_config() == 0);

	verify_list(folderlist, 1);

	puts("Success!");
	return 0;
}

/*
 * Local Variables:
 * compile-command: "gcc -I.. -DIMAP -g -coverage -Wall test_config.c -o test_config"
 * End:
 */
