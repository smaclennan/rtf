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

	assert(ignorelist != NULL);
	assert(strcmp(ignorelist->str, "everything") == 0);
	assert(ignorelist->folder == NULL);
	assert(ignorelist->next == NULL);

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

	struct entry *e = ignorelist;
	assert(e != NULL);
	assert(strcmp(e->str, "fred") == 0);
	assert(e->folder == NULL);
	e = e->next;
	assert(e != NULL);
	assert(strcmp(e->str, "meh") == 0);
	assert(e->folder == NULL);
	e = e->next;
	assert(e != NULL);
	assert(strcmp(e->str, "nothing") == 0);
	assert(e->folder == NULL);
	e = e->next;
	assert(e != NULL);
	assert(strcmp(e->str, "everything") == 0);
	assert(e->folder == NULL);
	assert(e->next == NULL);

	/* delete a first entry */
	lines[8] = NULL;

	curline = 0;
	assert(read_config() == 0);

	e = ignorelist;
	assert(e != NULL);
	assert(strcmp(e->str, "meh") == 0);
	assert(e->folder == NULL);
	e = e->next;
	assert(e != NULL);
	assert(strcmp(e->str, "nothing") == 0);
	assert(e->folder == NULL);
	e = e->next;
	assert(e != NULL);
	assert(strcmp(e->str, "everything") == 0);
	assert(e->folder == NULL);
	assert(e->next == NULL);

	/* delete a middle entry */
	lines[6] = "meh";
	lines[7] = NULL;

	curline = 0;
	assert(read_config() == 0);

	e = ignorelist;
	assert(e != NULL);
	assert(strcmp(e->str, "meh") == 0);
	assert(e->folder == NULL);
	e = e->next;
	assert(e != NULL);
	assert(strcmp(e->str, "everything") == 0);
	assert(e->folder == NULL);
	assert(e->next == NULL);

	/* delete a last entry */
	lines[5] = "meh";
	lines[6] = NULL;

	curline = 0;
	assert(read_config() == 0);

	e = ignorelist;
	assert(e != NULL);
	assert(strcmp(e->str, "meh") == 0);
	assert(e->folder == NULL);
	assert(e->next == NULL);

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
	lines[2] = "\\[Confluence]=+Confluence";
	lines[3] = "<jirabbqnx@blackberry.com>=Bugs";
	lines[4] = NULL;

	curline = 0;
	assert(read_config() == 0);

	e = folderlist;
	assert(e != NULL);
	assert(strcmp(e->str, "<jirabbqnx@blackberry.com>") == 0);
	assert(strcmp(e->folder, "Bugs") == 0);
	e = e->next;
	assert(e != NULL);
	assert(strcmp(e->str, "[Confluence]") == 0);
	assert(strcmp(e->folder, "+Confluence") == 0);
	e = e->next;
	assert(e != NULL);
	assert(strcmp(e->str, "Review Request") == 0);
	assert(strcmp(e->folder, "+Reviews") == 0);
	assert(e->next == NULL);

	/* delete everything again */
	lines[1] = NULL;

	curline = 0;
	assert(read_config() == 0);
	assert(folderlist == NULL);

	puts("Success!");
	return 0;
}

/*
 * Local Variables:
 * compile-command: "gcc -I.. -DIMAP -g -coverage -Wall test_config.c -o test_config"
 * End:
 */
