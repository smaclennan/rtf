#ifndef __RTF_H__
#define __RTF_H__

#define _GNU_SOURCE /* for strcasestr */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <syslog.h>
#include <errno.h>
#include <time.h>
#include <regex.h>
#include <sys/file.h>
#include <sys/stat.h>

#define IS_HAM			0x1
#define IS_IGNORED		0x2
#define IS_SPAM			0x4
#define IS_ME			0x8
#define FROM_ME			0x10
#define SAW_DATE		0x20
#define SAW_FROM		0x40
#define BOGO_SPAM		0x80
#define SAW_APP			0x100
#define FORWARD			0x200
/* flags for rtfsort */
#define LEARN_SPAM		0x1000
#define LEARN_HAM		0x2000

#define LEARN_DIR		".LearnSPAM"
#define HAM_DIR			".Ham"
#define SPAM_DIR		".Spam"
/* The drop dir can be the same as the spam dir */
#define DROP_DIR		".Drop"
#define IGNORE_DIR		".Ignore"

#define REGEXP_FLAGS (REG_EXTENDED | REG_ICASE | REG_NEWLINE)

#ifdef IMAP
/* imap-rtf only */

// config.c
struct entry {
	const char *str;
	const char *folder;
#ifdef IMAP
	int generation;
#else
	regex_t *reg;
#endif
	struct entry *next;
};

extern struct entry *global;
extern struct entry *melist;
extern struct entry *fromlist;
extern struct entry *whitelist;
extern struct entry *blacklist;
extern struct entry *ignorelist;
extern struct entry *folderlist;

const char *get_global(const char *glob);
int get_global_num(const char *glob);
int read_config(void);

// imap-rtf.c
extern int verbose;
extern int just_checking;
extern const char *home;
extern unsigned cur_uid;

void filter(void);
void logmsg(const char *fmt, ...);
void logit(void);
void run(void);

// bear.c
int ssl_open(int sock, const char *host);
int ssl_read(char *buffer, int len);
int ssl_timed_read(char *buffer, int len, int timeout);
int ssl_write(const char *buffer, int len);
int ssl_close(void);

// eyemap.c
int connect_to_server(const char *server, int port,
					  const char *user, const char *passwd);
int process_list(void);
char *fetchline(char *buf, int len);
int imap_move(const char *to);
#endif

#endif
