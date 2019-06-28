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

/* Largest buffer I have seen is 6,761 */
#define BUFFER_SIZE (16 * 1024)

// config.c
struct entry {
	const char *str;
	const char *folder;
	int generation;
	struct entry *next;
};

extern struct entry *global;
extern struct entry *whitelist;
extern struct entry *graylist;
extern struct entry *blacklist;
extern struct entry *folderlist;
extern struct entry *cleanlist;

extern char *home;
extern int verbose;
extern int use_stderr;

const char *get_global(const char *glob);
int get_global_num(const char *glob);
int read_config(void);
void logmsg(const char *fmt, ...);
void uid_validity(void);
void do_reload(void);

// bear.c
int ssl_open(int sock, const char *host);
int ssl_read(char *buffer, int len);
int ssl_timed_read(char *buffer, int len, int timeout);
int ssl_write(const char *buffer, int len);
void ssl_close(void);
int ssl_read_cert(const char *fname);

// eyemap.c
extern char reply[]; // BUFFER_SIZE
extern int is_exchange;

int connect_to_server(const char *server, int port,
					  const char *user, const char *passwd);
int send_recv(const char *fmt, ...);
int send_cmd(const char *cmd);
int fetch(unsigned uid);
int fetchline(char *buf, int len);
int check_folders(void);
#endif

#endif
