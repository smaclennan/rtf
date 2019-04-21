#ifndef __RTF_H__
#define __RTF_H__

#define _GNU_SOURCE /* for strcasestr */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <syslog.h>
#include <errno.h>
#include <time.h>
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

/* imap-rtf only */

// bear.c
int ssl_open(int sock, const char *host);
int ssl_read(char *buffer, int len);
int ssl_write(const char *buffer, int len);
int ssl_close(void);

// eyemap.c
int connect_to_server(const char *server, int port,
					  const char *user, const char *passwd);
int build_list(void);


#endif
