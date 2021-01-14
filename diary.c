#include "rtf.h"
#include <stdint.h>

/* Since the reply buffer is BUFFER_SIZE, this is the maximum size for
 * the base64 buffer after decoding.
 */
static char decode_buffer[(BUFFER_SIZE + 3) / 4 * 3];

static struct dst_block {
	char *base;
	char *cur;
} dst;

static int local_tz_offset = -1;

#ifndef STANDALONE
static void write_str(int fd, const char *str)
{
	int n;

	do
		n = write(fd, str, strlen(str));
	while (n < 0 && errno == EINTR);
}

static int open_diary(void)
{
	int fd = open(diary, O_WRONLY | O_APPEND | O_CREAT, 0644);
	if (fd < 0) {
		logmsg(LOG_ERR, "unable to open diary %s", diary);
		return -1;
	}

	int n;
	do
		n = flock(fd, LOCK_EX);
	while (n < 0 && errno == EINTR);
	if (n < 0) {
		logmsg(LOG_ERR, "flock %s", strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

static void close_diary(int fd)
{
	int n;
	do
		n = flock(fd, LOCK_UN);
	while (n < 0 && errno == EINTR);
	close(fd);
}

static void write_diary(const char *dtstart,
						const char *summary,
						const char *location)
{
	int fd = open_diary();
	if (fd < 0)
		return;

	char buf[1024];
	int n = snprintf(buf, sizeof(buf), "\n%s %s\n", dtstart, summary);
	if (location && *location)
		n += snprintf(buf + n, sizeof(buf) - n, "\t%s\n", location);

	write_str(fd, buf);

	close_diary(fd);
}
#else
static void write_diary(const char *dtstart,
						const char *summary,
						const char *location)
{
	printf("%s %s\n", dtstart, summary);
	if (location && *location)
		printf("\t%s\n", location);
}
#endif

static int tz_offset(char *base)
{
	char *tz = strstr(base, "BEGIN:VTIMEZONE");
	if (!tz) return 0;
	tz = strstr(tz, "BEGIN:STANDARD");
	if (!tz) return 0;
	tz = strstr(tz, "TZOFFSETTO:");
	if (!tz) return 0;
	int offset = strtol(tz + 11, NULL, 10);
	offset = (offset / 100) - local_tz_offset;
	return offset;
}

static int process_vcal(struct dst_block *dst)
{
	char summary[64] = "MISSING";
	char dtstart[32] = "";
	char location[64] = "";
	char uid[256] = "";

	// Limit to the vevent or we might get a false DTSTART
	dst->cur = strstr(dst->base, "BEGIN:VEVENT");
	if (!dst->cur) return -1;

	char *p = strstr(dst->cur, "UID:");
	if (p) {
		int state = 0;
		char *out = uid;

		p += 4;

		while (state >= 0) {
			switch(state) {
			case 0:
				switch (*p) {
				case '0'...'9':
				case 'A'...'F':
					*out++ = *p;
					break;
				case '\r':
					break;
				case '\n':
					state = 1;
					break;
				default:
					state = -1;
				}
				break;
			case 1:
				state = *p == ' ' ? 0 : -1;
				break;
			}
			++p;
		}
		*out = 0;
	}

	p = strstr(dst->cur, "\nSUMMARY");
	if (p && (p = strchr(p, ':'))) {
		char *out = summary;
		++p; // skip :
		for (int i = 0; i < sizeof(summary) - 1; ++i)
			if (*p == '\n') {
				// check for continuation
				if (*(p + 1) == ' ')
					p += 2;
				else
					break;
			} else if (*p == '\r')
				++p;
			else
				*out++ = *p++;
		*out = 0;
	}

	p = strstr(dst->cur, "\nDTSTART");
	if (!p) return -1;

	// Usually you get:
	// DTSTART;TZID=Eastern Standard Time:20191213T100000
	// but sometimes:
	// DTSTART;TZID="(UTC-05:00) Eastern Time (US & Canada)":20191211T130000
	char *e = strchr(p + 1, '\n');
	if (!e) return -1;
	while (*e != ':' && e > p) --e;
	if (*e != ':') return -1;

	uint64_t date, time;
	if (sscanf(e + 1, "%ldT%ld", &date, &time) != 2) {
		logmsg(LOG_WARNING, "bad date %s", p);
		return -1;
	}

	int day = date % 100; date /= 100;
	int month = date % 100; date /= 100;
	int year = date;

	time /= 100; // drop seconds
	int minute = time % 100; time /= 100;
	int hour = time - tz_offset(dst->base);

	sprintf(dtstart, "%d/%d/%d %02d:%02d", month, day, year, hour, minute);

	if ((p = strstr(dst->cur, "\nLOCATION"))) {
		if ((p = strchr(p, ':'))) {
			++p;
			// Deal with location with no location
			if (*p != '\r' && *p != '\n') {
				snprintf(location, sizeof(location), "%s", p);
				strtok(location, "\r\n");
			}
		}
	}

	write_diary(dtstart, summary, location);

	return 0;
}

static void calc_local_timezone_offset(void)
{
	if (local_tz_offset != -1)
		return;

	// calc local timezone offset
	// we always use standard time
	time_t now = time(NULL);
	struct tm *tm = gmtime(&now);
	int gmt = tm->tm_hour;
	tm = localtime(&now);
	local_tz_offset = tm->tm_hour - gmt - tm->tm_isdst;
}

static const uint8_t reverse[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0x3e, 0xff, 0x3e, 0xff, 0x3f,
	0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
	0x3c, 0x3d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
	0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
	0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
	0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0x3f,
	0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
	0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
	0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff,
};

/* decode 4 bytes into 3
 * < 6 > < 2 | 4 > < 4 | 2 > < 6 >
 */
static int decode_block(char *dst, const char *src)
{
	uint8_t block[4];
	int i;

	for (i = 0; i < 4; ++i, ++src) {
		if (*src == '=')
			break;
		block[i] = reverse[*src & 0x7f];
		if (block[i] == 0xff)
			return -1;
	}

	if (i > 1)
		*dst++ = ((block[0] << 2) & 0xfc) | ((block[1] >> 4) & 3);
	if (i > 2)
		*dst++ = ((block[1] << 4) & 0xf0) | ((block[2] >> 2) & 0xf);
	if (i > 3)
		*dst++ = ((block[2] << 6) & 0xc0) | (block[3] & 0x3f);
	return i - 1;
}

static int base64_decode(struct dst_block *dst, char *src)
{
	char *line;

	while ((line = strtok(src, "\r\n"))) {
		int len = strlen(line);
		if (len & 3) {
			return -1; // bad line
		}
		while (len >= 4) {
			int n = decode_block(dst->cur, line);
			if (n == -1) {
				*dst->cur = 0;
				logmsg(LOG_ERR, "base64 decode error");
				return EINVAL; /* invalid input */
			}
			dst->cur += n;
			line += 4;
			len -= 4;
		}
		src = NULL;
	}
	*dst->cur = 0;
	return 0;
}

static int look_for_vcal(unsigned int uid)
{
	char *p = strstr(reply, "Content-Type: text/calendar");
	if (!p)
		return 0;

	p = strchr(p, '\n');
	if (!p) {
		logmsg(LOG_ERR, "Bad calendar line for %u", uid);
		return 0;
	}

	++p;
	if (strncmp(p, "Content-Transfer-Encoding: base64", 33)) {
		// Untested - all the vcal emails I get are base64
		dst.base = p;
		return 1;
	}

	p = strchr(p, '\n');
	if (!p) {
		logmsg(LOG_ERR, "Bad encoding line for %u", uid);
		return 0;
	}
	++p;
	int sawcr = 0;
	if (*p == '\r') {
		sawcr = 1;
		++p; // skip empty line
	}
	if (*p == '\n') ++p; // skip empty line

	char *end;
	if (sawcr)
		end = strstr(p, "\n\r\n");
	else
		end = strstr(p, "\n\n");
	if (end) *(end + 1) = 0;

	// Deal with possible part. -2 is to skip possible \r.
	// part ends with -- so it is safe either way
	if (*(end - 2) == '-') {
		for (end -= 3; *end != '\r' && *end != '\n'; --end) ;
		*end = 0;
	}

	dst.base = decode_buffer;
	dst.cur = dst.base;
	if (base64_decode(&dst, p)) {
		logmsg(LOG_ERR, "Base64 decode failed for %u", uid);
		return 0;
	}

	return 1;
}

static int process_diary(unsigned int uid)
{
	if (!look_for_vcal(uid))
		return 0;

	calc_local_timezone_offset();

	if (process_vcal(&dst)) {
		logmsg(LOG_ERR, "Unable to parse vcal for %u", uid);
		return 0;
	}

	return 1; // success
}


#ifndef STANDALONE
int find_diary(unsigned int uid)
{
	int rc = send_recv("UID FETCH %u (BODY.PEEK[TEXT])", uid);
	if (rc) {
		logmsg(LOG_ERR, "Unable to fetch body for %u", uid);
		return 0;
	}

	return process_diary(uid);
}
#else
char reply[BUFFER_SIZE];

void logmsg(int type, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	putchar('\n');
}

/* diary < diary_file */
int main(int argc, char *argv[])
{
	size_t n = read(0, reply, sizeof(reply) - 1);
	if (n <= 0) {
		perror("read");
		exit(1);
	}
	reply[n] = 0;

	return !process_diary(0);
}
#endif

/*
 * Local Variables:
 * compile-command: "cc -DSTANDALONE -DIMAP -O2 -Wall diary.c -o diary"
 * End:
 */
