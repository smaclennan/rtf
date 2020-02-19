#include "rtf.h"

#if 0
struct dst_block {
	char *base;
	char *cur;
	int curlen;
	int maxlen;
};

static int local_tz_offset;

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
		logit("unable to open diary %s", diary);
		return -1;
	}

	int n;
	do
		n = flock(fd, LOCK_EX);
	while (n < 0 && errno == EINTR);
	if (n < 0) {
		logit("flock %s", strerror(errno));
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
						const char *location,
						const char *uid)
{
	int fd = open_diary();
	if (fd < 0)
		return;

	char buf[1024];
	int n = snprintf(buf, sizeof(buf), "\n%s %s\n", dtstart, summary);
	if (uid && *uid)
		n += snprintf(buf + n, sizeof(buf) - n, "\t%s\n", uid);
	if (location && *location)
		n += snprintf(buf + n, sizeof(buf) - n, "\t%s\n", location);

	write_str(fd, buf);

	close_diary(fd);
}

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

	if (dst->base == NULL)
		return -1;

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
		logit("bad date %s", p);
		return -1;
	}

	int day = date % 100; date /= 100;
	int month = date % 100; date /= 100;
	int year = date;

	time /= 100; // drop seconds
	int minute = time % 100; time /= 100;
	int hour = time - tz_offset(dst->base);

	sprintf(dtstart, "%d/%d/%d %02d:%02d", month, day, year, hour, minute);

	if ((p = strstr(dst->cur, "\nLOCATION")))
		if ((p = strchr(p, ':'))) {
			snprintf(location, sizeof(location), "%s", p + 1);
			strtok(location, "\r\n");
		}

	write_diary(dtstart, summary, location, hash);

	return 0;
}

static void calc_local_timezone_offset(void)
{	// calc local timezone offset
	// we always use standard time
	time_t now = time(NULL);
	struct tm *tm = gmtime(&now);
	int gmt = tm->tm_hour;
	tm = localtime(&now);
	local_tz_offset = tm->tm_hour - gmt - tm->tm_isdst;
}
#endif

void process_diary(unsigned int uid, int base64)
{
}
