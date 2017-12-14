#define WANT_FORWARDING
#ifdef WANT_FORWARDING

#include <curl/curl.h>

struct user_data {
	const char *fname;
	FILE *fp;
	int output;
};

static size_t read_callback(char *output, size_t size, size_t nmemb, void *datap)
{
	struct user_data *data = datap;
	int ch;
	size_t n = 0;

	/* I have always seen size == 1 */
	if (size == 1)
		size = nmemb;
	else
		size *= nmemb;
	if (size > 0)
		--size; /* we need room for possible \r\n */

	if (data->output == 0) {
		/* We need to find the first "real" header line */
		while (fgets(output, size, data->fp))
			if (!isspace(*output) &&
				strncmp(output, "Received:", 9) &&
				strncmp(output, "Return-Path:", 12) &&
				strncmp(output, "Delivered-To:", 13)) {
				data->output = 1;
				char *p = strchr(output, '\n');
				if (p) *p = 0;
				strcat(output, "\r\n");
				n = strlen(output);
				output += n;
				break;
			}
	}

	while (n < size && (ch = fgetc(data->fp)) != EOF) {
		if (ch == '\n') {
			*output++ = '\r';
			++n;
		}
		*output++ = ch;
		++n;
	}

	return n;
}

static void do_forward(const char *fname)
{
	CURL *curl = NULL;
	struct curl_slist *recipients = NULL;
	struct entry *e;
	int ok = 1; /* we currently always have sender */
	struct user_data upload_ctx;
	CURLcode res;
	char from[128];

	upload_ctx.fname = fname;
	upload_ctx.output = 0;
	upload_ctx.fp = fopen(fname, "r");
	if (!upload_ctx.fp) {
		syslog(LOG_ERR, "tmpfile %s: %m", fname);
		return;
	}

	curl = curl_easy_init();
	if(!curl) {
		syslog(LOG_ERR, "Unable to initialize curl");
		goto cleanup;
	}

	/* parse the forward list */
	for (e = forwardlist; e; e = e->next)
		if (strncmp(e->str, "smtp=", 5) == 0) {
			curl_easy_setopt(curl, CURLOPT_URL, e->str + 5);
			ok |= 2;
		} else if (strncmp(e->str, "to=", 3) == 0) {
			recipients = curl_slist_append(recipients, e->str + 3);
			ok |= 4;
		}

	if (ok != 7) {
		syslog(LOG_ERR, "Invalid configuraton: %d", ok);
		goto cleanup;
	}

	curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
	
	snprintf(from, sizeof(from), "<%s>", sender);
	curl_easy_setopt(curl, CURLOPT_MAIL_FROM, from);

	curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
	curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
	curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

	/* Send the message */
	res = curl_easy_perform(curl);
	if(res != CURLE_OK)
		syslog(LOG_ERR, "curl_easy_perform() failed: %s", curl_easy_strerror(res));

cleanup:
	fclose(upload_ctx.fp);
	curl_slist_free_all(recipients);
	curl_easy_cleanup(curl);
}
#else
#define do_forward(f)
#endif
