#define WANT_FORWARDING
#ifdef WANT_FORWARDING

#include <curl/curl.h>

static void do_forward(const char *fname)
{
	CURL *curl;
	struct curl_slist *recipients = NULL;
	struct entry *e;
	int ok = sender ? 1 : 0;

	curl = curl_easy_init();
	if(!curl) {
		syslog(LOG_ERR, "Unable to initialize curl");
		return;
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
	curl_easy_setopt(curl, CURLOPT_MAIL_FROM, sender);

#ifdef SAM_NOT_YET
	/* We're using a callback function to specify the payload (the headers and
	 * body of the message). You could just use the CURLOPT_READDATA option to
	 * specify a FILE pointer to read from. */
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, payload_source);
	curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
	curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

	/* Send the message */
	res = curl_easy_perform(curl);

	if(res != CURLE_OK)
	  fprintf(stderr, "curl_easy_perform() failed: %s\n",
			  curl_easy_strerror(res));
#endif

cleanup:
	curl_slist_free_all(recipients);
	curl_easy_cleanup(curl);
}
#else
#define do_forward(f)
#endif
