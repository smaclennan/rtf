#include <unistd.h>
#include <errno.h>
#include <sys/poll.h>
#include "bearssl.h"
#include "rtf.h"

/* WARNING: If you do not provide a $HOME/.rtf.d/cert file, then the
 * code falls back to "no anchor" mode. This is very insecure but
 * useful for initially debugging the connections.
 */

/* Hint: One what to get the cert:
openssl s_client -connect google.ca:443 -showcerts > /tmp/out
massage /tmp/out - You want the second cert
*/

#include "BearSSL/tools/certs.c"
#include "BearSSL/tools/xmem.c"
#include "BearSSL/tools/vector.c"
#include "BearSSL/tools/files.c"
#include "BearSSL/tools/names.c"

typedef VECTOR(br_x509_certificate) cert_list;

static anchor_list anchors = VEC_INIT;
static cert_list chain = VEC_INIT;

/* Called from read_config(). Note we do not cleanup memory on
 * error. If ssl_read_cert returns non-zero imap-rtf will exit.
 */
int ssl_read_cert(const char *fname, int anchor)
{
	if (anchor) {
		if (read_trust_anchors(&anchors, fname) == 0)
			return 1;
	} else {
		size_t num;
		br_x509_certificate *xcs = read_certificates(fname, &num);
		if (xcs == NULL)
			return 1;
		VEC_ADDMANY(chain, xcs, num);
		xfree(xcs);
	}
	return 0;
}

static br_ssl_client_context sc;
static br_x509_minimal_context xc;
static unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
static br_sslio_context ioc;
static x509_noanchor_context xwc;
static int sock_fd = -1;

/* The read/write callbacks  cannot return 0. EOF is considered an error. */
static int sock_read(void *ctx, unsigned char *buf, size_t len)
{
	int rlen;
	do
		rlen = read(sock_fd, buf, len);
	while (rlen < 0 && errno == EINTR);
	if (rlen == 0)
		return -1;
	return rlen;
}

static int sock_write(void *ctx, const unsigned char *buf, size_t len)
{
	int wlen;
	do
		wlen = write(sock_fd, buf, len);
	while (wlen < 0 && errno == EINTR);
	if (wlen == 0)
		return -1;
	return wlen;
}

int ssl_open(int sock, const char *host)
{
	if (VEC_LEN(anchors) == 0) {
		size_t num = VEC_LEN(chain);

		if (num == 0) {
			logmsg("Warning: No cert");
			xwc.vtable = &x509_noanchor_vtable;
			xwc.inner = &xwc.vtable;
			br_ssl_engine_set_x509(&sc.eng, &xwc.vtable);
		} else {
			// Convert certs to trust anchors
			anchor_list tas = VEC_INIT;

			for (size_t u = 0; u < num; u++) {
				br_x509_trust_anchor ta;

				if (certificate_to_trust_anchor_inner(&ta, &VEC_ELT(chain, u)) < 0)
					return 1;

				VEC_ADD(tas, ta);
			}
			VEC_ADDMANY(anchors, &VEC_ELT(tas, 0), num);
			VEC_CLEAR(tas);
			free_certificates(&VEC_ELT(chain, 0), num);
		}

		br_ssl_client_init_full(&sc, &xc, &VEC_ELT(anchors, 0), VEC_LEN(anchors));
	} else {
		// SAM FIXME
	}

	br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof iobuf, 1);

	if (br_ssl_client_reset(&sc, host, 0) == 0)
		return 1;

	sock_fd = sock;
	br_sslio_init(&ioc, &sc.eng, sock_read, &sock_fd, sock_write, &sock_fd);

	return 0;
}

int ssl_read(char *buffer, int len)
{
	return br_sslio_read(&ioc, buffer, len);
}

int ssl_timed_read(char *buffer, int len, int timeout)
{
	struct pollfd ufd = { .fd = sock_fd, .events = POLLIN };
	int n;

	while (1)
		switch(poll(&ufd, 1, timeout)) {
		case 0: // timeout
			return 0;
		case 1:
			n = br_sslio_read(&ioc, buffer, len);
			if (n == 0) return -1;
			return n;
		}
}

int ssl_write(const char *buffer, int len)
{
	int rc = br_sslio_write_all(&ioc, buffer, len);
	br_sslio_flush(&ioc);
	return rc == 0 ? len : -1;
}

int ssl_close(void)
{
	if (br_ssl_engine_current_state(&sc.eng) == BR_SSL_CLOSED) {
		return br_ssl_engine_last_error(&sc.eng);
	}
	return 0;
}
