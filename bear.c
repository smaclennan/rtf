#include <unistd.h>
#include <errno.h>
#include <sys/poll.h>
#include "bearssl.h"


/*
 * Special "no anchor" X.509 validator that wraps around another X.509
 * validator and turns "not trusted" error codes into success. This is
 * by definition insecure, but convenient for debug purposes.
 */
typedef struct {
	const br_x509_class *vtable;
	const br_x509_class **inner;
} x509_noanchor_context;

static br_ssl_client_context sc;
static br_x509_minimal_context xc;
static unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
static br_sslio_context ioc;
static x509_noanchor_context xwc;
static int sock_fd = -1;

static void
xwc_start_chain(const br_x509_class **ctx, const char *server_name)
{
	x509_noanchor_context *xwc = (x509_noanchor_context *)ctx;
	(*xwc->inner)->start_chain(xwc->inner, server_name);
}

static void
xwc_start_cert(const br_x509_class **ctx, uint32_t length)
{
	x509_noanchor_context *xwc = (x509_noanchor_context *)ctx;
	(*xwc->inner)->start_cert(xwc->inner, length);
}

static void
xwc_append(const br_x509_class **ctx, const unsigned char *buf, size_t len)
{
	x509_noanchor_context *xwc = (x509_noanchor_context *)ctx;
	(*xwc->inner)->append(xwc->inner, buf, len);
}

static void
xwc_end_cert(const br_x509_class **ctx)
{
	x509_noanchor_context *xwc = (x509_noanchor_context *)ctx;
	(*xwc->inner)->end_cert(xwc->inner);
}

static unsigned
xwc_end_chain(const br_x509_class **ctx)
{
	x509_noanchor_context *xwc = (x509_noanchor_context *)ctx;
	unsigned r = (*xwc->inner)->end_chain(xwc->inner);
	if (r == BR_ERR_X509_NOT_TRUSTED) {
		r = 0;
	}
	return r;
}

static const br_x509_pkey *
xwc_get_pkey(const br_x509_class *const *ctx, unsigned *usages)
{
	x509_noanchor_context *xwc = (x509_noanchor_context *)ctx;
	return (*xwc->inner)->get_pkey(xwc->inner, usages);
}

static const br_x509_class x509_noanchor_vtable = {
	sizeof(x509_noanchor_context),
	xwc_start_chain,
	xwc_start_cert,
	xwc_append,
	xwc_end_cert,
	xwc_end_chain,
	xwc_get_pkey
};

static void
x509_noanchor_init(x509_noanchor_context *xwc, const br_x509_class **inner)
{
	xwc->vtable = &x509_noanchor_vtable;
	xwc->inner = inner;
}

static int
sock_read(void *ctx, unsigned char *buf, size_t len)
{
	int rlen;
	do
		rlen = read(sock_fd, buf, len);
	while (rlen < 0 && errno == EINTR);
	return rlen;
}

static int
sock_write(void *ctx, const unsigned char *buf, size_t len)
{
	int wlen;
	do
		wlen = write(sock_fd, buf, len);
	while (wlen < 0 && errno == EINTR);
	return wlen;
}

int ssl_open(int sock, const char *host)
{
	br_ssl_client_init_full(&sc, &xc, NULL, 0);

	x509_noanchor_init(&xwc, &xc.vtable);
	br_ssl_engine_set_x509(&sc.eng, &xwc.vtable);

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
		default:
			perror("poll"); // SAM DBG
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
