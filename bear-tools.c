/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/* This is the code from various BearSSL/tools C files that where needed
 * to read the certificates and deal with noanchor mode. None of this
 * code is mine.
 */

#include "brssl.h"

/*
 * Type for a named blob (the 'name' is a normalised PEM header name).
 */
typedef struct {
	char *name;
	unsigned char *data;
	size_t data_len;
} pem_object;

/* see brssl.h */
static void *
xmalloc(size_t len)
{
	void *buf;

	if (len == 0) {
		return NULL;
	}
	buf = malloc(len);
	if (buf == NULL) {
		fprintf(stderr, "ERROR: could not allocate %lu byte(s)\n",
			(unsigned long)len);
		exit(EXIT_FAILURE);
	}
	return buf;
}

/* see brssl.h */
static void
xfree(void *buf)
{
	if (buf != NULL) {
		free(buf);
	}
}

/* see brssl.h */
static void *
xblobdup(const void *src, size_t len)
{
	void *buf;

	buf = xmalloc(len);
	memcpy(buf, src, len);
	return buf;
}

/* see brssl.h */
static char *
xstrdup(const void *src)
{
	return xblobdup(src, strlen(src) + 1);
}

/*
 * Macros for growable arrays.
 */

/*
 * Clear a vector.
 */
#define VEC_CLEAR(vec)   do { \
		xfree((vec).buf); \
		(vec).buf = NULL; \
		(vec).ptr = 0; \
		(vec).len = 0; \
	} while (0)

/*
 * Clear a vector, first calling the provided function on each vector
 * element.
 */
#define VEC_CLEAREXT(vec, fun)   do { \
		size_t vec_tmp; \
		for (vec_tmp = 0; vec_tmp < (vec).ptr; vec_tmp ++) { \
			(fun)(&(vec).buf[vec_tmp]); \
		} \
		VEC_CLEAR(vec); \
	} while (0)

/*
 * Add a value at the end of a vector.
 */
#define VEC_ADD(vec, x)   do { \
		(vec).buf = vector_expand((vec).buf, sizeof *((vec).buf), \
			&(vec).ptr, &(vec).len, 1); \
		(vec).buf[(vec).ptr ++] = (x); \
	} while (0)

/*
 * Add several values at the end of a vector.
 */
#define VEC_ADDMANY(vec, xp, num)   do { \
		size_t vec_num = (num); \
		(vec).buf = vector_expand((vec).buf, sizeof *((vec).buf), \
			&(vec).ptr, &(vec).len, vec_num); \
		memcpy((vec).buf + (vec).ptr, \
			(xp), vec_num * sizeof *((vec).buf)); \
		(vec).ptr += vec_num; \
	} while (0)

/*
 * Copy all vector elements into a newly allocated block.
 */
#define VEC_TOARRAY(vec)    xblobdup((vec).buf, sizeof *((vec).buf) * (vec).ptr)

/*
 * Prepare a vector buffer for adding 'extra' elements.
 *   buf      current buffer
 *   esize    size of a vector element
 *   ptr      pointer to the 'ptr' vector field
 *   len      pointer to the 'len' vector field
 *   extra    number of elements to add
 *
 * If the buffer must be enlarged, then this function allocates the new
 * buffer and releases the old one. The new buffer address is then returned.
 * If the buffer needs not be enlarged, then the buffer address is returned.
 *
 * In case of enlargement, the 'len' field is adjusted accordingly. The
 * 'ptr' field is not modified.
 */
static void *
vector_expand(void *buf,
	size_t esize, size_t *ptr, size_t *len, size_t extra)
{
	size_t nlen;
	void *nbuf;

	if (*len - *ptr >= extra) {
		return buf;
	}
	nlen = (*len << 1);
	if (nlen - *ptr < extra) {
		nlen = extra + *ptr;
		if (nlen < 8) {
			nlen = 8;
		}
	}
	nbuf = xmalloc(nlen * esize);
	if (buf != NULL) {
		memcpy(nbuf, buf, *len * esize);
		xfree(buf);
	}
	*len = nlen;
	return nbuf;
}

/*
 * Type for a vector of bytes.
 */
typedef VECTOR(unsigned char) bvector;

static int
is_ign(int c)
{
	if (c == 0) {
		return 0;
	}
	if (c <= 32 || c == '-' || c == '_' || c == '.'
		|| c == '/' || c == '+' || c == ':')
	{
		return 1;
	}
	return 0;
}

/*
 * Get next non-ignored character, normalised:
 *    ASCII letters are converted to lowercase
 *    control characters, space, '-', '_', '.', '/', '+' and ':' are ignored
 * A terminating zero is returned as 0.
 */
static int
next_char(const char **ps, const char *limit)
{
	for (;;) {
		int c;

		if (*ps == limit) {
			return 0;
		}
		c = *(*ps) ++;
		if (c == 0) {
			return 0;
		}
		if (c >= 'A' && c <= 'Z') {
			c += 'a' - 'A';
		}
		if (!is_ign(c)) {
			return c;
		}
	}
}

/*
 * Partial string equality comparison, with normalisation.
 */
static int
eqstr_chunk(const char *s1, size_t s1_len, const char *s2, size_t s2_len)
{
	const char *lim1, *lim2;

	lim1 = s1 + s1_len;
	lim2 = s2 + s2_len;
	for (;;) {
		int c1, c2;

		c1 = next_char(&s1, lim1);
		c2 = next_char(&s2, lim2);
		if (c1 != c2) {
			return 0;
		}
		if (c1 == 0) {
			return 1;
		}
	}
}

/* see brssl.h */
static int
eqstr(const char *s1, const char *s2)
{
	return eqstr_chunk(s1, strlen(s1), s2, strlen(s2));
}

/* see brssl.h */
static unsigned char *
read_file(const char *fname, size_t *len)
{
	bvector vbuf = VEC_INIT;
	FILE *f;

	*len = 0;
	f = fopen(fname, "rb");
	if (f == NULL) {
		fprintf(stderr,
			"ERROR: could not open file '%s' for reading\n", fname);
		return NULL;
	}
	for (;;) {
		unsigned char tmp[1024];
		size_t rlen;

		rlen = fread(tmp, 1, sizeof tmp, f);
		if (rlen == 0) {
			unsigned char *buf;

			if (ferror(f)) {
				fprintf(stderr,
					"ERROR: read error on file '%s'\n",
					fname);
				fclose(f);
				return NULL;
			}
			buf = VEC_TOARRAY(vbuf);
			*len = VEC_LEN(vbuf);
			VEC_CLEAR(vbuf);
			fclose(f);
			return buf;
		}
		VEC_ADDMANY(vbuf, tmp, rlen);
	}
}

/* see brssl.h */
static int
looks_like_DER(const unsigned char *buf, size_t len)
{
	int fb;
	size_t dlen;

	if (len < 2) {
		return 0;
	}
	if (*buf ++ != 0x30) {
		return 0;
	}
	fb = *buf ++;
	len -= 2;
	if (fb < 0x80) {
		return (size_t)fb == len;
	} else if (fb == 0x80) {
		return 0;
	} else {
		fb -= 0x80;
		if (len < (size_t)fb + 2) {
			return 0;
		}
		len -= (size_t)fb;
		dlen = 0;
		while (fb -- > 0) {
			if (dlen > (len >> 8)) {
				return 0;
			}
			dlen = (dlen << 8) + (size_t)*buf ++;
		}
		return dlen == len;
	}
}

static void
vblob_append(void *cc, const void *data, size_t len)
{
	bvector *bv;

	bv = cc;
	VEC_ADDMANY(*bv, data, len);
}

/* see brssl.h */
static void
free_pem_object_contents(pem_object *po)
{
	if (po != NULL) {
		xfree(po->name);
		xfree(po->data);
	}
}

/* see brssl.h */
static pem_object *
decode_pem(const void *src, size_t len, size_t *num)
{
	VECTOR(pem_object) pem_list = VEC_INIT;
	br_pem_decoder_context pc;
	pem_object po, *pos;
	const unsigned char *buf;
	bvector bv = VEC_INIT;
	int inobj;
	int extra_nl;

	*num = 0;
	br_pem_decoder_init(&pc);
	buf = src;
	inobj = 0;
	po.name = NULL;
	po.data = NULL;
	po.data_len = 0;
	extra_nl = 1;
	while (len > 0) {
		size_t tlen;

		tlen = br_pem_decoder_push(&pc, buf, len);
		buf += tlen;
		len -= tlen;
		switch (br_pem_decoder_event(&pc)) {

		case BR_PEM_BEGIN_OBJ:
			po.name = xstrdup(br_pem_decoder_name(&pc));
			br_pem_decoder_setdest(&pc, vblob_append, &bv);
			inobj = 1;
			break;

		case BR_PEM_END_OBJ:
			if (inobj) {
				po.data = VEC_TOARRAY(bv);
				po.data_len = VEC_LEN(bv);
				VEC_ADD(pem_list, po);
				VEC_CLEAR(bv);
				po.name = NULL;
				po.data = NULL;
				po.data_len = 0;
				inobj = 0;
			}
			break;

		case BR_PEM_ERROR:
			xfree(po.name);
			VEC_CLEAR(bv);
			fprintf(stderr,
				"ERROR: invalid PEM encoding\n");
			VEC_CLEAREXT(pem_list, &free_pem_object_contents);
			return NULL;
		}

		/*
		 * We add an extra newline at the end, in order to
		 * support PEM files that lack the newline on their last
		 * line (this is somwehat invalid, but PEM format is not
		 * standardised and such files do exist in the wild, so
		 * we'd better accept them).
		 */
		if (len == 0 && extra_nl) {
			extra_nl = 0;
			buf = (const unsigned char *)"\n";
			len = 1;
		}
	}
	if (inobj) {
		fprintf(stderr, "ERROR: unfinished PEM object\n");
		xfree(po.name);
		VEC_CLEAR(bv);
		VEC_CLEAREXT(pem_list, &free_pem_object_contents);
		return NULL;
	}

	*num = VEC_LEN(pem_list);
	VEC_ADD(pem_list, po);
	pos = VEC_TOARRAY(pem_list);
	VEC_CLEAR(pem_list);
	return pos;
}

/* see brssl.h */
static br_x509_certificate *
read_certificates(const char *fname, size_t *num)
{
	VECTOR(br_x509_certificate) cert_list = VEC_INIT;
	unsigned char *buf;
	size_t len;
	pem_object *pos;
	size_t u, num_pos;
	br_x509_certificate *xcs;
	br_x509_certificate dummy;

	*num = 0;

	/*
	 * TODO: reading the whole file is crude; we could parse them
	 * in a streamed fashion. But it does not matter much in practice.
	 */
	buf = read_file(fname, &len);
	if (buf == NULL) {
		return NULL;
	}

	/*
	 * Check for a DER-encoded certificate.
	 */
	if (looks_like_DER(buf, len)) {
		xcs = xmalloc(2 * sizeof *xcs);
		xcs[0].data = buf;
		xcs[0].data_len = len;
		xcs[1].data = NULL;
		xcs[1].data_len = 0;
		*num = 1;
		return xcs;
	}

	pos = decode_pem(buf, len, &num_pos);
	xfree(buf);
	if (pos == NULL) {
		return NULL;
	}
	for (u = 0; u < num_pos; u ++) {
		if (eqstr(pos[u].name, "CERTIFICATE")
			|| eqstr(pos[u].name, "X509 CERTIFICATE"))
		{
			br_x509_certificate xc;

			xc.data = pos[u].data;
			xc.data_len = pos[u].data_len;
			pos[u].data = NULL;
			VEC_ADD(cert_list, xc);
		}
	}
	for (u = 0; u < num_pos; u ++) {
		free_pem_object_contents(&pos[u]);
	}
	xfree(pos);

	if (VEC_LEN(cert_list) == 0) {
		fprintf(stderr, "ERROR: no certificate in file '%s'\n", fname);
		return NULL;
	}
	*num = VEC_LEN(cert_list);
	dummy.data = NULL;
	dummy.data_len = 0;
	VEC_ADD(cert_list, dummy);
	xcs = VEC_TOARRAY(cert_list);
	VEC_CLEAR(cert_list);
	return xcs;
}

/* see brssl.h */
static void
free_certificates(br_x509_certificate *certs, size_t num)
{
	size_t u;

	for (u = 0; u < num; u ++) {
		xfree(certs[u].data);
	}
	xfree(certs);
}

static void
dn_append(void *ctx, const void *buf, size_t len)
{
	VEC_ADDMANY(*(bvector *)ctx, buf, len);
}

static int
certificate_to_trust_anchor_inner(br_x509_trust_anchor *ta,
	br_x509_certificate *xc)
{
	br_x509_decoder_context dc;
	bvector vdn = VEC_INIT;
	br_x509_pkey *pk;

	br_x509_decoder_init(&dc, dn_append, &vdn);
	br_x509_decoder_push(&dc, xc->data, xc->data_len);
	pk = br_x509_decoder_get_pkey(&dc);
	if (pk == NULL) {
		fprintf(stderr, "ERROR: CA decoding failed with error %d\n",
			br_x509_decoder_last_error(&dc));
		VEC_CLEAR(vdn);
		return -1;
	}
	ta->dn.data = VEC_TOARRAY(vdn);
	ta->dn.len = VEC_LEN(vdn);
	VEC_CLEAR(vdn);
	ta->flags = 0;
	if (br_x509_decoder_isCA(&dc)) {
		ta->flags |= BR_X509_TA_CA;
	}
	switch (pk->key_type) {
	case BR_KEYTYPE_RSA:
		ta->pkey.key_type = BR_KEYTYPE_RSA;
		ta->pkey.key.rsa.n = xblobdup(pk->key.rsa.n, pk->key.rsa.nlen);
		ta->pkey.key.rsa.nlen = pk->key.rsa.nlen;
		ta->pkey.key.rsa.e = xblobdup(pk->key.rsa.e, pk->key.rsa.elen);
		ta->pkey.key.rsa.elen = pk->key.rsa.elen;
		break;
	case BR_KEYTYPE_EC:
		ta->pkey.key_type = BR_KEYTYPE_EC;
		ta->pkey.key.ec.curve = pk->key.ec.curve;
		ta->pkey.key.ec.q = xblobdup(pk->key.ec.q, pk->key.ec.qlen);
		ta->pkey.key.ec.qlen = pk->key.ec.qlen;
		break;
	default:
		fprintf(stderr, "ERROR: unsupported public key type in CA\n");
		xfree(ta->dn.data);
		return -1;
	}
	return 0;
}

/* see brssl.h */
static void
free_ta_contents(br_x509_trust_anchor *ta)
{
	xfree(ta->dn.data);
	switch (ta->pkey.key_type) {
	case BR_KEYTYPE_RSA:
		xfree(ta->pkey.key.rsa.n);
		xfree(ta->pkey.key.rsa.e);
		break;
	case BR_KEYTYPE_EC:
		xfree(ta->pkey.key.ec.q);
		break;
	}
}

/* see brssl.h */
size_t
read_trust_anchors(anchor_list *dst, const char *fname)
{
	br_x509_certificate *xcs;
	anchor_list tas = VEC_INIT;
	size_t u, num;

	xcs = read_certificates(fname, &num);
	if (xcs == NULL) {
		return 0;
	}
	for (u = 0; u < num; u ++) {
		br_x509_trust_anchor ta;

		if (certificate_to_trust_anchor_inner(&ta, &xcs[u]) < 0) {
			VEC_CLEAREXT(tas, free_ta_contents);
			free_certificates(xcs, num);
			return 0;
		}
		VEC_ADD(tas, ta);
	}
	VEC_ADDMANY(*dst, &VEC_ELT(tas, 0), num);
	VEC_CLEAR(tas);
	free_certificates(xcs, num);
	return num;
}

static void
xwc_start_chain(const br_x509_class **ctx, const char *server_name)
{
	x509_noanchor_context *xwc;

	xwc = (x509_noanchor_context *)ctx;
	(*xwc->inner)->start_chain(xwc->inner, server_name);
}

static void
xwc_start_cert(const br_x509_class **ctx, uint32_t length)
{
	x509_noanchor_context *xwc;

	xwc = (x509_noanchor_context *)ctx;
	(*xwc->inner)->start_cert(xwc->inner, length);
}

static void
xwc_append(const br_x509_class **ctx, const unsigned char *buf, size_t len)
{
	x509_noanchor_context *xwc;

	xwc = (x509_noanchor_context *)ctx;
	(*xwc->inner)->append(xwc->inner, buf, len);
}

static void
xwc_end_cert(const br_x509_class **ctx)
{
	x509_noanchor_context *xwc;

	xwc = (x509_noanchor_context *)ctx;
	(*xwc->inner)->end_cert(xwc->inner);
}

static unsigned
xwc_end_chain(const br_x509_class **ctx)
{
	x509_noanchor_context *xwc;
	unsigned r;

	xwc = (x509_noanchor_context *)ctx;
	r = (*xwc->inner)->end_chain(xwc->inner);
	if (r == BR_ERR_X509_NOT_TRUSTED) {
		r = 0;
	}
	return r;
}

static const br_x509_pkey *
xwc_get_pkey(const br_x509_class *const *ctx, unsigned *usages)
{
	x509_noanchor_context *xwc;

	xwc = (x509_noanchor_context *)ctx;
	return (*xwc->inner)->get_pkey(xwc->inner, usages);
}

/* see brssl.h */
const br_x509_class x509_noanchor_vtable = {
	sizeof(x509_noanchor_context),
	xwc_start_chain,
	xwc_start_cert,
	xwc_append,
	xwc_end_cert,
	xwc_end_chain,
	xwc_get_pkey
};

/* see brssl.h */
void
x509_noanchor_init(x509_noanchor_context *xwc, const br_x509_class **inner)
{
	xwc->vtable = &x509_noanchor_vtable;
	xwc->inner = inner;
}
