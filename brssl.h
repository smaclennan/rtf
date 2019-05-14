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

/* This is a stripped down version of brssl.h from BearSSL/tools. */

#ifndef BRSSL_H__
#define BRSSL_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "bearssl.h"

/*
 * Make a structure type for a vector of 'type'.
 */
#define VECTOR(type)   struct { \
		type *buf; \
		size_t ptr, len; \
	}

/*
 * Constant initialiser for a vector.
 */
#define VEC_INIT   { 0, 0, 0 }

/*
 * Access a vector element by index. This is a lvalue, and can be modified.
 */
#define VEC_ELT(vec, idx)   ((vec).buf[idx])

/*
 * Get current vector length.
 */
#define VEC_LEN(vec)   ((vec).ptr)

/*
 * Type for a vector of trust anchors.
 */
typedef VECTOR(br_x509_trust_anchor) anchor_list;

/*
 * Decode certificates from a file and interpret them as trust anchors.
 * The trust anchors are added to the provided list. The number of found
 * anchors is returned; on error, 0 is returned (finding no anchor at
 * all is considered an error). An appropriate error message is displayed.
 */
size_t read_trust_anchors(anchor_list *dst, const char *fname);

/*
 * Special "no anchor" X.509 validator that wraps around another X.509
 * validator and turns "not trusted" error codes into success. This is
 * by definition insecure, but convenient for debug purposes.
 */
typedef struct {
	const br_x509_class *vtable;
	const br_x509_class **inner;
} x509_noanchor_context;

/*
 * Initialise a "no anchor" X.509 validator.
 */
void x509_noanchor_init(x509_noanchor_context *xwc,
	const br_x509_class **inner);

#endif
