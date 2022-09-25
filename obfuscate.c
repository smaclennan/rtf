#include "rtf.h"
#include <stdint.h>
#include <string.h>

#define MAX_PASSWD 80
#define MAX_ENCODE_LEN ((MAX_PASSWD + 2 + 2) / 3 * 4)

#define TEA_BAG_SIZE 8
#define TEA_CONSTANT 0x9e3779b9u

// Some random numbers
#define MAGIC_1	0xa16ffe6e
#define MAGIC_2	0x04a6fd88
#define MAGIC_3 0x0b35bfc1
#define MAGIC_4 0xe0890e78

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
static int decode_block(uint8_t *dst, const char *src)
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

	/* For legal input, i > 1 */
	*dst++ = ((block[0] << 2) & 0xfc) | ((block[1] >> 4) & 3);
	if (i > 2)
		*dst++ = ((block[1] << 4) & 0xf0) | ((block[2] >> 2) & 0xf);
	if (i > 3)
		*dst++ = ((block[2] << 6) & 0xc0) | (block[3] & 0x3f);
	return i - 1;
}

/* Returns 0 on decode error. Some legacy code assumes decode can never fail. */
int base64_decode(uint8_t *dst, int dlen, const char *src, int len)
{
	int n, cnt = 0;

	while (len >= 4) {
		if ((n = decode_block(dst, src)) == -1)
			return 0; /* invalid input */
		dst += n;
		cnt += n;
		src += 4;
		len -= 4;
	}

	return cnt;
}

void tea_decrypt(const void *key, void *data, int len)
{
	const uint32_t *k = key;
	uint32_t *v = data;

	while (len >= TEA_BAG_SIZE) {
		uint32_t sum = 0xC6EF3720;
		uint32_t v0 = v[0], v1 = v[1];

		for (int i = 0; i < 32; i++) {
			v1 -= ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
			v0 -= ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
			sum -= TEA_CONSTANT;
		}

		v[0] = v0; v[1] = v1;

		v += 2;
		len -= TEA_BAG_SIZE;
	}
}

void unobfuscate(const char *encoded)
{
	if (encoded == NULL)
		return;

	char buf[MAX_PASSWD + 7 + 1];
	char *data = buf + 5;

	base64_decode((uint8_t *)data, MAX_PASSWD + 1, encoded, strlen(encoded));

	uint32_t key[4] = { MAGIC_1, MAGIC_2, MAGIC_3, MAGIC_4 };
	key[0] ^= data[0];
	key[2] ^= data[1];

	tea_decrypt(key, data + 2, data[1]);

	memcpy(buf, "passwd=", 7);
	add_entry(&global, buf);
}
