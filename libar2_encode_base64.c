/* See LICENSE file for copyright and license details. */
#include "common.h"


#define ALPHABET "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
static char lut[256] = ALPHABET ALPHABET ALPHABET ALPHABET;

#define O1(I1, I2, I3) ((I1) >> 2)
#define O2(I1, I2, I3) (((I1) << 4) | ((I2) >> 4))
#define O3(I1, I2, I3) (((I2) << 2) | ((I3) >> 6))
#define O4(I1, I2, I3) (I3)


size_t
libar2_encode_base64(char *buf, const void *data_, size_t len)
{
	const unsigned char *data = data_;
	unsigned char a, b, c;
	size_t q, r, i;

	q = len / 3;
	r = len % 3;

	if (buf) {
		buf = &buf[q * 4];
		data = &data[q * 3];

		if (r == 1) {
			a = data[0];
			buf[0] = lut[O1(a, 0, 0) & 255];
	                buf[1] = lut[O2(a, 0, 0) & 255];
			buf[2] = '\0';
		} else if (r == 2) {
			a = data[0], b = data[1];
			buf[0] = lut[O1(a, b, 0) & 255];
	                buf[1] = lut[O2(a, b, 0) & 255];
			buf[2] = lut[O3(a, b, 0) & 255];
			buf[3] = '\0';
		} else {
			buf[0] = '\0';
		}

		for (i = 0; i < q; i++) {
			data -= 3;
			buf -= 4;
			a = data[0], b = data[1], c = data[2];
			buf[0] = lut[O1(a, b, c) & 255];
	                buf[1] = lut[O2(a, b, c) & 255];
			buf[2] = lut[O3(a, b, c) & 255];
	                buf[3] = lut[O4(a, b, c) & 255];
		}
	}

	return (q * 4) + r + !!r + 1;
}
