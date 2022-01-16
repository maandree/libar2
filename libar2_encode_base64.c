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
	size_t q, r, i;

	q = len / 3;
	r = len % 3;

	if (buf) {
		for (i = 0; i < q; i++, data += 3) {
			*buf++ = lut[O1(data[0], data[1], data[2]) & 255];
	                *buf++ = lut[O2(data[0], data[1], data[2]) & 255];
			*buf++ = lut[O3(data[0], data[1], data[2]) & 255];
	                *buf++ = lut[O4(data[0], data[1], data[2]) & 255];
		}
		if (r == 1) {
			*buf++ = lut[O1(data[0], 0, 0) & 255];
	                *buf++ = lut[O2(data[0], 0, 0) & 255];
		} else if (r == 2) {
			*buf++ = lut[O1(data[0], data[1], 0) & 255];
	                *buf++ = lut[O2(data[0], data[1], 0) & 255];
			*buf++ = lut[O3(data[0], data[1], 0) & 255];
		}
		*buf = '\0';
	}

	return (q * 4) + r + !!r + 1;
}
