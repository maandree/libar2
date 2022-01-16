/* See LICENSE file for copyright and license details. */
#include "common.h"

#define FF 0xFF
static const unsigned char lut[256] = {
	FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF,
	FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF,
	FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, 62, FF, FF, FF, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, FF, FF, FF, FF, FF, FF,
	FF,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, FF, FF, FF, FF, FF,
	FF, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, FF, FF, FF, FF, FF,
	FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF,
	FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF,
	FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF,
	FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF,
	FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF,
	FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF,
	FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF,
	FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF
};


size_t
libar2_decode_base64(const char *str_, void *data_, size_t *lenp)
{
	const unsigned char *str = (const unsigned char *)str_;
	unsigned char *data = data_;
	unsigned char a, b, c, d;
	size_t ret = 0;

	*lenp = 0;

	for(;; str += 4) {
		if (lut[str[0]] == FF || lut[str[1]] == FF)
			break;
		a = lut[str[0]];
		b = lut[str[1]];
		ret += 2;
		if (data)
			*data++ = (unsigned char)((a << 2) | (b >> 4));
		++*lenp;

		if (lut[str[2]] == FF) {
			ret += (str[2] == '=');
			ret += (str[2] == '=' && str[3] == '=');
			break;
		}
		c = lut[str[2]];
		ret += 1;
		if (data)
			*data++ = (unsigned char)((b << 4) | (c >> 2));
		++*lenp;

		if (lut[str[3]] == FF) {
			ret += (str[3] == '=');
			break;
		}
		d = lut[str[3]];
		ret += 1;
		if (data)
			*data++ = (unsigned char)((c << 6) | (d >> 0));
		++*lenp;
	}

	return ret;
}
