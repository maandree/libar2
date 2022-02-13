/* See LICENSE file for copyright and license details. */
#include "common.h"


size_t
libar2_hash_buf_size(struct libar2_argon2_parameters *params)
{
	if (params->hashlen <= 64)
		return params->hashlen;
	if (params->hashlen > SIZE_MAX / 128 * 64 - 31) {
		errno = EOVERFLOW;
		return 0;
	}
	return (params->hashlen + 31) / 64 * 128;
}
