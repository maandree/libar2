/* See LICENSE file for copyright and license details. */
#include "common.h"


size_t
libar2_hash_buf_size(const struct libar2_argon2_parameters *params)
{
	if (params->hashlen <= 64)
		return params->hashlen;
	if (params->hashlen > SIZE_MAX - 31 ||
	    ((params->hashlen + 31) | 31) == SIZE_MAX) {
		errno = EOVERFLOW;
		return 0;
	}
	return ((params->hashlen + 31) | 31) + 1;
}
