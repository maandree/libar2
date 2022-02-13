/* See LICENSE file for copyright and license details. */
#include "common.h"


size_t
libar2_hash_buf_size(struct libar2_argon2_parameters *params)
{
	return (params->hashlen > 64 && (params->hashlen & 127)) ? (params->hashlen | 127) + 1 : params->hashlen;
}
