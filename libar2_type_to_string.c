/* See LICENSE file for copyright and license details. */
#include "common.h"


const char *
libar2_type_to_string(enum libar2_argon2_type type, enum libar2_casing casing)
{
	static const char *strs[3][5] = {
		{"argon2d", "argon2i", "argon2id", NULL, "argon2ds"},
		{"Argon2d", "Argon2i", "Argon2id", NULL, "Argon2ds"},
		{"ARGON2D", "ARGON2I", "ARGON2ID", NULL, "ARGON2DS"}
	};

#if defined(__clang__)
# pragma clang diagnostic ignored "-Wtautological-unsigned-enum-zero-compare"
#endif

	if (type < 0 || casing < 0 || type >= ELEMSOF(*strs) || casing >= ELEMSOF(strs) || !strs[casing][type]) {
		errno = EINVAL;
		return NULL;
	}

	return strs[casing][type];
}
