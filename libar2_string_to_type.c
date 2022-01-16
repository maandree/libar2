/* See LICENSE file for copyright and license details. */
#include "common.h"


int
libar2_string_to_type(const char *str, enum libar2_argon2_type *typep)
{
#define STRSTARTS(A, B) (!strncmp(A, B, sizeof(B) - 1))

	if (!strcasecmp(str, "argon2d") || STRSTARTS(str, "argon2d$")) {
		*typep = LIBAR2_ARGON2D;
		return 0;

	} else if (!strcasecmp(str, "argon2i") || STRSTARTS(str, "argon2i$")) {
		*typep = LIBAR2_ARGON2I;
		return 0;

	} else if (!strcasecmp(str, "argon2id") || STRSTARTS(str, "argon2id$")) {
		*typep = LIBAR2_ARGON2ID;
		return 0;

	} else if (!strcasecmp(str, "argon2ds") || STRSTARTS(str, "argon2ds$")) {
		*typep = LIBAR2_ARGON2DS;
		return 0;

	} else {
		errno = EINVAL;
		return -1;
	}
}
