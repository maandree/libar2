/* See LICENSE file for copyright and license details. */
#include "common.h"


int
libar2_string_to_version(const char *str, enum libar2_argon2_version *versionp)
{
	if (!strcmp(str, "10") || !strcmp(str, "1.0")) {
		*versionp = LIBAR2_ARGON2_VERSION_10;
		return 0;

	} else if (!strcmp(str, "13") || !strcmp(str, "1.3")) {
		*versionp = LIBAR2_ARGON2_VERSION_13;
		return 0;

	} else {
		errno = EINVAL;
		return -1;
	}
}
