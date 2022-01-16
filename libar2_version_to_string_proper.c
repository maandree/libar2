/* See LICENSE file for copyright and license details. */
#include "common.h"


const char *
libar2_version_to_string_proper(enum libar2_argon2_version version)
{
	if (version == LIBAR2_ARGON2_VERSION_10) {
		return "1.0";

	} else if (version == LIBAR2_ARGON2_VERSION_13) {
		return "1.3";

	} else {
		errno = EINVAL;
		return NULL;
	}
}
