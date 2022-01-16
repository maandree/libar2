/* See LICENSE file for copyright and license details. */
#include "common.h"


enum libar2_parameter_error
libar2_validate_params(const struct libar2_argon2_parameters *params, const char **errmsgp)
{
#define LIBAR2_X__(ENUM, ERRMESG, CONDITION)\
	if (CONDITION) {\
		if (errmsgp)\
			*errmsgp = ERRMESG;\
		return ENUM;\
	}
	LIBAR2_LIST_PARAMETER_ERRORS(LIBAR2_X__, params);
#undef LIBAR2_X__

	if (errmsgp)
		*errmsgp = "OK";
	return LIBAR2_OK;
}
