/* See LICENSE file for copyright and license details. */
#include "common.h"


size_t
libar2_encode_params(char *buf, const struct libar2_argon2_parameters *params)
{
	size_t off;

#define FMT_AND_ARGS\
	"$%s$v=%i$m=%ju,t=%ju,p=%ju$",\
	libar2_type_to_string(params->type, LIBAR2_LOWER_CASE),\
	(int)params->version,\
	(uintmax_t)params->m_cost,\
	(uintmax_t)params->t_cost,\
	(uintmax_t)params->lanes

	if (buf) {
		off = (size_t)sprintf(buf, FMT_AND_ARGS);
		off += libar2_encode_base64(&buf[off], params->salt, params->saltlen) - 1;
		buf[off++] = '$';
		buf[off++] = '\0';

	} else {
		off = (size_t)snprintf(NULL, 0, FMT_AND_ARGS);
		off += libar2_encode_base64(NULL, params->salt, params->saltlen) - 1;
		off += 2;
	}

	return off;
}
