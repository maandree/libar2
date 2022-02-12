/* See LICENSE file for copyright and license details. */
#include "common.h"


size_t
libar2_encode_params(char *buf, const struct libar2_argon2_parameters *params)
{
	size_t off;

#define FMT_AND_ARGS_HEAD\
	"$%s$",\
	libar2_type_to_string(params->type, LIBAR2_LOWER_CASE)

#define FMT_AND_ARGS_VERSION\
	"v=%i$",\
	(int)params->version

#define FMT_AND_ARGS_TAIL\
	"m=%lu,t=%lu,p=%lu$",\
	(unsigned long int)params->m_cost,\
	(unsigned long int)params->t_cost,\
	(unsigned long int)params->lanes

	if (buf) {
		off = (size_t)sprintf(buf, FMT_AND_ARGS_HEAD);
		if (params->version)
			off += (size_t)sprintf(&buf[off], FMT_AND_ARGS_VERSION);
		off += (size_t)sprintf(&buf[off], FMT_AND_ARGS_TAIL);
		off += libar2_encode_base64(&buf[off], params->salt, params->saltlen) - 1;
		buf[off++] = '$';
		buf[off++] = '\0';

	} else {
		off = (size_t)snprintf(NULL, 0, FMT_AND_ARGS_HEAD);
		if (params->version)
			off += (size_t)snprintf(NULL, 0, FMT_AND_ARGS_VERSION);
		off += (size_t)snprintf(NULL, 0, FMT_AND_ARGS_TAIL);
		off += libar2_encode_base64(NULL, params->salt, params->saltlen) - 1;
		off += 2;
	}

	return off;
}
