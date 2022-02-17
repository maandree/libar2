/* See LICENSE file for copyright and license details. */
#include "common.h"


static size_t
decode_u32(const char *s, uint_least32_t *outp)
{
	uint_least32_t digit;
	size_t i;

	if ((s[0] == '0' && isdigit(s[1])) || !isdigit(s[0])) {
		errno = EINVAL;
		return 0;
	}

	*outp = 0;
	for (i = 0; isdigit(s[i]); i++) {
		digit = (uint_least32_t)(s[i] & 15);
		if (*outp > (UINT_LEAST32_C(0xFFFFffff) - digit) / 10) {
			errno = ERANGE;
			return 0;
		}
		*outp = *outp * 10 + digit;
	}

	return i;
}


size_t
libar2_decode_params(const char *str, struct libar2_argon2_parameters *params, char **bufp, struct libar2_context *ctx)
{
	const char *start = str;
	uint_least32_t u32;
	size_t n, q, r;

	*bufp = NULL;
	params->salt = NULL;
	params->saltlen = 0;
	params->key = NULL;
	params->keylen = 0;
	params->ad = NULL;
	params->adlen = 0;

	if (*str++ != '$')
		goto einval;

	if (libar2_string_to_type(str, &params->type))
		goto fail;
	while (*str && *str != '$')
		str++;

	if (*str++ != '$')
		goto einval;

	if (str[0] == 'v' && str[1] == '=') {
		n = decode_u32(&str[2], &u32);
		if (!n)
			goto fail;
		if (u32 > (uint_least32_t)INT_MAX)
			goto erange;
		if (!u32)
			goto einval;
		params->version = (enum libar2_argon2_version)u32;
		str += n + 2;
		if (*str++ != '$')
			goto einval;
	} else {
#if defined(__clang__)
# pragma clang diagnostic push
# pragma clang diagnostic ignored "-Wassign-enum"
#endif
		params->version = 0; /* implicit LIBAR2_ARGON2_VERSION_10 */
#if defined(__clang__)
# pragma clang diagnostic pop
#endif
	}

	if (str[0] != 'm' || str[1] != '=')
		goto einval;
	str += 2;
	n = decode_u32(str, &params->m_cost);
	if (!n)
		goto fail;
	str += n;

	if (str[0] != ',' || str[1] != 't' || str[2] != '=')
		goto einval;
	str += 3;
	n = decode_u32(str, &params->t_cost);
	if (!n)
		goto fail;
	str += n;

	if (str[0] != ',' || str[1] != 'p' || str[2] != '=')
		goto einval;
	str += 3;
	n = decode_u32(str, &params->lanes);
	if (!n)
		goto fail;
	str += n;

	if (*str++ != '$')
		goto einval;

	n = libar2_decode_base64(str, NULL, &params->saltlen);
	if (params->saltlen) {
		*bufp = ctx->allocate(params->saltlen, sizeof(char), ALIGNOF(char), ctx);
		if (!*bufp)
			goto fail;
	}
	str += libar2_decode_base64(str, *bufp, &params->saltlen);
	params->salt = (void *)*bufp;

	if (*str++ != '$')
		goto einval;

	params->hashlen = 0;
	while (isalnum(str[params->hashlen]) || str[params->hashlen] == '+' || str[params->hashlen] == '/')
		params->hashlen += 1;
	q = params->hashlen / 4;
	r = params->hashlen % 4;
	params->hashlen = q * 3 + (r == 3 ? 2 : r == 2 ? 1 : 0);

	return (size_t)(str - start);

erange:
	errno = ERANGE;
	goto fail;

einval:
	errno = EINVAL;
fail:
	if (*bufp) {
		ctx->deallocate(*bufp, ctx);
		*bufp = NULL;
	}
	return 0;
}
