/* See LICENSE file for copyright and license details. */
#include "common.h"
#include <stdlib.h>


#define MEM(S) S, sizeof(S) - 1


#define assert(TRUTH) assert_(TRUTH, #TRUTH, __LINE__)
#define assert_streq(RESULT, EXPECT) assert_streq_(RESULT, EXPECT, #RESULT, __LINE__)
#define assert_zueq(RESULT, EXPECT) assert_zueq_(RESULT, EXPECT, #RESULT, __LINE__)

static int from_lineno = 0;


static void *
allocate(size_t num, size_t size, size_t alignment, struct libar2_context *ctx)
{
	void *ptr;
	int err;
	(void) ctx;
	if (num > SIZE_MAX / size) {
		errno = ENOMEM;
		return NULL;
	}
	if (alignment < sizeof(void *))
		alignment = sizeof(void *);
	err = posix_memalign(&ptr, alignment, num * size);
	if (err) {
		errno = err;
		return NULL;
	} else {
		return ptr;
	}
}

static void
deallocate(void *ptr, struct libar2_context *ctx)
{
	(void) ctx;
	free(ptr);
}

static int
st_init_thread_pool(size_t desired, size_t *createdp, struct libar2_context *ctx)
{
	(void) desired;
	(void) ctx;
	*createdp = 0;
	return 0;
}

static struct libar2_context ctx_st = {
	.user_data = NULL,
	.autoerase_message = 1,
	.autoerase_secret = 1,
	.autoerase_salt = 1,
	.autoerase_associated_data = 1,
	.allocate = allocate,
	.deallocate = deallocate,
	.init_thread_pool = st_init_thread_pool,
	.get_ready_threads = NULL,
	.run_thread = NULL,
	.join_thread_pool = NULL,
	.destroy_thread_pool = NULL
};


static int
nulstrcmp(const char *a, const char *b)
{
	return !a ? -!!b : !b ? +1 : strcmp(a, b);
}


static void
assert_(int truth, const char *truthstr, int lineno)
{
	if (!truth) {
		if (from_lineno)
			fprintf(stderr, "Assertion at line %i, from line %i failed: %s\n", lineno, from_lineno, truthstr);
		else
			fprintf(stderr, "Assertion at line %i failed: %s\n", lineno, truthstr);
		fprintf(stderr, "\terrno: %i (%s)\n", errno, strerror(errno));
		exit(1);
	}
}


static void
assert_streq_(const char *result, const char *expect, const char *code, int lineno)
{
	if (nulstrcmp(result, expect)) {
		if (from_lineno)
			fprintf(stderr, "Assertion at line %i, form line %i failed:\n", lineno, from_lineno);
		else
			fprintf(stderr, "Assertion at line %i failed:\n", lineno);
		fprintf(stderr, "\tcode:     %s\n", code);
		fprintf(stderr, "\tresult:   %s\n", result);
		fprintf(stderr, "\texpected: %s\n", expect);
		fprintf(stderr, "\terrno:    %i (%s)\n", errno, strerror(errno));
		exit(1);
	}
}


static void
assert_zueq_(size_t result, size_t expect, const char *code, int lineno)
{
	if (result != expect) {
		if (from_lineno)
			fprintf(stderr, "Assertion at line %i, form line %i failed:\n", lineno, from_lineno);
		else
			fprintf(stderr, "Assertion at line %i failed:\n", lineno);
		fprintf(stderr, "\tcode:     %s\n", code);
		fprintf(stderr, "\tresult:   %zu\n", result);
		fprintf(stderr, "\texpected: %zu\n", expect);
		fprintf(stderr, "\terrno:    %i (%s)\n", errno, strerror(errno));
		exit(1);
	}
}


static void
check_libar2_type_to_string(void)
{
	errno = 0;

	assert_streq(libar2_type_to_string(LIBAR2_ARGON2D, LIBAR2_LOWER_CASE), "argon2d");
	assert_streq(libar2_type_to_string(LIBAR2_ARGON2D, LIBAR2_TITLE_CASE), "Argon2d");
	assert_streq(libar2_type_to_string(LIBAR2_ARGON2D, LIBAR2_UPPER_CASE), "ARGON2D");
	assert(errno == 0);

	assert_streq(libar2_type_to_string(LIBAR2_ARGON2I, LIBAR2_LOWER_CASE), "argon2i");
	assert_streq(libar2_type_to_string(LIBAR2_ARGON2I, LIBAR2_TITLE_CASE), "Argon2i");
	assert_streq(libar2_type_to_string(LIBAR2_ARGON2I, LIBAR2_UPPER_CASE), "ARGON2I");
	assert(errno == 0);

	assert_streq(libar2_type_to_string(LIBAR2_ARGON2ID, LIBAR2_LOWER_CASE), "argon2id");
	assert_streq(libar2_type_to_string(LIBAR2_ARGON2ID, LIBAR2_TITLE_CASE), "Argon2id");
	assert_streq(libar2_type_to_string(LIBAR2_ARGON2ID, LIBAR2_UPPER_CASE), "ARGON2ID");
	assert(errno == 0);

	assert_streq(libar2_type_to_string(LIBAR2_ARGON2DS, LIBAR2_LOWER_CASE), "argon2ds");
	assert_streq(libar2_type_to_string(LIBAR2_ARGON2DS, LIBAR2_TITLE_CASE), "Argon2ds");
	assert_streq(libar2_type_to_string(LIBAR2_ARGON2DS, LIBAR2_UPPER_CASE), "ARGON2DS");
	assert(errno == 0);

	assert_streq(libar2_type_to_string(LIBAR2_ARGON2I, -1), NULL);
	assert(errno == EINVAL);
	errno = 0;
	assert_streq(libar2_type_to_string(LIBAR2_ARGON2I, 3), NULL);
	assert(errno == EINVAL);
	errno = 0;

	assert_streq(libar2_type_to_string(3, LIBAR2_LOWER_CASE), NULL);
	assert(errno == EINVAL);
	errno = 0;
	assert_streq(libar2_type_to_string(3, LIBAR2_TITLE_CASE), NULL);
	assert(errno == EINVAL);
	errno = 0;
	assert_streq(libar2_type_to_string(3, LIBAR2_UPPER_CASE), NULL);
	assert(errno == EINVAL);
	errno = 0;

	assert_streq(libar2_type_to_string(-1, LIBAR2_LOWER_CASE), NULL);
	assert(errno == EINVAL);
	errno = 0;
	assert_streq(libar2_type_to_string(-1, LIBAR2_TITLE_CASE), NULL);
	assert(errno == EINVAL);
	errno = 0;
	assert_streq(libar2_type_to_string(-1, LIBAR2_UPPER_CASE), NULL);
	assert(errno == EINVAL);
	errno = 0;

	assert_streq(libar2_type_to_string(5, LIBAR2_LOWER_CASE), NULL);
	assert(errno == EINVAL);
	errno = 0;
	assert_streq(libar2_type_to_string(5, LIBAR2_TITLE_CASE), NULL);
	assert(errno == EINVAL);
	errno = 0;
	assert_streq(libar2_type_to_string(5, LIBAR2_UPPER_CASE), NULL);
	assert(errno == EINVAL);
	errno = 0;
}


static void
check_libar2_string_to_type(void)
{
	enum libar2_argon2_type type;

	errno = 0;

	assert(!libar2_string_to_type("argon2i", &type) && type == LIBAR2_ARGON2I);
	assert(!libar2_string_to_type("Argon2i", &type) && type == LIBAR2_ARGON2I);
	assert(!libar2_string_to_type("ARgon2i", &type) && type == LIBAR2_ARGON2I);
	assert(!libar2_string_to_type("ARGon2i", &type) && type == LIBAR2_ARGON2I);
	assert(!libar2_string_to_type("ARGOn2i", &type) && type == LIBAR2_ARGON2I);
	assert(!libar2_string_to_type("ARGON2i", &type) && type == LIBAR2_ARGON2I);
	assert(!libar2_string_to_type("ARGON2I", &type) && type == LIBAR2_ARGON2I);
	assert(!libar2_string_to_type("aRGON2I", &type) && type == LIBAR2_ARGON2I);
	assert(!libar2_string_to_type("arGON2I", &type) && type == LIBAR2_ARGON2I);
	assert(!libar2_string_to_type("argON2I", &type) && type == LIBAR2_ARGON2I);
	assert(!libar2_string_to_type("argoN2I", &type) && type == LIBAR2_ARGON2I);
	assert(!libar2_string_to_type("argon2I", &type) && type == LIBAR2_ARGON2I);
	assert(!libar2_string_to_type("argon2i$x", &type) && type == LIBAR2_ARGON2I);
	assert(errno == 0);

	assert(!libar2_string_to_type("argon2d", &type) && type == LIBAR2_ARGON2D);
	assert(!libar2_string_to_type("Argon2d", &type) && type == LIBAR2_ARGON2D);
	assert(!libar2_string_to_type("ARgon2d", &type) && type == LIBAR2_ARGON2D);
	assert(!libar2_string_to_type("ARGon2d", &type) && type == LIBAR2_ARGON2D);
	assert(!libar2_string_to_type("ARGOn2d", &type) && type == LIBAR2_ARGON2D);
	assert(!libar2_string_to_type("ARGON2d", &type) && type == LIBAR2_ARGON2D);
	assert(!libar2_string_to_type("ARGON2D", &type) && type == LIBAR2_ARGON2D);
	assert(!libar2_string_to_type("aRGON2D", &type) && type == LIBAR2_ARGON2D);
	assert(!libar2_string_to_type("arGON2D", &type) && type == LIBAR2_ARGON2D);
	assert(!libar2_string_to_type("argON2D", &type) && type == LIBAR2_ARGON2D);
	assert(!libar2_string_to_type("argoN2D", &type) && type == LIBAR2_ARGON2D);
	assert(!libar2_string_to_type("argon2D", &type) && type == LIBAR2_ARGON2D);
	assert(!libar2_string_to_type("argon2d$x", &type) && type == LIBAR2_ARGON2D);
	assert(errno == 0);

	assert(!libar2_string_to_type("argon2id", &type) && type == LIBAR2_ARGON2ID);
	assert(!libar2_string_to_type("Argon2id", &type) && type == LIBAR2_ARGON2ID);
	assert(!libar2_string_to_type("ARgon2id", &type) && type == LIBAR2_ARGON2ID);
	assert(!libar2_string_to_type("ARGon2id", &type) && type == LIBAR2_ARGON2ID);
	assert(!libar2_string_to_type("ARGOn2id", &type) && type == LIBAR2_ARGON2ID);
	assert(!libar2_string_to_type("ARGON2id", &type) && type == LIBAR2_ARGON2ID);
	assert(!libar2_string_to_type("ARGON2Id", &type) && type == LIBAR2_ARGON2ID);
	assert(!libar2_string_to_type("ARGON2ID", &type) && type == LIBAR2_ARGON2ID);
	assert(!libar2_string_to_type("aRGON2ID", &type) && type == LIBAR2_ARGON2ID);
	assert(!libar2_string_to_type("arGON2ID", &type) && type == LIBAR2_ARGON2ID);
	assert(!libar2_string_to_type("argON2ID", &type) && type == LIBAR2_ARGON2ID);
	assert(!libar2_string_to_type("argoN2ID", &type) && type == LIBAR2_ARGON2ID);
	assert(!libar2_string_to_type("argon2ID", &type) && type == LIBAR2_ARGON2ID);
	assert(!libar2_string_to_type("argon2id$x", &type) && type == LIBAR2_ARGON2ID);
	assert(errno == 0);

	assert(!libar2_string_to_type("argon2ds", &type) && type == LIBAR2_ARGON2DS);
	assert(!libar2_string_to_type("Argon2ds", &type) && type == LIBAR2_ARGON2DS);
	assert(!libar2_string_to_type("ARgon2ds", &type) && type == LIBAR2_ARGON2DS);
	assert(!libar2_string_to_type("ARGon2ds", &type) && type == LIBAR2_ARGON2DS);
	assert(!libar2_string_to_type("ARGOn2ds", &type) && type == LIBAR2_ARGON2DS);
	assert(!libar2_string_to_type("ARGON2ds", &type) && type == LIBAR2_ARGON2DS);
	assert(!libar2_string_to_type("ARGON2Ds", &type) && type == LIBAR2_ARGON2DS);
	assert(!libar2_string_to_type("ARGON2DS", &type) && type == LIBAR2_ARGON2DS);
	assert(!libar2_string_to_type("aRGON2DS", &type) && type == LIBAR2_ARGON2DS);
	assert(!libar2_string_to_type("arGON2DS", &type) && type == LIBAR2_ARGON2DS);
	assert(!libar2_string_to_type("argON2DS", &type) && type == LIBAR2_ARGON2DS);
	assert(!libar2_string_to_type("argoN2DS", &type) && type == LIBAR2_ARGON2DS);
	assert(!libar2_string_to_type("argon2DS", &type) && type == LIBAR2_ARGON2DS);
	assert(!libar2_string_to_type("argon2ds$x", &type) && type == LIBAR2_ARGON2DS);
	assert(errno == 0);

	assert(libar2_string_to_type("argon2", &type) == -1);
	assert(errno == EINVAL);
	errno = 0;
	assert(libar2_string_to_type("argon2x", &type) == -1);
	assert(errno == EINVAL);
	errno = 0;
	assert(libar2_string_to_type("ARGON2", &type) == -1);
	assert(errno == EINVAL);
	errno = 0;
}


static void
check_libar2_version_to_string(void)
{
	errno = 0;

	assert_streq(libar2_version_to_string(LIBAR2_ARGON2_VERSION_10), "10");
	assert(errno == 0);

	assert_streq(libar2_version_to_string(LIBAR2_ARGON2_VERSION_13), "13");
	assert(errno == 0);

	assert_streq(libar2_version_to_string(0x10), "10");
	assert(errno == 0);

	assert_streq(libar2_version_to_string(0x13), "13");
	assert(errno == 0);

	assert_streq(libar2_version_to_string(0x11), NULL);
	assert(errno == EINVAL);
	errno = 0;

	assert_streq(libar2_version_to_string(0x12), NULL);
	assert(errno == EINVAL);
	errno = 0;

	assert_streq(libar2_version_to_string(0), NULL);
	assert(errno == EINVAL);
	errno = 0;
}


static void
check_libar2_version_to_string_proper(void)
{
	errno = 0;

	assert_streq(libar2_version_to_string_proper(LIBAR2_ARGON2_VERSION_10), "1.0");
	assert(errno == 0);

	assert_streq(libar2_version_to_string_proper(LIBAR2_ARGON2_VERSION_13), "1.3");
	assert(errno == 0);

	assert_streq(libar2_version_to_string_proper(0x10), "1.0");
	assert(errno == 0);

	assert_streq(libar2_version_to_string_proper(0x13), "1.3");
	assert(errno == 0);

	assert_streq(libar2_version_to_string_proper(0x11), NULL);
	assert(errno == EINVAL);
	errno = 0;

	assert_streq(libar2_version_to_string_proper(0x12), NULL);
	assert(errno == EINVAL);
	errno = 0;

	assert_streq(libar2_version_to_string_proper(0), NULL);
	assert(errno == EINVAL);
	errno = 0;
}


static void
check_libar2_string_to_version(void)
{
	enum libar2_argon2_version version;

	errno = 0;

	assert(!libar2_string_to_version("10", &version) && version == LIBAR2_ARGON2_VERSION_10);
	assert(errno == 0);

	assert(!libar2_string_to_version("13", &version) && version == LIBAR2_ARGON2_VERSION_13);
	assert(errno == 0);

	assert(!libar2_string_to_version("1.0", &version) && version == LIBAR2_ARGON2_VERSION_10);
	assert(errno == 0);

	assert(!libar2_string_to_version("1.3", &version) && version == LIBAR2_ARGON2_VERSION_13);
	assert(errno == 0);

	assert(libar2_string_to_version("11", &version) == -1);
	assert(errno == EINVAL);
	errno = 0;

	assert(libar2_string_to_version("12", &version) == -1);
	assert(errno == EINVAL);
	errno = 0;

	assert(libar2_string_to_version("1.1", &version) == -1);
	assert(errno == EINVAL);
	errno = 0;

	assert(libar2_string_to_version("1.2", &version) == -1);
	assert(errno == EINVAL);
	errno = 0;

	assert(libar2_string_to_version("16", &version) == -1);
	assert(errno == EINVAL);
	errno = 0;

	assert(libar2_string_to_version("19", &version) == -1);
	assert(errno == EINVAL);
	errno = 0;
}


static void
check_libar2_encode_base64(void)
{
	char buf[128];

	errno = 0;

	assert(libar2_encode_base64(NULL, MEM("")) == 1);
	assert(libar2_encode_base64(NULL, MEM("1")) == 3);
	assert(libar2_encode_base64(NULL, MEM("12")) == 4);
	assert(libar2_encode_base64(NULL, MEM("123")) == 5);
	assert(libar2_encode_base64(NULL, MEM("1234")) == 7);
	assert(libar2_encode_base64(NULL, MEM("12345")) == 8);
	assert(errno == 0);

	assert(libar2_encode_base64(buf, MEM("")) == 1);
	assert_streq(buf, "");
	assert(errno == 0);

	assert(libar2_encode_base64(buf, MEM("\x00")) == 3);
	assert_streq(buf, "AA");
	assert(errno == 0);

	assert(libar2_encode_base64(buf, MEM("\x00\x00")) == 4);
	assert_streq(buf, "AAA");
	assert(errno == 0);

	assert(libar2_encode_base64(buf, MEM("\x00\x00\x00")) == 5);
	assert_streq(buf, "AAAA");
	assert(errno == 0);

	assert(libar2_encode_base64(buf, MEM("12345678")) == 12);
	assert_streq(buf, "MTIzNDU2Nzg");
	assert(errno == 0);

	assert(libar2_encode_base64(buf, MEM("testtest")) == 12);
	assert_streq(buf, "dGVzdHRlc3Q");
	assert(errno == 0);

	assert(libar2_encode_base64(buf, MEM("zy[]y21 !")) == 13);
	assert_streq(buf, "enlbXXkyMSAh");
	assert(errno == 0);

	assert(libar2_encode_base64(buf, MEM("{~|~}~~~\x7f\x7f")) == 15);
	assert_streq(buf, "e358fn1+fn5/fw");
	assert(errno == 0);
}


static void
check_libar2_decode_base64(void)
{
	char buf[128];
	size_t len;

	errno = 0;

	assert(libar2_decode_base64("", buf, &len) == 0);
	assert(len == 0);
	assert(errno == 0);

	assert(libar2_decode_base64("A", buf, &len) == 0);
	assert(len == 0);
	assert(errno == 0);

#define CHECK(S) len == sizeof(S) - 1 && !memcmp(buf, S, len)

	assert(libar2_decode_base64("AA", buf, &len) == 2);
	assert(CHECK("\x00"));
	assert(errno == 0);

	assert(libar2_decode_base64("AAA", buf, &len) == 3);
	assert(CHECK("\x00\x00"));
	assert(errno == 0);

	assert(libar2_decode_base64("AAAA", buf, &len) == 4);
	assert(CHECK("\x00\x00\x00"));
	assert(errno == 0);

	assert(libar2_decode_base64("AAAAA", buf, &len) == 4);
	assert(CHECK("\x00\x00\x00"));
	assert(errno == 0);

	assert(libar2_decode_base64("AAAAAA", buf, &len) == 6);
	assert(CHECK("\x00\x00\x00\x00"));
	assert(errno == 0);

	assert(libar2_decode_base64("MTIzNDU2Nzg", buf, &len) == 11);
	assert(CHECK("12345678"));
	assert(errno == 0);

	assert(libar2_decode_base64("dGVzdHRlc3Q", buf, &len) == 11);
	assert(CHECK("testtest"));
	assert(errno == 0);

	assert(libar2_decode_base64("enlbXXkyMSAh", buf, &len) == 12);
	assert(CHECK("zy[]y21 !"));
	assert(errno == 0);

	assert(libar2_decode_base64("e358fn1+fn5/fw", buf, &len) == 14);
	assert(CHECK("{~|~}~~~\x7f\x7f"));
	assert(errno == 0);

#undef CHECK
}


static void
check_libar2_encode_params_libar2_decode_params(void)
{
	struct libar2_argon2_parameters params;
	char *sbuf = NULL;
	char pbuf[256];

#define DECODE(PARAMS, HASH)\
	libar2_decode_params(PARAMS""HASH, &params, &sbuf, &ctx_st)

#define PARAMSTR "$argon2i$v=19$m=4096,t=3,p=1$fn5/f35+f38$"
	memset(&params, 0xFF, sizeof(params));
	assert_zueq(DECODE(PARAMSTR, "1234"), sizeof(PARAMSTR) - 1);
	assert(params.type == LIBAR2_ARGON2I);
	assert(params.version == LIBAR2_ARGON2_VERSION_13);
	assert(params.t_cost == 3);
	assert(params.m_cost == 4096);
	assert(params.lanes == 1);
	assert(params.salt != NULL);
	assert(params.saltlen == 8);
	assert(!memcmp(params.salt, "~~\x7f\x7f~~\x7f\x7f", params.saltlen));
	assert(!params.key);
	assert(!params.keylen);
	assert(!params.ad);
	assert(!params.adlen);
	assert(params.hashlen == 3);
	assert_zueq(libar2_encode_params(NULL, &params), sizeof(PARAMSTR));
	assert_zueq(libar2_encode_params(pbuf, &params), sizeof(PARAMSTR));
	assert_streq(pbuf, PARAMSTR);
	assert(sbuf != NULL);
	ctx_st.deallocate(sbuf, &ctx_st);
	sbuf = NULL;
#undef PARAMSTR

#undef DECODE
}


static void
check_libar2_validate_params(void)
{
	struct libar2_argon2_parameters params;
	const char *errmsg = NULL;

	errno = 0;

	memset(&params, 0, sizeof(params));
	params.type = LIBAR2_ARGON2I;
	params.version = LIBAR2_ARGON2_VERSION_13;
	params.t_cost = 3;
	params.m_cost = 4096;
	params.lanes = 1;
	params.saltlen = 8;
	params.hashlen = 4;
	assert(libar2_validate_params(&params, &errmsg) == LIBAR2_OK);
	assert_streq(errmsg, "OK");
	assert(errno == 0);
	errmsg = NULL;
	assert(libar2_validate_params(&params, &errmsg) == 0);
	assert_streq(errmsg, "OK");
	assert(errno == 0);
	errmsg = NULL;
	assert(libar2_validate_params(&params, NULL) == 0);
	assert(errno == 0);

	params.version = LIBAR2_ARGON2_VERSION_10;
	assert(libar2_validate_params(&params, NULL) == 0);
	assert(errno == 0);
	params.type = LIBAR2_ARGON2I;
	assert(libar2_validate_params(&params, NULL) == 0);
	assert(errno == 0);
	params.type = LIBAR2_ARGON2D;
	assert(libar2_validate_params(&params, NULL) == 0);
	assert(errno == 0);
	params.type = LIBAR2_ARGON2DS;
	assert(libar2_validate_params(&params, NULL) == 0);
	assert(errno == 0);

	params.hashlen = 3;
	assert(libar2_validate_params(&params, &errmsg) == LIBAR2_HASH_TOO_SMALL);
	assert_streq(errmsg, "tag length parameter is too small");
	assert(errno == 0);
	errmsg = NULL;
	assert(libar2_validate_params(&params, NULL) == LIBAR2_HASH_TOO_SMALL);
	assert(errno == 0);
	params.hashlen = 4;

	params.saltlen = 7;
	assert(libar2_validate_params(&params, &errmsg) == LIBAR2_SALT_TOO_SMALL);
	assert_streq(errmsg, "salt parameter is too small");
	assert(errno == 0);
	errmsg = NULL;
	assert(libar2_validate_params(&params, NULL) == LIBAR2_SALT_TOO_SMALL);
	assert(errno == 0);
	params.saltlen = 8;

	params.t_cost = 0;
	assert(libar2_validate_params(&params, &errmsg) == LIBAR2_T_COST_TOO_SMALL);
	assert_streq(errmsg, "time-cost parameter is too small");
	assert(errno == 0);
	errmsg = NULL;
	assert(libar2_validate_params(&params, NULL) == LIBAR2_T_COST_TOO_SMALL);
	assert(errno == 0);
	params.t_cost = 1;

	params.m_cost = 7;
	assert(libar2_validate_params(&params, &errmsg) == LIBAR2_M_COST_TOO_SMALL);
	assert_streq(errmsg, "memory-cost parameter is too small");
	assert(errno == 0);
	errmsg = NULL;
	assert(libar2_validate_params(&params, NULL) == LIBAR2_M_COST_TOO_SMALL);
	assert(errno == 0);
	params.m_cost = 8;

	params.lanes = 0;
	assert(libar2_validate_params(&params, &errmsg) == LIBAR2_TOO_FEW_LANES);
	assert_streq(errmsg, "lane-count parameter is too small");
	assert(errno == 0);
	errmsg = NULL;
	assert(libar2_validate_params(&params, NULL) == LIBAR2_TOO_FEW_LANES);
	assert(errno == 0);
	params.lanes = 1;

	params.lanes = 0x1000000UL;
	assert(libar2_validate_params(&params, &errmsg) == LIBAR2_TOO_MANY_LANES);
	assert_streq(errmsg, "lane-count parameter is too large");
	assert(errno == 0);
	errmsg = NULL;
	assert(libar2_validate_params(&params, NULL) == LIBAR2_TOO_MANY_LANES);
	assert(errno == 0);
	params.lanes = 1;

	params.type = -1;
	assert(libar2_validate_params(&params, &errmsg) == LIBAR2_INVALID_TYPE);
	assert_streq(errmsg, "type parameter is invalid");
	assert(errno == 0);
	errmsg = NULL;
	assert(libar2_validate_params(&params, NULL) == LIBAR2_INVALID_TYPE);
	assert(errno == 0);
	params.type = 0;

	params.type = 3;
	assert(libar2_validate_params(&params, &errmsg) == LIBAR2_INVALID_TYPE);
	assert_streq(errmsg, "type parameter is invalid");
	assert(errno == 0);
	errmsg = NULL;
	assert(libar2_validate_params(&params, NULL) == LIBAR2_INVALID_TYPE);
	assert(errno == 0);
	params.type = 0;

	params.type = 5;
	assert(libar2_validate_params(&params, &errmsg) == LIBAR2_INVALID_TYPE);
	assert_streq(errmsg, "type parameter is invalid");
	assert(errno == 0);
	errmsg = NULL;
	assert(libar2_validate_params(&params, NULL) == LIBAR2_INVALID_TYPE);
	assert(errno == 0);
	params.type = 0;

	params.version = 0x11;
	assert(libar2_validate_params(&params, &errmsg) == LIBAR2_INVALID_VERSION);
	assert_streq(errmsg, "version parameter is invalid");
	assert(errno == 0);
	errmsg = NULL;
	assert(libar2_validate_params(&params, NULL) == LIBAR2_INVALID_VERSION);
	assert(errno == 0);
	params.type = 0x10;
}


static void
check_hash(const char *pwd_, size_t pwdlen, const char *hash, struct libar2_context *ctx, int lineno)
{
	struct libar2_argon2_parameters params;
	char *sbuf, output[512], pwd[512], output64[700];
	size_t plen;

	from_lineno = lineno;
	errno = 0;

	stpcpy(pwd, pwd_);
	plen = libar2_decode_params(hash, &params, &sbuf, ctx);
	assert(!libar2_validate_params(&params, NULL));
	assert(!libar2_hash(output, pwd, pwdlen, &params, ctx));
	libar2_encode_base64(output64, output, params.hashlen);
	assert_streq(output64, &hash[plen]);
	assert(errno == 0);
	if (sbuf) {
		ctx->deallocate(sbuf, ctx);
	}

	from_lineno = 0;
}


static void
check_libar2_hash(void)
{
#define CHECK(PWD, HASH)\
	check_hash(MEM(PWD), HASH, &ctx_st, __LINE__);

	CHECK("\x00", "$argon2d$v=16$m=8,t=1,p=1$ICAgICAgICA$Eyx1BxGazSuPQoy7osaQuo20Dw9VI97dYUOgcC3cMgw");
	CHECK("test", "$argon2i$v=19$m=4096,t=3,p=1$fn5/f35+f38$9tqKA4WMEsSAOEUwatjxvJLSqL1j0GQkgbsfnpresDw");
	CHECK("\x00", "$argon2id$v=16$m=8,t=1,p=1$ICAgICAgICA$fXq1aUbp9yhbn+EQc4AzUUE6AKnHAkvzIXsN6J4ukvE");
	CHECK("", "$argon2d$v=16$m=8,t=1,p=1$ICAgICAgICA$X54KZYxUSfMUihzebb70sKbheabHilo8gsUldrVU4IU");
	CHECK("", "$argon2d$v=16$m=8,t=1,p=1$ICAgICAgICA$NjODMrWrS7zeivNNpHsuxD9c6uDmUQ6YqPRhb8H5DSNw9n683FUCJZ3tyxgfJpYYANI+01WT/S5zp1UVs+qNRwnkdEyLKZMg+DIOXVc9z1po9ZlZG8+Gp4g5brqfza3lvkR9vw");
	CHECK("", "$argon2ds$v=16$m=8,t=1,p=1$ICAgICAgICA$zgdykk9ZjN5VyrW0LxGw8LmrJ1Z6fqSC+3jPQtn4n0s");

	CHECK("password", "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ");
	CHECK("password", "$argon2i$m=1048576,t=2,p=1$c29tZXNhbHQ$lpDsVdKNPtMlYvLnPqYrArAYdXZDoq5ueVKEWd6BBuk");
	CHECK("password", "$argon2i$m=262144,t=2,p=1$c29tZXNhbHQ$Pmiaqj0op3zyvHKlGsUxZnYXURgvHuKS4/Z3p9pMJGc");
	CHECK("password", "$argon2i$m=256,t=2,p=1$c29tZXNhbHQ$/U3YPXYsSb3q9XxHvc0MLxur+GP960kN9j7emXX8zwY");
	CHECK("password", "$argon2i$m=256,t=2,p=2$c29tZXNhbHQ$tsEVYKap1h6scGt5ovl9aLRGOqOth+AMB+KwHpDFZPs");
	CHECK("password", "$argon2i$m=65536,t=1,p=1$c29tZXNhbHQ$gWMFUrjzsfSM2xmSxMZ4ZD1JCytetP9sSzQ4tWIXJLI");
	CHECK("password", "$argon2i$m=65536,t=4,p=1$c29tZXNhbHQ$8hLwFhXm6110c03D70Ct4tUdBSRo2MaUQKOh8sHChHs");
	CHECK("differentpassword", "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ$6ckCB0tnVFMaOgvlGeW69ASzDOabPwGsO/ISKZYBCaM");
	CHECK("password", "$argon2i$m=65536,t=2,p=1$ZGlmZnNhbHQ$eaEDuQ/orvhXDLMfyLIiWXeJFvgza3vaw4kladTxxJc");

	CHECK("password", "$argon2i$v=19$m=1048576,t=2,p=1$c29tZXNhbHQ$0Vh6ygkiw7XWqD7asxvuPE667zQu1hJ6VdGbI1GtH0E");
	CHECK("password", "$argon2i$v=19$m=262144,t=2,p=1$c29tZXNhbHQ$KW266AuAfNzqrUSudBtQbxTbCVkmexg7EY+bJCKbx8s");
	CHECK("password", "$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8");
	CHECK("password", "$argon2i$v=19$m=256,t=2,p=2$c29tZXNhbHQ$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E");
	CHECK("password", "$argon2i$v=19$m=65536,t=1,p=1$c29tZXNhbHQ$0WgHXE2YXhPr6uVgz4uUw7XYoWxRkWtvSsLaOsEbvs8");
	CHECK("password", "$argon2i$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$qqlT1YrzcGzj3xrv1KZKhOMdf1QXUjHxKFJZ+IF0zls");
	CHECK("differentpassword", "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$FK6NoBr+qHAMI1jc73xTWNkCEoK9iGY6RWL1n7dNIu4");
	CHECK("password", "$argon2i$v=19$m=65536,t=2,p=1$ZGlmZnNhbHQ$sDV8zPvvkfOGCw26RHsjSMvv7K2vmQq/6cxAcmxSEnE");

	CHECK("password", "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc");
	CHECK("password", "$argon2id$v=19$m=262144,t=2,p=1$c29tZXNhbHQ$eP4eyR+zqlZX1y5xCFTkw9m5GYx0L5YWwvCFvtlbLow");
	CHECK("password", "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4");
	CHECK("password", "$argon2id$v=19$m=256,t=2,p=2$c29tZXNhbHQ$bQk8UB/VmZZF4Oo79iDXuL5/0ttZwg2f/5U52iv1cDc");
	CHECK("password", "$argon2id$v=19$m=65536,t=1,p=1$c29tZXNhbHQ$9qWtwbpyPd3vm1rB1GThgPzZ3/ydHL92zKL+15XZypg");
	CHECK("password", "$argon2id$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$kCXUjmjvc5XMqQedpMTsOv+zyJEf5PhtGiUghW9jFyw");
	CHECK("differentpassword", "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$C4TWUs9rDEvq7w3+J4umqA32aWKB1+DSiRuBfYxFj94");
	CHECK("password", "$argon2id$v=19$m=65536,t=2,p=1$ZGlmZnNhbHQ$vfMrBczELrFdWP0ZsfhWsRPaHppYdP3MVEMIVlqoFBw");

#undef CHECK
}


int
main(void)
{
	check_libar2_type_to_string();
	check_libar2_string_to_type();
	check_libar2_version_to_string();
	check_libar2_version_to_string_proper();
	check_libar2_string_to_version();
	check_libar2_encode_base64();
	check_libar2_decode_base64();
	check_libar2_encode_params_libar2_decode_params();
	check_libar2_validate_params();
	check_libar2_hash();
}
