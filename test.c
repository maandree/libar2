/* See LICENSE file for copyright and license details. */
#include "common.h"

#ifndef MEASURE_TIME
# define MEASURE_TIME 0
#endif
#ifndef MEASURE_TIME_ONLY
# define MEASURE_TIME_ONLY MEASURE_TIME
#endif

#include <stdlib.h>
#if MEASURE_TIME
# include <stdio.h>
# include <time.h>
#endif


#define MEM(S) S, sizeof(S) - 1


#define assert(TRUTH) assert_(TRUTH, #TRUTH, __LINE__)
#define assert_streq(RESULT, EXPECT) assert_streq_(RESULT, EXPECT, #RESULT, __LINE__)
#define assert_zueq(RESULT, EXPECT) assert_zueq_(RESULT, EXPECT, #RESULT, __LINE__)

static int from_lineno = 0;


#if defined(__clang__)
# pragma clang diagnostic push
# pragma clang diagnostic ignored "-Wpadded"
#endif

struct context_user_data {
	size_t allocate_fail_in;
	int init_thread_pool_error;
	int get_ready_threads_error;
	int run_thread_error;
	int join_thread_pool_error;
	int destroy_thread_pool_error;
};

#if defined(__clang__)
# pragma clang diagnostic pop
#endif


static void *
allocate(size_t num, size_t size, size_t alignment, struct libar2_context *ctx)
{
#ifndef _POSIX_C_SOURCE
# define _POSIX_C_SOURCE 0
#endif
#ifndef _ISOC11_SOURCE
# ifdef __STDC_VERSION__
#  if __STDC_VERSION__ >= 201112L
#   define _ISOC11_SOURCE
#  endif
# endif
#endif
	void *ptr;
	uintptr_t req_alignment = (uintptr_t)alignment;
	if (ctx->user_data) {
		struct context_user_data *user_data = ctx->user_data;
		if (user_data->allocate_fail_in) {
			if (!--user_data->allocate_fail_in) {
				errno = ENOMEM;
				return NULL;
			}
		}
	}
	if (num > SIZE_MAX / size) {
		/* $covered{$ */
		errno = ENOMEM;
	fail:
		fprintf(stderr, "Internal test failure: %s\n", strerror(errno));
		exit(2);
		/* $covered}$ */
	}
	if (alignment < sizeof(void *))
		alignment = sizeof(void *);
#if _POSIX_C_SOURCE >= 200112L
	errno = posix_memalign(&ptr, alignment, num * size);
	if (errno)
		goto fail; /* $covered$ */
#elif defined(_ISOC11_SOURCE)
	size *= num;
	/* $covered{$ */
	if (size % alignment) {
		if (size > SIZE_MAX - (alignment - size % alignment)) {
			errno = ENOMEM;
			goto fail;
		}
		size += alignment - size % alignment;
	}
	/* $covered}$ */
	ptr = aligned_alloc(alignment, size);
	if (!ptr)
		goto fail; /* $covered$ */
#else
# error No implementation for aligned memory allocation available
#endif
	if ((uintptr_t)ptr % req_alignment) {
		/* $covered{$ */
		fprintf(stderr, "Internal test failure: memory not properly aligned\n");
		exit(2);
		/* $covered}$ */
	}
	return ptr;
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
	if (ctx->user_data) {
		struct context_user_data *user_data = ctx->user_data;
		if (user_data->init_thread_pool_error) {
			errno = user_data->init_thread_pool_error;
			return -1;
		}
	}
	*createdp = 0;
	return 0;
}

static int
pt_init_thread_pool(size_t desired, size_t *createdp, struct libar2_context *ctx)
{
	(void) ctx;
	*createdp = desired;
	return 0;
}

static size_t
pt_get_ready_threads(size_t *indices, size_t n, struct libar2_context *ctx)
{
	(void) n;
	if (ctx->user_data) {
		struct context_user_data *user_data = ctx->user_data;
		if (user_data->get_ready_threads_error) {
			errno = user_data->get_ready_threads_error;
			return 0;
		}
	}
	indices[0] = 0;
	return 1;
}

static int
pt_run_thread(size_t index, void (*function)(void *data), void *data, struct libar2_context *ctx)
{
	(void) index;
	if (ctx->user_data) {
		struct context_user_data *user_data = ctx->user_data;
		if (user_data->run_thread_error) {
			errno = user_data->run_thread_error;
			return -1;
		}
	}
	function(data);
	return 0;
}

static int
pt_join_thread_pool(struct libar2_context *ctx)
{
	if (ctx->user_data) {
		struct context_user_data *user_data = ctx->user_data;
		if (user_data->join_thread_pool_error) {
			errno = user_data->join_thread_pool_error;
			return -1;
		}
	}
	return 0;
}

static int
pt_destroy_thread_pool(struct libar2_context *ctx)
{
	if (ctx->user_data) {
		struct context_user_data *user_data = ctx->user_data;
		if (user_data->destroy_thread_pool_error) {
			errno = user_data->destroy_thread_pool_error;
			return -1;
		}
	}
	return 0;
}

static struct libar2_context ctx_st = { /* st = single threaded */
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

static struct libar2_context ctx_pt = { /* pt = phony threading */
	.user_data = NULL,
	.autoerase_message = 1,
	.autoerase_secret = 1,
	.autoerase_salt = 1,
	.autoerase_associated_data = 1,
	.allocate = allocate,
	.deallocate = deallocate,
	.init_thread_pool = pt_init_thread_pool,
	.get_ready_threads = pt_get_ready_threads,
	.run_thread = pt_run_thread,
	.join_thread_pool = pt_join_thread_pool,
	.destroy_thread_pool = pt_destroy_thread_pool
};


static int
nulstrcmp(const char *a, const char *b)
{
	return !a ? -!!b : !b ? +1 : strcmp(a, b);
}


/* $covered{$ */

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
			fprintf(stderr, "Assertion at line %i, from line %i failed:\n", lineno, from_lineno);
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
			fprintf(stderr, "Assertion at line %i, from line %i failed:\n", lineno, from_lineno);
		else
			fprintf(stderr, "Assertion at line %i failed:\n", lineno);
		fprintf(stderr, "\tcode:     %s\n", code);
		fprintf(stderr, "\tresult:   %zu\n", result);
		fprintf(stderr, "\texpected: %zu\n", expect);
		fprintf(stderr, "\terrno:    %i (%s)\n", errno, strerror(errno));
		exit(1);
	}
}

/* $covered}$ */


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

	assert_streq(libar2_type_to_string(LIBAR2_ARGON2I, (enum libar2_casing)-1), NULL);
	assert(errno == EINVAL);
	errno = 0;
	assert_streq(libar2_type_to_string(LIBAR2_ARGON2I, (enum libar2_casing)3), NULL);
	assert(errno == EINVAL);
	errno = 0;

	assert_streq(libar2_type_to_string((enum libar2_argon2_type)3, LIBAR2_LOWER_CASE), NULL);
	assert(errno == EINVAL);
	errno = 0;
	assert_streq(libar2_type_to_string((enum libar2_argon2_type)3, LIBAR2_TITLE_CASE), NULL);
	assert(errno == EINVAL);
	errno = 0;
	assert_streq(libar2_type_to_string((enum libar2_argon2_type)3, LIBAR2_UPPER_CASE), NULL);
	assert(errno == EINVAL);
	errno = 0;

	assert_streq(libar2_type_to_string((enum libar2_argon2_type)-1, LIBAR2_LOWER_CASE), NULL);
	assert(errno == EINVAL);
	errno = 0;
	assert_streq(libar2_type_to_string((enum libar2_argon2_type)-1, LIBAR2_TITLE_CASE), NULL);
	assert(errno == EINVAL);
	errno = 0;
	assert_streq(libar2_type_to_string((enum libar2_argon2_type)-1, LIBAR2_UPPER_CASE), NULL);
	assert(errno == EINVAL);
	errno = 0;

	assert_streq(libar2_type_to_string((enum libar2_argon2_type)5, LIBAR2_LOWER_CASE), NULL);
	assert(errno == EINVAL);
	errno = 0;
	assert_streq(libar2_type_to_string((enum libar2_argon2_type)5, LIBAR2_TITLE_CASE), NULL);
	assert(errno == EINVAL);
	errno = 0;
	assert_streq(libar2_type_to_string((enum libar2_argon2_type)5, LIBAR2_UPPER_CASE), NULL);
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

	assert_streq(libar2_version_to_string((enum libar2_argon2_version)0x11), NULL);
	assert(errno == EINVAL);
	errno = 0;

	assert_streq(libar2_version_to_string((enum libar2_argon2_version)0x12), NULL);
	assert(errno == EINVAL);
	errno = 0;

	assert_streq(libar2_version_to_string((enum libar2_argon2_version)0), NULL);
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

	assert_streq(libar2_version_to_string_proper((enum libar2_argon2_version)0x11), NULL);
	assert(errno == EINVAL);
	errno = 0;

	assert_streq(libar2_version_to_string_proper((enum libar2_argon2_version)0x12), NULL);
	assert(errno == EINVAL);
	errno = 0;

	assert_streq(libar2_version_to_string_proper((enum libar2_argon2_version)0), NULL);
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

#define PARAMSTR "$argon2i$v=16$m=4096,t=3,p=1$fn5/f35+f38$"
	memset(&params, 0xFF, sizeof(params));
	assert_zueq(DECODE(PARAMSTR, "1234"), sizeof(PARAMSTR) - 1);
	assert(params.type == LIBAR2_ARGON2I);
	assert(params.version == LIBAR2_ARGON2_VERSION_10);
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

#define PARAMSTR "$argon2i$m=4096,t=3,p=1$fn5/f35+f38$"
	memset(&params, 0xFF, sizeof(params));
	assert_zueq(DECODE(PARAMSTR, "1234"), sizeof(PARAMSTR) - 1);
	assert(params.type == LIBAR2_ARGON2I);
	assert(params.version == 0);
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

	params.type = (enum libar2_argon2_type)-1;
	assert(libar2_validate_params(&params, &errmsg) == LIBAR2_INVALID_TYPE);
	assert_streq(errmsg, "type parameter is invalid");
	assert(errno == 0);
	errmsg = NULL;
	assert(libar2_validate_params(&params, NULL) == LIBAR2_INVALID_TYPE);
	assert(errno == 0);
	params.type = 0;

	params.type = (enum libar2_argon2_type)3;
	assert(libar2_validate_params(&params, &errmsg) == LIBAR2_INVALID_TYPE);
	assert_streq(errmsg, "type parameter is invalid");
	assert(errno == 0);
	errmsg = NULL;
	assert(libar2_validate_params(&params, NULL) == LIBAR2_INVALID_TYPE);
	assert(errno == 0);
	params.type = 0;

	params.type = (enum libar2_argon2_type)5;
	assert(libar2_validate_params(&params, &errmsg) == LIBAR2_INVALID_TYPE);
	assert_streq(errmsg, "type parameter is invalid");
	assert(errno == 0);
	errmsg = NULL;
	assert(libar2_validate_params(&params, NULL) == LIBAR2_INVALID_TYPE);
	assert(errno == 0);
	params.type = 0;

	params.version = (enum libar2_argon2_version)0x11;
	assert(libar2_validate_params(&params, &errmsg) == LIBAR2_INVALID_VERSION);
	assert_streq(errmsg, "version parameter is invalid");
	assert(errno == 0);
	errmsg = NULL;
	assert(libar2_validate_params(&params, NULL) == LIBAR2_INVALID_VERSION);
	assert(errno == 0);
	params.version = 0x10;
}


static void
check_hash(const char *pwd_, size_t pwdlen, const char *hash,
           void *key, size_t keylen, void *ad, size_t adlen,
           struct libar2_context *ctx, int lineno)
{
	struct libar2_argon2_parameters params;
	char *sbuf, output[512], pwd[512], output64[700];
	size_t plen;

	from_lineno = lineno;
	errno = 0;

	memcpy(pwd, pwd_, pwdlen);
	plen = libar2_decode_params(hash, &params, &sbuf, ctx);
	params.key = key;
	params.keylen = keylen;
	params.ad = ad;
	params.adlen = adlen;
	assert(!libar2_validate_params(&params, NULL));
	assert(!libar2_hash(output, pwd, pwdlen, &params, ctx));
	libar2_encode_base64(output64, output, params.hashlen);
	assert_streq(output64, &hash[plen]);
	assert(errno == 0);
	if (sbuf)
		ctx->deallocate(sbuf, ctx);

	from_lineno = 0;
}


static int
memis(char *mem, int ch, size_t n)
{
	size_t i;
	int ok = 1;
	for (i = 0; i < n; i++)
		if (mem[i] != (char)ch)
			return 0; /* $covered$ */
	return ok;
}

/* Typo in version 1.0 */
extern void libar2_earse(volatile void *mem, size_t size);

static void
check_libar2_erase(void)
{
	char buf[1024];

	memset(buf, 1, sizeof(buf));
	libar2_earse(&buf[0], 512);
	assert(memis(&buf[512], 1, 512));
	assert(memis(&buf[0], 0, 512));

	/* libar2_erase has been replaced by this test, so we test this instead */
	memset(buf, 1, sizeof(buf));
	libar2_internal_erase__(&buf[0], 512);
	assert(memis(&buf[512], 1, 512));
	assert(memis(&buf[0], 0, 512));
}


static void
check_libar2_hash(void)
{
	char spaces[512];
	char zeroes[512];
	memset(spaces, ' ', sizeof(spaces));
	memset(zeroes, 0, sizeof(zeroes));

#define CHECK(PWD, HASH)\
	check_hash(MEM(PWD), HASH, NULL, 0, NULL, 0, &ctx_st, __LINE__)

	CHECK("\x00", "$argon2d$v=16$m=8,t=1,p=1$ICAgICAgICA$Eyx1BxGazSuPQoy7osaQuo20Dw9VI97dYUOgcC3cMgw");
	CHECK("test", "$argon2i$v=19$m=4096,t=3,p=1$fn5/f35+f38$9tqKA4WMEsSAOEUwatjxvJLSqL1j0GQkgbsfnpresDw");
	CHECK("\x00", "$argon2id$v=16$m=8,t=1,p=1$ICAgICAgICA$fXq1aUbp9yhbn+EQc4AzUUE6AKnHAkvzIXsN6J4ukvE");
	CHECK("", "$argon2d$v=16$m=8,t=1,p=1$ICAgICAgICA$X54KZYxUSfMUihzebb70sKbheabHilo8gsUldrVU4IU");
	CHECK("", "$argon2d$v=16$m=8,t=1,p=1$ICAgICAgICA$NjODMrWrS7zeivNNpHsuxD9c6uDmUQ6YqPRhb8H5DSNw9"
	          "n683FUCJZ3tyxgfJpYYANI+01WT/S5zp1UVs+qNRwnkdEyLKZMg+DIOXVc9z1po9ZlZG8+Gp4g5brqfza3lvkR9vw");
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

	CHECK("", "$argon2ds$v=16$m=8,t=1,p=2$ICAgICAgICA$+6+yBnWbuV7mLs6rKMhvi+SLbkzb5CB6Jd2pSWuC/Kw"); /* not well-known */

#undef CHECK

#define CHECK(PWD, HASH)\
	check_hash(MEM(PWD), HASH, NULL, 0, NULL, 0, &ctx_pt, __LINE__)

	CHECK("password", "$argon2i$m=256,t=2,p=2$c29tZXNhbHQ$tsEVYKap1h6scGt5ovl9aLRGOqOth+AMB+KwHpDFZPs");
	CHECK("", "$argon2ds$v=16$m=8,t=1,p=2$ICAgICAgICA$+6+yBnWbuV7mLs6rKMhvi+SLbkzb5CB6Jd2pSWuC/Kw"); /* verified above */
	CHECK("", "$argon2d$v=16$m=8,t=1,p=1$ICAgICAgICA$X54KZYxUSfMUihzebb70sKbheabHilo8gsUldrVU4IU");
	CHECK("password", "$argon2id$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$kCXUjmjvc5XMqQedpMTsOv+zyJEf5PhtGiUghW9jFyw");

#undef CHECK

#define CHECK(PWDLEN, KEYLEN, ADLEN, HASH)\
	check_hash(spaces, PWDLEN, HASH, KEYLEN ? zeroes : NULL, KEYLEN, ADLEN ? zeroes : NULL, ADLEN, &ctx_pt, __LINE__)

	/* these are calculated with reference implmentation */
	CHECK(1, 0, 0, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$MKifhakDKOM");
	CHECK(8, 0, 0, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$n6AxIe1Ch+Y");
	CHECK(16, 0, 0, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$n1jRvzIq/JI");
	CHECK(99, 0, 0, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$7f1A+np6ekI");
	CHECK(100, 0, 0, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$oQ0MP/+6pTE");
	CHECK(101, 0, 0, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$0nF5gzoood8");
	CHECK(96, 0, 0, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$JtutNzkqeVs");
	CHECK(88, 0, 0, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$uq+BEaf7YGs");
	CHECK(84, 0, 0, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$6fY3ZSyP1Yc");
	CHECK(85, 0, 0, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$EvoR6s6ZVs0");
	CHECK(83, 0, 0, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$q46jnJcAUCY");
	CHECK(1, 4, 0, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$Mhl4o3AkJuA");
	CHECK(84, 4, 0, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$+hlEcRn+F3s");
	CHECK(80, 4, 0, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$z2d6ce8UqS0");
	CHECK(80, 140, 0, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$15FAGe1KIX8");
	CHECK(80, 160, 0, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$oH3H5atuca8");
	CHECK(80, 128, 0, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$TsimqI1YC08");
	CHECK(80, 256, 0, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$mzPlVOVjVos");
	CHECK(1, 0, 16, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$HrfeSHrbdxk");
	CHECK(80, 0, 16, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$VRC9yoVQxGQ");
	CHECK(76, 0, 16, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$i8q267O+NzU");
	CHECK(76, 0, 128, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$fqP9Bhruhvs");
	CHECK(76, 0, 130, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$kZ/OfiPy33c");
	CHECK(76, 0, 160, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$XEdsiqJkQ4I");
	CHECK(80, 0, 160, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$2aPe8XbvFv0");
	CHECK(76, 0, 256, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$NlyQ7poTmcA");
	CHECK(80, 0, 128, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$W214JDf8nik");

#undef CHECK
}


#if defined(__x86_64__) && defined(LIBAR2_TARGET__) && defined(__GNUC__)
static void
run_check_libar2_hash_optimisations(void)
{

#define CHECK(PWD, HASH)\
	check_hash(MEM(PWD), HASH, NULL, 0, NULL, 0, &ctx_st, __LINE__)

	CHECK("password", "$argon2i$m=256,t=2,p=2$c29tZXNhbHQ$tsEVYKap1h6scGt5ovl9aLRGOqOth+AMB+KwHpDFZPs");
	CHECK("", "$argon2ds$v=16$m=8,t=1,p=2$ICAgICAgICA$+6+yBnWbuV7mLs6rKMhvi+SLbkzb5CB6Jd2pSWuC/Kw");
	CHECK("", "$argon2d$v=16$m=8,t=1,p=1$ICAgICAgICA$X54KZYxUSfMUihzebb70sKbheabHilo8gsUldrVU4IU");
	CHECK("password", "$argon2i$v=19$m=256,t=2,p=2$c29tZXNhbHQ$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E");

#undef CHECK
}
#endif


static void
check_libar2_hash_optimisations(void)
{
#if defined(__x86_64__) && defined(LIBAR2_TARGET__) && defined(__GNUC__)

	__builtin_cpu_init();

	libar2_internal_use_generic__();
	run_check_libar2_hash_optimisations();

	libar2_internal_use_sse2__();
	if (__builtin_cpu_supports("sse2"))
		run_check_libar2_hash_optimisations(); /* $covered$ */

	libar2_internal_use_avx2__();
	if (__builtin_cpu_supports("avx2"))
		run_check_libar2_hash_optimisations(); /* $covered$ */

	libar2_internal_use_avx512f__();
	if (__builtin_cpu_supports("avx512f"))
		run_check_libar2_hash_optimisations(); /* $covered$ */
	/* $covered{$ */
	else if (__builtin_cpu_supports("avx2"))
		libar2_internal_use_avx2__();
	else if (__builtin_cpu_supports("sse2"))
		libar2_internal_use_sse2__();
	else
		libar2_internal_use_generic__();
	/* $covered}$ */
#endif
}


#ifdef LIBAR2_WEAKLY_LINKED__

void
libar2_erase(volatile void *mem, size_t size)
{
	(void) mem;
	(void) size;
}

static void
check_libar2_hash_buf_size(void)
{
	struct libar2_argon2_parameters params;
	char pwd[512], output[2049], *doutput;
	unsigned char salt[LIBAR2_MIN_SALTLEN];
	size_t i, size, size0, size1;
	volatile char x, *avoid_code_elimination = &x;

	errno = 0;

	memset(&params, 0, sizeof(params));
	memset(salt, 0, sizeof(salt));
	params.saltlen = LIBAR2_MIN_SALTLEN;
	params.salt = salt;
	params.m_cost = LIBAR2_MIN_M_COST;
	params.t_cost = LIBAR2_MIN_T_COST;
	params.lanes = LIBAR2_MIN_LANES;
	params.type = LIBAR2_ARGON2I;

	for (params.hashlen = LIBAR2_MIN_HASHLEN; params.hashlen < sizeof(output) - 513; params.hashlen++) {
		memset(output, 0, sizeof(output));
		assert(!libar2_hash(output, pwd, 0, &params, &ctx_st));
		assert(errno == 0);
		for (size0 = sizeof(output); size0; size0--)
			if (output[size0 - 1] != 0)
				break;

		memset(output, 1, sizeof(output));
		assert(!libar2_hash(output, pwd, 0, &params, &ctx_st));
		assert(errno == 0);
		for (size1 = sizeof(output); size1; size1--)
			if (output[size1 - 1] != 1)
				break;

		size = MAX(size0, size1);
		if (libar2_hash_buf_size(&params) != size || size > params.hashlen + 63)
			fprintf(stderr, "At hashlen = %zu (expect %zu)\n", params.hashlen, size); /* $covered$ */
		assert(size <= params.hashlen + 63);
		assert_zueq(libar2_hash_buf_size(&params), size);

		size = libar2_hash_buf_size(&params);
		assert(size > 0);
		/* Using posix_memalign because free fails under valgrind (even
		 * when the code is isoleted into a trivial minimal example)
		 * when the memory has been allocated with malloc when using
		 * musl, at least if musl is not the default libc */
		assert(!posix_memalign((void *)&doutput, sizeof(void *), size));
		assert(!libar2_hash(doutput, pwd, 0, &params, &ctx_st));
		assert(errno == 0);
		for(i = 0; i < params.hashlen; i++)
			*avoid_code_elimination ^= doutput[i];
		free(doutput);
	}
}

#endif


static void
check_failures(void)
{
	struct context_user_data user_data;
	struct libar2_argon2_parameters params;
	char *buf, sbuf[3 * sizeof(unsigned int) + 512];

	params.hashlen = SIZE_MAX;
	errno = 0;
	assert(libar2_hash_buf_size(&params) == 0 && errno == EOVERFLOW);

	buf = NULL;
#define CHECKE(STR, ERR)\
	do {\
		errno = 0;\
		assert(libar2_decode_params(STR, &params, &buf, &ctx_st) == 0 && errno == (ERR));\
		assert(!buf);\
	} while (0)
#define CHECK(STR) CHECKE(STR, EINVAL)
	CHECK("");
	CHECK("x");
	CHECK("$");
	CHECK("$argon2id");
	CHECK("$argon2idX");
	CHECK("$argon2idX$");
	CHECK("$argon2id$");
	CHECK("$argon2id$$");
	CHECK("$argon2id$x");
	CHECK("$argon2id$v");
	CHECK("$argon2id$v=");
	CHECK("$argon2id$v=$");
	CHECK("$argon2id$v=x$");
	CHECKE("$argon2id$v=9999999999999999999999999999999999999999999999999999999999999999999999999$", ERANGE);
	sprintf(sbuf, "$argon2id$v=%u$", (unsigned int)INT_MAX + 1U);
	CHECKE(sbuf, ERANGE);
	CHECK("$argon2id$v=-1$");
	CHECK("$argon2id$v=16");
	CHECK("$argon2id$v=16,");
	CHECK("$argon2id$$m=128,t=128,p=128$AAAABBBBCCCC$");
	CHECK("$argon2id$v=19$m=-128,t=128,p=128$AAAABBBBCCCC$");
	CHECK("$argon2id$v=19$m=128,t=-128,p=128$AAAABBBBCCCC$");
	CHECK("$argon2id$v=19$m=128,t=128,p=-128$AAAABBBBCCCC$");
	CHECK("$argon2id$v=19$m=x,t=128,p=128$AAAABBBBCCCC$");
	CHECK("$argon2id$v=19$m=128,t=x,p=128$AAAABBBBCCCC$");
	CHECK("$argon2id$v=19$m=128,t=128,p=x$AAAABBBBCCCC$");
	CHECK("$argon2id$v=19$t=128,p=128$AAAABBBBCCCC$");
	CHECK("$argon2id$v=19$m=128,p=128$AAAABBBBCCCC$");
	CHECK("$argon2id$v=19$m=128,t=128$AAAABBBBCCCC$");
	CHECK("$argon2id$v=19$m=128,t=128,p=128,m=128$AAAABBBBCCCC$");
	CHECK("$argon2id$v=19$m=128,t=128,p=128,t=128$AAAABBBBCCCC$");
	CHECK("$argon2id$v=19$m=128,t=128,p=128,p=128$AAAABBBBCCCC$");
	CHECK("$argon2id$v=19$m=128$AAAABBBBCCCC$");
	CHECK("$argon2id$v=19$t=128$AAAABBBBCCCC$");
	CHECK("$argon2id$v=19$p=128$AAAABBBBCCCC$");
	CHECKE("$argon2id$v=19$m=999999999999999999999999999999999999999999999999999999999999,t=128,p=128$AAAABBBBCCCC$", ERANGE);
	CHECKE("$argon2id$v=19$m=128,t=999999999999999999999999999999999999999999999999999999999999,p=128$AAAABBBBCCCC$", ERANGE);
	CHECKE("$argon2id$v=19$m=128,t=128,p=999999999999999999999999999999999999999999999999999999999999$AAAABBBBCCCC$", ERANGE);
	CHECK("$argon2id$m=128;t=128;p=128$AAAABBBBCCCC$");
	CHECK("$argon2id$m=128t=128,p=128$AAAABBBBCCCC$");
	CHECK("$argon2id$v=19,m=128,t=128,p=128$AAAABBBBCCCC$");
	CHECK("$argon2id$m=128,t=128,p=128,v=19$AAAABBBBCCCC$");
	CHECK("$argon2id$m=128,t=128,p=128,$AAAABBBBCCCC$");
	CHECK("$argon2id$m=128,t=128,p=128");
	CHECK("$argon2id$m=128,t=128,,p=128");
	CHECK("$argon2id$m=128,t=128,p=128$");
	CHECK("$argon2id$m=128,t=128,p=128,");
	CHECK("$argon2id$m=128,t=128,p=128,$AAAABBBBCCCC");
	CHECK("$argon2id$m=128,t=128,p=128$AAAABBBBCCCC");
	CHECK("$argon2id$m=128,t=128,p=128$AAAAB-BBCCCC$");
	CHECK("$argon2id$m=128,t=128,p=128$AAAABBBBC$");
	CHECK("$argon2id$,m=128,t=128,p=128$AAAABBBBCCCC$");
	CHECK("$argon2id$m=128,p=128,t=128$AAAABBBBCCCC$");
	CHECK("$argon2id$t=128,m=128,p=128$AAAABBBBCCCC$");
	CHECK("$argon2id$t=128,p=128,m=128$AAAABBBBCCCC$");
	CHECK("$argon2id$p=128,m=128,t=128$AAAABBBBCCCC$");
	CHECK("$argon2id$p=128,t=128,m=128$AAAABBBBCCCC$");
	CHECK("$argon2id$m=0128,t=128,p=128$AAAABBBBCCCC$");
	CHECK("$argon2id$m=00128,t=128,p=128$AAAABBBBCCCC$");
	CHECK("$argon2id$m=128,t=0128,p=128$AAAABBBBCCCC$");
	CHECK("$argon2id$m=128,t=00128,p=128$AAAABBBBCCCC$");
	CHECK("$argon2id$m=128,t=128,p=0128$AAAABBBBCCCC$");
	CHECK("$argon2id$m=128,t=128,p=00128$AAAABBBBCCCC$");
	CHECK("$argon2id$v=0$m=128,t=128,p=128$AAAABBBBCCCC$");
	CHECK("$argon2id$v=016$m=128,t=128,p=128$AAAABBBBCCCC$");
	errno = 0;
	ctx_st.user_data = &user_data;
	user_data.allocate_fail_in = 1;
	assert(libar2_decode_params("$argon2id$m=8,t=1,p=1$AAAABBBBCCC$", &params, &buf, &ctx_st) == 0 && errno == ENOMEM);
	assert(!buf);
	ctx_st.user_data = NULL;
#undef CHECK
#undef CHECKE

	memset(&params, 0, sizeof(params));
	errno = 0;
	assert(libar2_hash(sbuf, NULL, 0, &params, &ctx_st) == -1 && errno == EINVAL);
	params.m_cost = 32;
	params.t_cost = 32;
	params.lanes = 32;
	params.salt = (unsigned char []){"\0\0\0\0\0\0\0\0"};
	params.saltlen = 8;
	params.hashlen = 32;
#if SIZE_MAX >> 31 > 1
	errno = 0;
	assert(libar2_hash(sbuf, NULL, (size_t)1 << 32, &params, &ctx_st) == -1 && errno == EINVAL);
#endif
	ctx_st.user_data = &user_data;
	ctx_pt.user_data = &user_data;
	memset(&user_data, 0, sizeof(user_data));
	errno = 0;
	user_data.allocate_fail_in = 1;
	assert(libar2_hash(sbuf, NULL, 0, &params, &ctx_st) == -1 && errno == ENOMEM);
	errno = 0;
	params.type = LIBAR2_ARGON2DS;
	user_data.allocate_fail_in = 2;
	assert(libar2_hash(sbuf, NULL, 0, &params, &ctx_st) == -1 && errno == ENOMEM);
	errno = 0;
	user_data.allocate_fail_in = 3;
	assert(libar2_hash(sbuf, NULL, 0, &params, &ctx_pt) == -1 && errno == ENOMEM);
	user_data.allocate_fail_in = 0;
	errno = 0;
	user_data.init_thread_pool_error = EDOM;
	assert(libar2_hash(sbuf, NULL, 0, &params, &ctx_st) == -1 && errno == EDOM);
	user_data.init_thread_pool_error = 0;
	errno = 0;
	user_data.get_ready_threads_error = EDOM;
	assert(libar2_hash(sbuf, NULL, 0, &params, &ctx_pt) == -1 && errno == EDOM);
	user_data.get_ready_threads_error = 0;
	errno = 0;
	user_data.run_thread_error = EDOM;
	assert(libar2_hash(sbuf, NULL, 0, &params, &ctx_pt) == -1 && errno == EDOM);
	user_data.run_thread_error = 0;
	errno = 0;
	user_data.join_thread_pool_error = EDOM;
	assert(libar2_hash(sbuf, NULL, 0, &params, &ctx_pt) == -1 && errno == EDOM);
	user_data.join_thread_pool_error = 0;
	errno = 0;
	user_data.destroy_thread_pool_error = EDOM;
	assert(libar2_hash(sbuf, NULL, 0, &params, &ctx_pt) == -1 && errno == EDOM);
	errno = 0;
	user_data.destroy_thread_pool_error = EDOM;
	params.lanes = 1;
	assert(libar2_hash(sbuf, NULL, 0, &params, &ctx_pt) == -1 && errno == EDOM);
	params.lanes = 32;
	user_data.destroy_thread_pool_error = 0;

	ctx_st.user_data = NULL;
	ctx_pt.user_data = NULL;

	errno = 0;
}


int
main(void)
{
#if !MEASURE_TIME_ONLY
	check_libar2_type_to_string();
	check_libar2_string_to_type();
	check_libar2_version_to_string();
	check_libar2_version_to_string_proper();
	check_libar2_string_to_version();
	check_libar2_encode_base64();
	check_libar2_decode_base64();
	check_libar2_encode_params_libar2_decode_params();
	check_libar2_validate_params();
	check_libar2_erase();
	check_libar2_hash();
# ifdef LIBAR2_WEAKLY_LINKED__
	check_libar2_hash_buf_size();
# endif

	check_failures();
#endif

#if MEASURE_TIME
	{
		struct libar2_argon2_parameters params;
		char output[512];
		clock_t dur;
		double ddur;
		int r;
		memset(&params, 0, sizeof(params));
		params.m_cost = 8;
		params.t_cost = 1;
		params.lanes = 1;
		params.saltlen = 8;
		params.salt = (unsigned char[]){"\0\0\0\0\0\0\0\0"};
		params.hashlen = 32;
		assert(!libar2_validate_params(&params, NULL));
		dur = clock();
		r = libar2_hash(output, NULL, 0, &params, &ctx_st);
		dur = clock() - dur;
		assert(!r);
		ddur = (double)dur;
		ddur /= CLOCKS_PER_SEC;
		ddur *= 1000;
		fprintf(stderr, "Time: %lg ms\n", ddur);
	}
#endif

#if !MEASURE_TIME_ONLY
	check_libar2_hash_optimisations();
#endif
	return 0;
}
