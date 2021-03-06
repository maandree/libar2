/* See LICENSE file for copyright and license details. */
#include "libar2.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include <libblake.h>


#ifndef UINT_LEAST32_C
# ifdef UINT32_C
#  define UINT_LEAST32_C(V) UINT32_C(V)
# else
#  define UINT_LEAST32_C(V) V##UL
# endif
#endif

#ifndef UINT_LEAST64_C
# ifdef UINT64_C
#  define UINT_LEAST64_C(V) UINT64_C(V)
# else
#  define UINT_LEAST64_C(V) V##ULL
# endif
#endif


#if defined(__GNUC__)
# define LIBAR2_WEAKLY_LINKED__ __attribute__((__weak__))
# define LIBAR2_TARGET__(TARGETS) __attribute__((__target__(TARGETS)))
# define LIBAR2_INITIALISER__ __attribute__((__constructor__))
# define LIBAR2_HIDDEN__ __attribute__((__visibility__("hidden")))
#else
# define LIBAR2_INITIALISER__
# define LIBAR2_HIDDEN__
#endif


#ifndef CACHE_LINE_SIZE
# define CACHE_LINE_SIZE 256 /* better with larger than actual than smaller than actual */
#endif


#ifndef ALIGNOF
# ifdef __STDC_VERSION__
#  if __STDC_VERSION__ >= 201112L
#   define ALIGNOF(X) _Alignof(X)
#  endif
# endif
#endif
#ifndef ALIGNOF
# ifdef __GNUC__
#   define ALIGNOF(X) __alignof__(X)
# else
#   define ALIGNOF(X) sizeof(X)
# endif
#endif


#ifndef __GNUC__
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wunused-macros"
#endif
#ifdef WARN_UNKNOWN_ENDIAN
# define WARN_UNKNOWN_ENDIAN__
#endif
#ifndef __GNUC__
# pragma GCC diagnostic pop
#endif

#define LITTLE_ENDIAN__ 1234
#define BIG_ENDIAN__ 4321
#ifndef HOST_ENDIAN
# if defined(i386) || defined(__i386__) || defined(__x86_64__)
#  define HOST_ENDIAN LITTLE_ENDIAN__
# endif
#endif
#ifdef HOST_ENDIAN
# if HOST_ENDIAN == LITTLE_ENDIAN__
#  define USING_LITTLE_ENDIAN
# elif HOST_ENDIAN == BIG_ENDIAN__
#  define USING_BIG_ENDIAN
# endif
#else
# ifdef __GNUC__
#  ifdef WARN_UNKNOWN_ENDIAN__
#   warning The host endian is unknown
#  endif
# endif
#endif


#if defined(__x86_64__) && defined(LIBAR2_TARGET__)
# define MAX_SIMD_ALIGNMENT 64
# define SIMD_ALIGNED _Alignas(MAX_SIMD_ALIGNMENT)
# if defined(__GNUC__)
#  define SIMD_ALIGNED_ATTRIBUTE __attribute__((__aligned__(MAX_SIMD_ALIGNMENT)))
# else
#  define SIMD_ALIGNED_ATTRIBUTE
# endif
#else
# define MAX_SIMD_ALIGNMENT 1
# define SIMD_ALIGNED /* use the types native alignment */
# define SIMD_ALIGNED_ATTRIBUTE /* ditto */
#endif


#define ELEMSOF(ARR) (sizeof(ARR) / sizeof(*(ARR)))

#define MAX(A, B) ((A) > (B) ? (A) : (B))
#define MIN(A, B) ((A) < (B) ? (A) : (B))


#define ERASE_ARRAY(ARR) libar2_erase(ARR, sizeof(ARR))
#define ERASE_STRUCT(S) libar2_erase(&(S), sizeof(S))


struct SIMD_ALIGNED_ATTRIBUTE block {
	uint_least64_t w[1024 / (64 / 8)];
};


LIBAR2_HIDDEN__ void libar2_internal_erase__(volatile void *mem, size_t size);
#if defined(__x86_64__) && defined(LIBAR2_TARGET__)
LIBAR2_HIDDEN__ void libar2_internal_use_generic__(void);
LIBAR2_HIDDEN__ void libar2_internal_use_sse2__(void);
LIBAR2_HIDDEN__ void libar2_internal_use_avx2__(void);
LIBAR2_HIDDEN__ void libar2_internal_use_avx512f__(void);
#endif


#if defined(__clang__)
# pragma clang diagnostic ignored "-Wc++98-compat"
#endif
