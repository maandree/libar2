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
# define LIBAR2_WEAKLY_LINKED__ __attribute__((weak))
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


#define ELEMSOF(ARR) (sizeof(ARR) / sizeof(*(ARR)))

#define MAX(A, B) ((A) > (B) ? (A) : (B))
#define MIN(A, B) ((A) < (B) ? (A) : (B))


#define ERASE(PTR, N) libar2_erase(PTR, N)
#define ERASE_ARRAY(ARR) ERASE(ARR, sizeof(ARR))
#define ERASE_STRUCT(S) ERASE(&(S), sizeof(S))


struct block {
	uint_least64_t w[1024 / (64 / 8)];
};


#if defined(__clang__)
# pragma clang diagnostic ignored "-Wc++98-compat"
#endif
