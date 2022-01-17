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

#define ELEMSOF(ARR) (sizeof(ARR) / sizeof(*(ARR)))

#define MAX(A, B) ((A) > (B) ? (A) : (B))
#define MIN(A, B) ((A) < (B) ? (A) : (B))


#define ERASE(PTR, N) libar2_erase(PTR, N)
#define ERASE_ARRAY(ARR) ERASE(ARR, sizeof(ARR))
#define ERASE_STRUCT(S) ERASE(&(S), sizeof(S))


struct block {
	uint_least64_t w[1024 / (64 / 8)];
};
