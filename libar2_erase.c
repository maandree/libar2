/* See LICENSE file for copyright and license details. */
#include "common.h"


#if defined(memset_s)
#elif defined(explicit_bzero) || defined(__OpenBSD__)
#elif defined(explicit_memset)
#else
# if defined(__GNUC__)
__attribute__((visibility("hidden")))
# endif
extern void *(*const volatile libar2_internal_explicit_memset__)(void *, int, size_t);
void *(*const volatile libar2_internal_explicit_memset__)(void *, int, size_t) = &memset;
#endif


/* libar2_internal_erase__ is intended for the test code to use, because it replaces `libar2_erase`  */
# if defined(__GNUC__)
__attribute__((visibility("hidden")))
# endif
void libar2_internal_erase__(volatile void *mem, size_t size);
#if defined(__clang__) /* before __GNUC__ because that is also set in clang */
# if __has_attribute(optnone)
__attribute__((optnone))
# endif
#elif defined(__GNUC__)
# if __GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__ >= 40400
__attribute__((optimize("O0")))
# endif
#endif
#ifdef LIBAR2_WEAKLY_LINKED__
LIBAR2_WEAKLY_LINKED__
#endif
void
libar2_internal_erase__(volatile void *mem_, size_t size)
{
	void *mem = *(void **)(void *)&mem_;
#if defined(memset_s)
	memset_s(mem, size);
#elif defined(explicit_bzero) || defined(__OpenBSD__)
	explicit_bzero(mem, size);
#elif defined(explicit_memset)
	explicit_memset(mem, 0, size);
#else
	libar2_internal_explicit_memset__(mem, 0, size);
#endif
}


#if defined(__GNUC__)
LIBAR2_PUBLIC__ LIBAR2_WEAKLY_LINKED__
extern void libar2_erase(volatile void *, size_t) __attribute__((__alias__("libar2_internal_erase__")));
#else
void
libar2_erase(volatile void *mem, size_t size)
{
	libar2_internal_erase__(mem, size);
}
#endif


/* Typo in version 1.0 */
#if defined(__GNUC__)
LIBAR2_PUBLIC__ LIBAR2_WEAKLY_LINKED__
extern void libar2_earse(volatile void *, size_t) __attribute__((__alias__("libar2_internal_erase__")));
#else
LIBAR2_PUBLIC__ LIBAR2_WEAKLY_LINKED__
void libar2_earse(volatile void *mem, size_t size);
void
libar2_earse(volatile void *mem, size_t size)
{
	libar2_internal_erase__(mem, size);
}
#endif
