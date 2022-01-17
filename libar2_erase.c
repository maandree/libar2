/* See LICENSE file for copyright and license details. */
#include "common.h"


#if defined(memset_s)
#elif defined(explicit_bzero) || defined(__OpenBSD__)
#elif defined(explicit_memset)
#else
# if defined(__GNUC__)
__attribute__((visibility("hidden")))
# endif
void *(*const volatile libar2_internal_explicit_memset__)(void *, int, size_t) = &memset;
#endif


#if defined(__clang__) /* before __GNUC__ because that is also set in clang */
# if __has_attribute(optnone)
__attribute__((optnone))
# endif
#elif defined(__GNUC__)
# if __GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__ >= 40400
__attribute__((optimize("O0")))
# endif
#endif
void
libar2_erase(volatile void *mem_, size_t size)
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

/* Typo in version 1.0 */
#if defined(__GNUC__)
extern __typeof(libar2_erase) libar2_earse __attribute__((__weak__, __alias__("libar2_erase")));
#else
void libar2_earse(volatile void *mem, size_t size);
void
libar2_earse(volatile void *mem, size_t size)
{
	libar2_erase(mem, size);
}
#endif