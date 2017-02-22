#ifndef FIO_COMPILER_H
#define FIO_COMPILER_H
#include <assert.h>

#if __GNUC__ >= 4
#include "compiler-gcc4.h"
#elif __GNUC__ == 3
#include "compiler-gcc3.h"
#else
#error Compiler too old, need gcc at least gcc 3.x
#endif

#ifndef __must_check
#define __must_check
#endif

/*
 * Mark unused variables passed to ops functions as unused, to silence gcc
 */
#define fio_unused	__attribute__((__unused__))
#define fio_init	__attribute__((constructor))
#define fio_exit	__attribute__((destructor))

#define fio_unlikely(x)	__builtin_expect(!!(x), 0)

/*
 * Check at compile time that something is of a particular type.
 * Always evaluates to 1 so you may use it easily in comparisons.
 */
#define typecheck(type,x) \
({	type __dummy; \
	typeof(x) __dummy2; \
	(void)(&__dummy == &__dummy2); \
	1; \
})


#if defined(CONFIG_STATIC_ASSERT)
#define compiletime_assert(condition, msg) _Static_assert(condition, msg)

#elif !defined(CONFIG_DISABLE_OPTIMIZATIONS)

#ifndef __compiletime_error
#define __compiletime_error(message)
#endif

#ifndef __compiletime_error_fallback
#define __compiletime_error_fallback(condition)	do { } while (0)
#endif

#define __compiletime_assert(condition, msg, prefix, suffix)		\
	do {								\
		int __cond = !(condition);				\
		extern void prefix ## suffix(void) __compiletime_error(msg); \
		if (__cond)						\
			prefix ## suffix();				\
		__compiletime_error_fallback(__cond);			\
	} while (0)

#define _compiletime_assert(condition, msg, prefix, suffix) \
	__compiletime_assert(condition, msg, prefix, suffix)

#define compiletime_assert(condition, msg) \
	_compiletime_assert(condition, msg, __compiletime_assert_, __LINE__)

#else

#define compiletime_assert(condition, msg)	do { } while (0)

#endif

#endif
