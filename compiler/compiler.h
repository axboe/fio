#ifndef FIO_COMPILER_H
#define FIO_COMPILER_H

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

#endif
