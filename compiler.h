#ifndef FIO_COMPILER_H
#define FIO_COMPILER_H

#if __GNUC__ >= 4
#include "compiler-gcc4.h"
#elif __GNUC == 3
#include "compiler-gcc3.h"
#else
#error Compiler too old, need gcc at least gcc 3.x
#endif

#endif
