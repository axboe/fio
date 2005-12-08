#ifndef ARCH_H
#define ARCH_H

enum {
	arch_x86_64,
	arch_i386,
	arch_ppc,
	arch_ia64,
	arch_s390,
	arch_alpha,
};

static inline unsigned long generic_ffz(unsigned long word)
{
	unsigned int i;

	for (i = 0; i < sizeof(word) * 8; i++)
		if ((word & (1UL << i)) == 0)
			return i;

	return -1;
}

#if defined(__i386__)
#include "arch-x86.h"
#elif defined(__x86_64__)
#include "arch-x86_64.h"
#elif defined(__powerpc__) || defined(__powerpc64__)
#include "arch-ppc.h"
#elif defined(__ia64__)
#include "arch-ia64.h"
#elif defined(__alpha__)
#include "arch-alpha.h"
#elif defined(__s390x__) || defined(__s390__)
#include "arch-s390.h"
#else
#error "Unsupported arch"
#endif

#define BITS_PER_LONG	(__WORDSIZE)

#endif
