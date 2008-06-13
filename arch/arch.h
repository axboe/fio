#ifndef ARCH_H
#define ARCH_H

enum {
	arch_x86_64,
	arch_i386,
	arch_ppc,
	arch_ia64,
	arch_s390,
	arch_alpha,
	arch_sparc,
	arch_sparc64,
};

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
#elif defined(__sparc__)
#include "arch-sparc.h"
#elif defined(__sparc64__)
#include "arch-sparc64.h"
#else
#error "Unsupported arch"
#endif

#ifdef ARCH_HAVE_FFZ
#define ffz(bitmask)	arch_ffz(bitmask)
#else
#include "../lib/ffz.h"
#endif

#endif
