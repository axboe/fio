#ifndef ARCH_H
#define ARCH_H

enum {
	arch_x86_64 = 1,
	arch_i386,
	arch_ppc,
	arch_ia64,
	arch_s390,
	arch_alpha,
	arch_sparc,
	arch_sparc64,
	arch_arm,
	arch_sh,
	arch_hppa,
	arch_mips,

	arch_generic,

	arch_nr,
};

enum {
	ARCH_FLAG_1	= 1 << 0,
	ARCH_FLAG_2	= 1 << 1,
	ARCH_FLAG_3	= 1 << 2,
	ARCH_FLAG_4	= 1 << 3,
};

extern unsigned long arch_flags;

#if defined(__i386__)
#include "arch-x86.h"
#elif defined(__x86_64__)
#include "arch-x86_64.h"
#elif defined(__powerpc__) || defined(__powerpc64__) || defined(__ppc__)
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
#elif defined(__arm__)
#include "arch-arm.h"
#elif defined(__mips__) || defined(__mips64__)
#include "arch-mips.h"
#elif defined(__sh__)
#include "arch-sh.h"
#elif defined(__hppa__)
#include "arch-hppa.h"
#else
#warning "Unknown architecture, attempting to use generic model."
#include "arch-generic.h"
#endif

#ifdef ARCH_HAVE_FFZ
#define ffz(bitmask)	arch_ffz(bitmask)
#else
#include "../lib/ffz.h"
#endif

#ifndef ARCH_HAVE_INIT
static inline int arch_init(char *envp[])
{
	return 0;
}
#endif

#endif
