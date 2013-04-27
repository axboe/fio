#ifndef ARCH_X86_H
#define ARCH_X86_H

static inline void do_cpuid(unsigned int *eax, unsigned int *ebx,
			    unsigned int *ecx, unsigned int *edx)
{
	asm volatile("xchgl %%ebx, %1\ncpuid\nxchgl %%ebx, %1"
		: "=a" (*eax), "=r" (*ebx), "=c" (*ecx), "=d" (*edx)
		: "0" (*eax)
		: "memory");
}

#include "arch-x86-common.h"

#define FIO_ARCH	(arch_i386)

#ifndef __NR_ioprio_set
#define __NR_ioprio_set		289
#define __NR_ioprio_get		290
#endif

#ifndef __NR_fadvise64
#define __NR_fadvise64		250
#endif

#ifndef __NR_sys_splice
#define __NR_sys_splice		313
#define __NR_sys_tee		315
#define __NR_sys_vmsplice	316
#endif

#define	FIO_HUGE_PAGE		4194304

#define nop		__asm__ __volatile__("rep;nop": : :"memory")
#define read_barrier()	__asm__ __volatile__("": : :"memory")
#define write_barrier()	__asm__ __volatile__("": : :"memory")

static inline unsigned long arch_ffz(unsigned long bitmask)
{
	__asm__("bsfl %1,%0" :"=r" (bitmask) :"r" (~bitmask));
	return bitmask;
}

static inline unsigned long long get_cpu_clock(void)
{
	unsigned long long ret;

	__asm__ __volatile__("rdtsc" : "=A" (ret));
	return ret;
}

#define ARCH_HAVE_FFZ
#define ARCH_HAVE_CPU_CLOCK

#endif
