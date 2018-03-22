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

#include "arch-x86-common.h" /* IWYU pragma: export */

#define FIO_ARCH	(arch_x86)

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
