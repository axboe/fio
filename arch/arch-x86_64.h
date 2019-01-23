#ifndef ARCH_X86_64_H
#define ARCH_X86_64_H

static inline void do_cpuid(unsigned int *eax, unsigned int *ebx,
			    unsigned int *ecx, unsigned int *edx)
{
	asm volatile("cpuid"
		: "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
		: "0" (*eax), "2" (*ecx)
		: "memory");
}

#include "arch-x86-common.h" /* IWYU pragma: export */

#define FIO_ARCH	(arch_x86_64)

#define	FIO_HUGE_PAGE		2097152

#define nop		__asm__ __volatile__("rep;nop": : :"memory")
#define read_barrier()	__asm__ __volatile__("":::"memory")
#define write_barrier()	__asm__ __volatile__("":::"memory")

static inline unsigned long arch_ffz(unsigned long bitmask)
{
	__asm__("bsf %1,%0" :"=r" (bitmask) :"r" (~bitmask));
	return bitmask;
}

static inline unsigned long long get_cpu_clock(void)
{
	unsigned int lo, hi;

	__asm__ __volatile__("rdtsc" : "=a" (lo), "=d" (hi));
	return ((unsigned long long) hi << 32ULL) | lo;
}

#define ARCH_HAVE_FFZ
#define ARCH_HAVE_SSE4_2
#define ARCH_HAVE_CPU_CLOCK

#define RDRAND_LONG	".byte 0x48,0x0f,0xc7,0xf0"
#define RDSEED_LONG	".byte 0x48,0x0f,0xc7,0xf8"
#define RDRAND_RETRY	100

static inline int arch_rand_long(unsigned long *val)
{
	int ok;

	asm volatile("1: " RDRAND_LONG "\n\t"
		     "jc 2f\n\t"
		     "decl %0\n\t"
		     "jnz 1b\n\t"
		     "2:"
		     : "=r" (ok), "=a" (*val)
		     : "0" (RDRAND_RETRY));

	return ok;
}

static inline int arch_rand_seed(unsigned long *seed)
{
	unsigned char ok;

	asm volatile(RDSEED_LONG "\n\t"
			"setc %0"
			: "=qm" (ok), "=a" (*seed));

	return 0;
}

#endif
