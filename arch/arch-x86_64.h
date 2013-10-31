#ifndef ARCH_X86_64_h
#define ARCH_X86_64_h

static inline void do_cpuid(unsigned int *eax, unsigned int *ebx,
			    unsigned int *ecx, unsigned int *edx)
{
	asm volatile("cpuid"
		: "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
		: "0" (*eax), "2" (*ecx)
		: "memory");
}

#include "arch-x86-common.h"

#define FIO_ARCH	(arch_x86_64)

#ifndef __NR_ioprio_set
#define __NR_ioprio_set		251
#define __NR_ioprio_get		252
#endif

#ifndef __NR_fadvise64
#define __NR_fadvise64		221
#endif

#ifndef __NR_sys_splice
#define __NR_sys_splice		275
#define __NR_sys_tee		276
#define __NR_sys_vmsplice	278
#endif

#ifndef __NR_shmget
#define __NR_shmget		 29
#define __NR_shmat		 30
#define __NR_shmctl		 31
#define __NR_shmdt		 67
#endif

#define	FIO_HUGE_PAGE		2097152

#define nop		__asm__ __volatile__("rep;nop": : :"memory")
#define read_barrier()	__asm__ __volatile__("lfence":::"memory")
#define write_barrier()	__asm__ __volatile__("sfence":::"memory")

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

#endif
