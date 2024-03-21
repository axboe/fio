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

static inline void tsc_barrier(void)
{
	__asm__ __volatile__("mfence":::"memory");
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

#define __do_syscall0(NUM) ({			\
	intptr_t rax;				\
						\
	__asm__ volatile(			\
		"syscall"			\
		: "=a"(rax)	/* %rax */	\
		: "a"(NUM)	/* %rax */	\
		: "rcx", "r11", "memory"	\
	);					\
	rax;					\
})

#define __do_syscall1(NUM, ARG1) ({		\
	intptr_t rax;				\
						\
	__asm__ volatile(			\
		"syscall"			\
		: "=a"(rax)	/* %rax */	\
		: "a"((NUM)),	/* %rax */	\
		  "D"((ARG1))	/* %rdi */	\
		: "rcx", "r11", "memory"	\
	);					\
	rax;					\
})

#define __do_syscall2(NUM, ARG1, ARG2) ({	\
	intptr_t rax;				\
						\
	__asm__ volatile(			\
		"syscall"			\
		: "=a"(rax)	/* %rax */	\
		: "a"((NUM)),	/* %rax */	\
		  "D"((ARG1)),	/* %rdi */	\
		  "S"((ARG2))	/* %rsi */	\
		: "rcx", "r11", "memory"	\
	);					\
	rax;					\
})

#define __do_syscall3(NUM, ARG1, ARG2, ARG3) ({	\
	intptr_t rax;				\
						\
	__asm__ volatile(			\
		"syscall"			\
		: "=a"(rax)	/* %rax */	\
		: "a"((NUM)),	/* %rax */	\
		  "D"((ARG1)),	/* %rdi */	\
		  "S"((ARG2)),	/* %rsi */	\
		  "d"((ARG3))	/* %rdx */	\
		: "rcx", "r11", "memory"	\
	);					\
	rax;					\
})

#define __do_syscall4(NUM, ARG1, ARG2, ARG3, ARG4) ({			\
	intptr_t rax;							\
	register __typeof__(ARG4) __r10 __asm__("r10") = (ARG4);	\
									\
	__asm__ volatile(						\
		"syscall"						\
		: "=a"(rax)	/* %rax */				\
		: "a"((NUM)),	/* %rax */				\
		  "D"((ARG1)),	/* %rdi */				\
		  "S"((ARG2)),	/* %rsi */				\
		  "d"((ARG3)),	/* %rdx */				\
		  "r"(__r10)	/* %r10 */				\
		: "rcx", "r11", "memory"				\
	);								\
	rax;								\
})

#define __do_syscall5(NUM, ARG1, ARG2, ARG3, ARG4, ARG5) ({		\
	intptr_t rax;							\
	register __typeof__(ARG4) __r10 __asm__("r10") = (ARG4);	\
	register __typeof__(ARG5) __r8 __asm__("r8") = (ARG5);		\
									\
	__asm__ volatile(						\
		"syscall"						\
		: "=a"(rax)	/* %rax */				\
		: "a"((NUM)),	/* %rax */				\
		  "D"((ARG1)),	/* %rdi */				\
		  "S"((ARG2)),	/* %rsi */				\
		  "d"((ARG3)),	/* %rdx */				\
		  "r"(__r10),	/* %r10 */				\
		  "r"(__r8)	/* %r8 */				\
		: "rcx", "r11", "memory"				\
	);								\
	rax;								\
})

#define __do_syscall6(NUM, ARG1, ARG2, ARG3, ARG4, ARG5, ARG6) ({	\
	intptr_t rax;							\
	register __typeof__(ARG4) __r10 __asm__("r10") = (ARG4);	\
	register __typeof__(ARG5) __r8 __asm__("r8") = (ARG5);		\
	register __typeof__(ARG6) __r9 __asm__("r9") = (ARG6);		\
									\
	__asm__ volatile(						\
		"syscall"						\
		: "=a"(rax)	/* %rax */				\
		: "a"((NUM)),	/* %rax */				\
		  "D"((ARG1)),	/* %rdi */				\
		  "S"((ARG2)),	/* %rsi */				\
		  "d"((ARG3)),	/* %rdx */				\
		  "r"(__r10),	/* %r10 */				\
		  "r"(__r8),	/* %r8 */				\
		  "r"(__r9)	/* %r9 */				\
		: "rcx", "r11", "memory"				\
	);								\
	rax;								\
})

#define FIO_ARCH_HAS_SYSCALL

#endif
