#ifndef ARCH_RISCV64_H
#define ARCH_RISCV64_H

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

#define FIO_ARCH	(arch_riscv64)

#define nop		__asm__ __volatile__ ("nop")
#define read_barrier()		__asm__ __volatile__("fence r, r": : :"memory")
#define write_barrier()		__asm__ __volatile__("fence w, w": : :"memory")

static inline unsigned long long get_cpu_clock(void)
{
	unsigned long val;

	asm volatile("rdtime %0" : "=r"(val));
	return val;
}
#define ARCH_HAVE_CPU_CLOCK

#define ARCH_HAVE_INIT
extern bool tsc_reliable;
static inline int arch_init(char *envp[])
{
	tsc_reliable = true;
	return 0;
}

#define __do_syscallM(...) ({						\
	__asm__ volatile (						\
		"ecall"							\
		: "=r"(a0)						\
		: __VA_ARGS__						\
		: "memory", "a1");					\
	(long) a0;							\
})

#define __do_syscallN(...) ({						\
	__asm__ volatile (						\
		"ecall"							\
		: "=r"(a0)						\
		: __VA_ARGS__						\
		: "memory");					\
	(long) a0;							\
})

#define __do_syscall0(__n) ({						\
	register long a7 __asm__("a7") = __n;				\
	register long a0 __asm__("a0");					\
									\
	__do_syscallM("r" (a7));					\
})

#define __do_syscall1(__n, __a) ({					\
	register long a7 __asm__("a7") = __n;				\
	register __typeof__(__a) a0 __asm__("a0") = __a;		\
									\
	__do_syscallM("r" (a7), "0" (a0));				\
})

#define __do_syscall2(__n, __a, __b) ({					\
	register long a7 __asm__("a7") = __n;				\
	register __typeof__(__a) a0 __asm__("a0") = __a;		\
	register __typeof__(__b) a1 __asm__("a1") = __b;		\
									\
	__do_syscallN("r" (a7), "0" (a0), "r" (a1));			\
})

#define __do_syscall3(__n, __a, __b, __c) ({				\
	register long a7 __asm__("a7") = __n;				\
	register __typeof__(__a) a0 __asm__("a0") = __a;		\
	register __typeof__(__b) a1 __asm__("a1") = __b;		\
	register __typeof__(__c) a2 __asm__("a2") = __c;		\
									\
	__do_syscallN("r" (a7), "0" (a0), "r" (a1), "r" (a2));		\
})

#define __do_syscall4(__n, __a, __b, __c, __d) ({			\
	register long a7 __asm__("a7") = __n;				\
	register __typeof__(__a) a0 __asm__("a0") = __a;		\
	register __typeof__(__b) a1 __asm__("a1") = __b;		\
	register __typeof__(__c) a2 __asm__("a2") = __c;		\
	register __typeof__(__d) a3 __asm__("a3") = __d;		\
									\
	__do_syscallN("r" (a7), "0" (a0), "r" (a1), "r" (a2), "r" (a3));\
})

#define __do_syscall5(__n, __a, __b, __c, __d, __e) ({			\
	register long a7 __asm__("a7") = __n;				\
	register __typeof__(__a) a0 __asm__("a0") = __a;		\
	register __typeof__(__b) a1 __asm__("a1") = __b;		\
	register __typeof__(__c) a2 __asm__("a2") = __c;		\
	register __typeof__(__d) a3 __asm__("a3") = __d;		\
	register __typeof__(__e) a4 __asm__("a4") = __e;		\
									\
	__do_syscallN("r" (a7), "0" (a0), "r" (a1), "r" (a2), "r" (a3),	\
			"r"(a4));					\
})

#define __do_syscall6(__n, __a, __b, __c, __d, __e, __f) ({		\
	register long a7 __asm__("a7") = __n;				\
	register __typeof__(__a) a0 __asm__("a0") = __a;		\
	register __typeof__(__b) a1 __asm__("a1") = __b;		\
	register __typeof__(__c) a2 __asm__("a2") = __c;		\
	register __typeof__(__d) a3 __asm__("a3") = __d;		\
	register __typeof__(__e) a4 __asm__("a4") = __e;		\
	register __typeof__(__f) a5 __asm__("a5") = __f;		\
									\
	__do_syscallN("r" (a7), "0" (a0), "r" (a1), "r" (a2), "r" (a3),	\
			"r" (a4), "r"(a5));				\
})

#define FIO_ARCH_HAS_SYSCALL

#endif
