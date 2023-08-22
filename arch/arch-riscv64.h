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

	asm volatile("rdcycle %0" : "=r"(val));
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

#endif
