#ifndef ARCH_AARCH64_H
#define ARCH_AARCH64_H

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

#define FIO_ARCH	(arch_aarch64)

#define nop		do { __asm__ __volatile__ ("yield"); } while (0)
#define read_barrier()	do { __sync_synchronize(); } while (0)
#define write_barrier()	do { __sync_synchronize(); } while (0)

static inline int arch_ffz(unsigned long bitmask)
{
	unsigned long count, reversed_bits;
	if (~bitmask == 0)	/* ffz() in lib/ffz.h does this. */
		return 63;

	__asm__ __volatile__ ("rbit %1, %2\n"
			      "clz %0, %1\n" : 
			      "=r"(count), "=&r"(reversed_bits) :
			      "r"(~bitmask));
	return count;
}

#define ARCH_HAVE_FFZ

static inline unsigned long long get_cpu_clock(void)
{
	unsigned long val;

	asm volatile("mrs %0, cntvct_el0" : "=r" (val));
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
