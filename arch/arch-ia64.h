#ifndef ARCH_IA64_H
#define ARCH_IA64_H

#define FIO_ARCH	(arch_ia64)

#define nop		asm volatile ("hint @pause" ::: "memory");
#define read_barrier()	asm volatile ("mf" ::: "memory")
#define write_barrier()	asm volatile ("mf" ::: "memory")

#define ia64_popcnt(x)							\
({									\
	unsigned long ia64_intri_res;					\
	asm ("popcnt %0=%1" : "=r" (ia64_intri_res) : "r" (x));		\
	ia64_intri_res;							\
})

static inline unsigned long arch_ffz(unsigned long bitmask)
{
	return ia64_popcnt(bitmask & (~bitmask - 1));
}

static inline unsigned long long get_cpu_clock(void)
{
	unsigned long long ret;

	__asm__ __volatile__("mov %0=ar.itc" : "=r" (ret) : : "memory");
	return ret;
}

#define ARCH_HAVE_INIT
extern int tsc_reliable;
static inline int arch_init(char *envp[])
{
	tsc_reliable = 1;
	return 0;
}

#define ARCH_HAVE_FFZ
#define ARCH_HAVE_CPU_CLOCK

#endif
