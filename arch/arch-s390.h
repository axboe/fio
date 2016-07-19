#ifndef ARCH_S390_H
#define ARCH_S390_H

#define FIO_ARCH	(arch_s390)

#define nop		asm volatile("nop" : : : "memory")
#define read_barrier()	asm volatile("bcr 15,0" : : : "memory")
#define write_barrier()	asm volatile("bcr 15,0" : : : "memory")

static inline unsigned long long get_cpu_clock(void)
{
	unsigned long long clk;

#ifdef CONFIG_S390_Z196_FACILITIES
	/*
	 * Fio needs monotonic (never lower), but not strict monotonic (never
	 * the same) so store clock fast is enough.
	 */
	__asm__ __volatile__("stckf %0" : "=Q" (clk) : : "cc");
#else
	__asm__ __volatile__("stck %0" : "=Q" (clk) : : "cc");
#endif
	return clk>>12;
}

#define ARCH_CPU_CLOCK_CYCLES_PER_USEC 1
#define ARCH_HAVE_CPU_CLOCK
#undef ARCH_CPU_CLOCK_WRAPS

#define ARCH_HAVE_INIT
extern int tsc_reliable;
static inline int arch_init(char *envp[])
{
	tsc_reliable = 1;
	return 0;
}

#endif
