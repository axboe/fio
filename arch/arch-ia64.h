#ifndef ARCH_IA64_H
#define ARCH_IA64_H

#define FIO_ARCH	(arch_ia64)

#ifndef __NR_ioprio_set
#define __NR_ioprio_set		1274
#define __NR_ioprio_get		1275
#endif

#ifndef __NR_fadvise64
#define __NR_fadvise64		1234
#endif

#ifndef __NR_sys_splice
#define __NR_sys_splice		1297
#define __NR_sys_tee		1301
#define __NR_sys_vmsplice	1302
#endif

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
