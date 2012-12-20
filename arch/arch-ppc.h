#ifndef ARCH_PPC_H
#define ARCH_PPH_H

#define FIO_ARCH	(arch_ppc)

#ifndef __NR_ioprio_set
#define __NR_ioprio_set		273
#define __NR_ioprio_get		274
#endif

#ifndef __NR_fadvise64
#define __NR_fadvise64		233
#endif

#ifndef __NR_sys_splice
#define __NR_sys_splice		283
#define __NR_sys_tee		284
#define __NR_sys_vmsplice	285
#endif

#define nop	do { } while (0)

#ifdef __powerpc64__
#define read_barrier()	__asm__ __volatile__ ("lwsync" : : : "memory")
#else
#define read_barrier()	__asm__ __volatile__ ("sync" : : : "memory")
#endif

#define write_barrier()	__asm__ __volatile__ ("sync" : : : "memory")

static inline int __ilog2(unsigned long bitmask)
{
	int lz;

	asm ("cntlzw %0,%1" : "=r" (lz) : "r" (bitmask));
	return 31 - lz;
}

static inline int arch_ffz(unsigned long bitmask)
{
	if ((bitmask = ~bitmask) == 0)
		return 32;
	return  __ilog2(bitmask & -bitmask);
}

static inline unsigned long long get_cpu_clock(void)
{
	unsigned int tbl, tbu0, tbu1;
	unsigned long long ret;

	do {
		__asm__ __volatile__ ("mftbu %0" : "=r"(tbu0));
		__asm__ __volatile__ ("mftb %0"  : "=r"(tbl) );
		__asm__ __volatile__ ("mftbu %0" : "=r"(tbu1));
	} while (tbu0 != tbu1);

	ret = (((unsigned long long)tbu0) << 32) | tbl;
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
