#ifndef ARCH_PPC_H
#define ARCH_PPC_H

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

#define FIO_ARCH	(arch_ppc)

#define nop	do { } while (0)

#ifdef __powerpc64__
#define read_barrier()	__asm__ __volatile__ ("lwsync" : : : "memory")
#else
#define read_barrier()	__asm__ __volatile__ ("sync" : : : "memory")
#endif

#define write_barrier()	__asm__ __volatile__ ("sync" : : : "memory")

#ifdef __powerpc64__
#define PPC_CNTLZL "cntlzd"
#else
#define PPC_CNTLZL "cntlzw"
#endif

static inline int __ilog2(unsigned long bitmask)
{
	int lz;

	asm (PPC_CNTLZL " %0,%1" : "=r" (lz) : "r" (bitmask));
	return BITS_PER_LONG - 1 - lz;
}

static inline int arch_ffz(unsigned long bitmask)
{
	if ((bitmask = ~bitmask) == 0)
		return BITS_PER_LONG;
	return  __ilog2(bitmask & -bitmask);
}

static inline unsigned int mfspr(unsigned int reg)
{
	unsigned int val;

	asm volatile("mfspr %0,%1": "=r" (val) : "K" (reg));
	return val;
}

#define SPRN_TBRL  0x10C /* Time Base Register Lower */
#define SPRN_TBRU  0x10D /* Time Base Register Upper */
#define SPRN_ATBL  0x20E /* Alternate Time Base Lower */
#define SPRN_ATBU  0x20F /* Alternate Time Base Upper */

#ifdef __powerpc64__
static inline unsigned long long get_cpu_clock(void)
{
	unsigned long long rval;

	asm volatile(
		"90:	mfspr %0, %1;\n"
		"	cmpwi %0,0;\n"
		"	beq-  90b;\n"
	: "=r" (rval)
	: "i" (SPRN_TBRL));

	return rval;
}
#else
static inline unsigned long long get_cpu_clock(void)
{
	unsigned int tbl, tbu0, tbu1;
	unsigned long long ret;

	do {
		if (arch_flags & ARCH_FLAG_1) {
			tbu0 = mfspr(SPRN_ATBU);
			tbl = mfspr(SPRN_ATBL);
			tbu1 = mfspr(SPRN_ATBU);
		} else {
			tbu0 = mfspr(SPRN_TBRU);
			tbl = mfspr(SPRN_TBRL);
			tbu1 = mfspr(SPRN_TBRU);
		}
	} while (tbu0 != tbu1);

	ret = (((unsigned long long)tbu0) << 32) | tbl;
	return ret;
}
#endif

#if 0
static void atb_child(void)
{
	arch_flags |= ARCH_FLAG_1;
	get_cpu_clock();
	_exit(0);
}

static void atb_clocktest(void)
{
	pid_t pid;

	pid = fork();
	if (!pid)
		atb_child();
	else if (pid != -1) {
		int status;

		pid = wait(&status);
		if (pid == -1 || !WIFEXITED(status))
			arch_flags &= ~ARCH_FLAG_1;
		else
			arch_flags |= ARCH_FLAG_1;
	}
}
#endif

#define ARCH_HAVE_INIT
extern int tsc_reliable;

static inline int arch_init(char *envp[])
{
#if 0
	tsc_reliable = 1;
	atb_clocktest();
#endif
	return 0;
}

#define ARCH_HAVE_FFZ

/*
 * We don't have it on all platforms, lets comment this out until we
 * can handle it more intelligently.
 *
 * #define ARCH_HAVE_CPU_CLOCK
 */

/*
 * Let's have it defined for ppc64
 */

#ifdef __powerpc64__
#define ARCH_HAVE_CPU_CLOCK
#endif

#endif
