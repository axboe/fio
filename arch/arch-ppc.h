#ifndef ARCH_PPC_H
#define ARCH_PPH_H

#define ARCH	(arch_ppc)

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

static inline int __ilog2(unsigned long bitmask)
{
	int lz;

	asm ("cntlzw %0,%1" : "=r" (lz) : "r" (bitmask));
	return 31 - lz;
}

static inline int fio_ffz(unsigned long bitmask)
{
	if ((bitmask = ~bitmask) == 0)
		return 32;
	return  __ilog2(bitmask & -bitmask);
}

#endif
