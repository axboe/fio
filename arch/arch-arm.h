#ifndef ARCH_ARM_H
#define ARCH_ARM_H

#define FIO_ARCH	(arch_arm)

#ifndef __NR_ioprio_set
#define __NR_ioprio_set		314
#define __NR_ioprio_get		315
#endif

#ifndef __NR_fadvise64
#define __NR_fadvise64		270
#endif

#ifndef __NR_sys_splice
#define __NR_sys_splice		340
#define __NR_sys_tee		342
#define __NR_sys_vmsplice	343
#endif

#if defined (__ARM_ARCH_4__) || defined (__ARM_ARCH_4T__) \
	|| defined (__ARM_ARCH_5__) || defined (__ARM_ARCH_5T__) || defined (__ARM_ARCH_5TE__) || defined (__ARM_ARCH_5TEJ__) \
	|| defined(__ARM_ARCH_6__)  || defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__)
#define nop             __asm__ __volatile__("mov\tr0,r0\t@ nop\n\t")
#define read_barrier()	__asm__ __volatile__ ("" : : : "memory")
#define write_barrier()	__asm__ __volatile__ ("" : : : "memory")
#elif defined(__ARM_ARCH_7A__)
#define	nop		__asm__ __volatile__ ("nop")
#define read_barrier()	__sync_synchronize()
#define write_barrier()	__sync_synchronize()
#endif

#endif
