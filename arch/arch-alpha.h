#ifndef ARCH_ALPHA_H
#define ARCH_ALPHA_H

#define FIO_ARCH	(arch_alpha)

#ifndef __NR_ioprio_set
#define __NR_ioprio_set		442
#define __NR_ioprio_get		443
#endif

#ifndef __NR_fadvise64
#define __NR_fadvise64		413
#endif

#ifndef __NR_sys_splice
#define __NR_sys_splice		468
#define __NR_sys_tee		470
#define __NR_sys_vmsplice	471
#endif

#define nop			do { } while (0)
#define read_barrier()		__asm__ __volatile__("mb": : :"memory")
#define write_barrier()		__asm__ __volatile__("wmb": : :"memory")

#endif
