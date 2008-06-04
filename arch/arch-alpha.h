#ifndef ARCH_ALPHA_H
#define ARCH_ALPHA_H

#define ARCH	(arch_alpha)

#ifndef __NR_ioprio_set
#define __NR_ioprio_set		442
#define __NR_ioprio_get		443
#endif

#ifndef __NR_fadvise64
#define __NR_fadvise64		413
#endif

#define nop			do { } while (0)
#define read_barrier()		__asm__ __volatile__("mb": : :"memory")
#define writer_barrier()	__asm__ __volatile__("wmb": : :"memory")

#endif
