#ifndef ARCH_ALPHA_H
#define ARCH_ALPHA_H

#define FIO_ARCH	(arch_alpha)

#define nop			do { } while (0)
#define read_barrier()		__asm__ __volatile__("mb": : :"memory")
#define write_barrier()		__asm__ __volatile__("wmb": : :"memory")

#endif
