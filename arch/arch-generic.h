#ifndef ARCH_GENERIC_H
#define ARCH_GENERIC_H

#define FIO_ARCH	(arch_generic)

#define nop			do { } while (0)
#define read_barrier()		__asm__ __volatile__("": : :"memory")
#define write_barrier()		__asm__ __volatile__("": : :"memory")

#endif
