#ifndef ARCH_SPARC_H
#define ARCH_SPARC_H

#define FIO_ARCH	(arch_sparc)

#define nop	do { } while (0)

#define read_barrier()	__asm__ __volatile__ ("" : : : "memory")
#define write_barrier()	__asm__ __volatile__ ("" : : : "memory")

#endif
