#ifndef ARCH_MIPS64_H
#define ARCH_MIPS64_H

#define FIO_ARCH	(arch_mips)

#ifndef __SANE_USERSPACE_TYPES__
#define __SANE_USERSPACE_TYPES__
#endif

#define read_barrier()		__asm__ __volatile__("": : :"memory")
#define write_barrier()		__asm__ __volatile__("": : :"memory")
#define nop			__asm__ __volatile__("": : :"memory")

#endif
