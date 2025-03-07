#ifndef ARCH_LOONGARCH64_H
#define ARCH_LOONGARCH64_H

#define FIO_ARCH	(arch_loongarch64)

#define read_barrier()		__asm__ __volatile__("dbar 0": : :"memory")
#define write_barrier()		__asm__ __volatile__("dbar 0": : :"memory")
#define nop			__asm__ __volatile__("dbar 0": : :"memory")

#endif
