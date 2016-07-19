#ifndef ARCH_SPARC64_H
#define ARCH_SPARC64_H

#define FIO_ARCH	(arch_sparc64)

#define nop	do { } while (0)

#define membar_safe(type) \
	do {    __asm__ __volatile__("ba,pt     %%xcc, 1f\n\t" \
					" membar   " type "\n" \
					"1:\n" \
					: : : "memory"); \
	} while (0)

#define read_barrier()		membar_safe("#LoadLoad")
#define write_barrier()		membar_safe("#StoreStore")

#endif
