#ifndef ARCH_SPARC64_H
#define ARCH_SPARC64_H

#define FIO_ARCH	(arch_sparc64)

#ifndef __NR_ioprio_set
#define __NR_ioprio_set		196
#define __NR_ioprio_get		218
#endif

#ifndef __NR_fadvise64
#define __NR_fadvise64		209
#endif

#ifndef __NR_sys_splice
#define __NR_sys_splice		232
#define __NR_sys_tee		280
#define __NR_sys_vmsplice	25
#endif

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
