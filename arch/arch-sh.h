/* Renesas SH (32bit) only */

#ifndef ARCH_SH_H
#define ARCH_SH_H

#define FIO_ARCH	(arch_sh)

#ifndef __NR_ioprio_set
#define __NR_ioprio_set	288
#define __NR_ioprio_get	289
#endif

#ifndef __NR_fadvise64
#define __NR_fadvise64	250
#endif

#ifndef __NR_sys_splice
#define __NR_sys_splice		313
#define __NR_sys_tee		315
#define __NR_sys_vmsplice	316
#endif

#define nop             __asm__ __volatile__ ("nop": : :"memory")

#define mb()								\
	do {								\
		if (arch_flags & ARCH_FLAG_1)				\
			__asm__ __volatile__ ("synco": : :"memory");	\
		else							\
			__asm__ __volatile__ (" " : : : "memory");	\
	} while (0)

#define read_barrier()	mb()
#define write_barrier()	mb()

#include <stdio.h>
#include <elf.h>

extern unsigned long arch_flags;

#define CPU_HAS_LLSC	0x0040

static inline int arch_init(char *envp[])
{
	Elf32_auxv_t *auxv;

	while (*envp++ != NULL)
		;

	for (auxv = (Elf32_auxv_t *) envp; auxv->a_type != AT_NULL; auxv++) {
		if (auxv->a_type == AT_HWCAP) {
			if (auxv->a_un.a_val & CPU_HAS_LLSC) {
				arch_flags |= ARCH_FLAG_1;
				break;
			}
		}
	}

	return 0;
}

#define ARCH_HAVE_INIT

#endif
