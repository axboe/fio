/* Renesas SH (32bit) only */

#ifndef ARCH_SH_H
#define ARCH_SH_H

#define ARCH	(arch_sh)

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

#if defined(__SH4A__)
#define	mb()		__asm__ __volatile__ ("synco": : :"memory")
#else
#define mb()		__asm__ __volatile__ (" " : : : "memory")
#endif

#define read_barrier()	mb()
#define write_barrier()	mb()

#endif
