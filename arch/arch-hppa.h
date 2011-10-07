#ifndef ARCH_HPPA_H
#define ARCH_HPPA_H

#define FIO_ARCH	(arch_hppa)

#ifndef __NR_ioprio_set
#define __NR_ioprio_set		267
#define __NR_ioprio_get		268
#endif

#ifndef __NR_fadvise64
#define __NR_fadvise64		236
#endif

#ifndef __NR_sys_splice
#define __NR_sys_splice		291
#define __NR_sys_tee		293
#define __NR_sys_vmsplice	294
#endif

#define nop	do { } while (0)

#define read_barrier()	__asm__ __volatile__ ("" : : : "memory")
#define write_barrier()	__asm__ __volatile__ ("" : : : "memory")

#endif
