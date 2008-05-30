#ifndef ARCH_IA64_H
#define ARCH_IA64_H

#define ARCH	(arch_ia64)

#ifndef __NR_ioprio_set
#define __NR_ioprio_set		1274
#define __NR_ioprio_get		1275
#endif

#ifndef __NR_fadvise64
#define __NR_fadvise64		1234
#endif

#ifndef __NR_sys_splice
#define __NR_sys_splice		1297
#define __NR_sys_tee		1301
#define __NR_sys_vmsplice	1302
#endif

#define nop		asm volatile ("hint @pause" ::: "memory");
#define read_barrier()	asm volatile ("mf" ::: "memory")

#endif
