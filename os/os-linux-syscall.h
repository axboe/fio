#ifndef FIO_OS_LINUX_SYSCALL_H
#define FIO_OS_LINUX_SYSCALL_H

#include "../arch/arch.h"

/* Linux syscalls for x86 */
#if defined(ARCH_X86_H)
#ifndef __NR_ioprio_set
#define __NR_ioprio_set		289
#define __NR_ioprio_get		290
#endif

#ifndef __NR_fadvise64
#define __NR_fadvise64		250
#endif

#ifndef __NR_sys_splice
#define __NR_sys_splice		313
#define __NR_sys_tee		315
#define __NR_sys_vmsplice	316
#endif

#ifndef __NR_preadv2
#define __NR_preadv2		378
#endif
#ifndef __NR_pwritev2
#define __NR_pwritev2		379
#endif

/* Linux syscalls for x86_64 */
#elif defined(ARCH_X86_64_H)
#ifndef __NR_ioprio_set
#define __NR_ioprio_set		251
#define __NR_ioprio_get		252
#endif

#ifndef __NR_fadvise64
#define __NR_fadvise64		221
#endif

#ifndef __NR_sys_splice
#define __NR_sys_splice		275
#define __NR_sys_tee		276
#define __NR_sys_vmsplice	278
#endif

#ifndef __NR_shmget
#define __NR_shmget		 29
#define __NR_shmat		 30
#define __NR_shmctl		 31
#define __NR_shmdt		 67
#endif

#ifndef __NR_preadv2
#define __NR_preadv2		327
#endif
#ifndef __NR_pwritev2
#define __NR_pwritev2		328
#endif

/* Linux syscalls for ppc */
#elif defined(ARCH_PPC_H)
#ifndef __NR_ioprio_set
#define __NR_ioprio_set		273
#define __NR_ioprio_get		274
#endif

#ifndef __NR_fadvise64
#define __NR_fadvise64		233
#endif

#ifndef __NR_sys_splice
#define __NR_sys_splice		283
#define __NR_sys_tee		284
#define __NR_sys_vmsplice	285
#endif

/* Linux syscalls for ia64 */
#elif defined(ARCH_IA64_H)
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

#ifndef __NR_preadv2
#define __NR_preadv2		1348
#endif
#ifndef __NR_pwritev2
#define __NR_pwritev2		1349
#endif

/* Linux syscalls for alpha */
#elif defined(ARCH_ALPHA_H)
#ifndef __NR_ioprio_set
#define __NR_ioprio_set		442
#define __NR_ioprio_get		443
#endif

#ifndef __NR_fadvise64
#define __NR_fadvise64		413
#endif

#ifndef __NR_sys_splice
#define __NR_sys_splice		468
#define __NR_sys_tee		470
#define __NR_sys_vmsplice	471
#endif

/* Linux syscalls for s390 */
#elif defined(ARCH_S390_H)
#ifndef __NR_ioprio_set
#define __NR_ioprio_set		282
#define __NR_ioprio_get		283
#endif

#ifndef __NR_fadvise64
#define __NR_fadvise64		253
#endif

#ifndef __NR_sys_splice
#define __NR_sys_splice		306
#define __NR_sys_tee		308
#define __NR_sys_vmsplice	309
#endif

#ifndef __NR_preadv2
#define __NR_preadv2		376
#endif
#ifndef __NR_pwritev2
#define __NR_pwritev2		377
#endif

/* Linux syscalls for sparc */
#elif defined(ARCH_SPARC_H)
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

#ifndef __NR_preadv2
#define __NR_preadv2		358
#endif
#ifndef __NR_pwritev2
#define __NR_pwritev2		359
#endif

/* Linux syscalls for sparc64 */
#elif defined(ARCH_SPARC64_H)
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

#ifndef __NR_preadv2
#define __NR_preadv2		358
#endif
#ifndef __NR_pwritev2
#define __NR_pwritev2		359
#endif

/* Linux syscalls for arm */
#elif defined(ARCH_ARM_H)
#ifndef __NR_ioprio_set
#define __NR_ioprio_set		314
#define __NR_ioprio_get		315
#endif

#ifndef __NR_fadvise64
#define __NR_fadvise64		270
#endif

#ifndef __NR_sys_splice
#define __NR_sys_splice		340
#define __NR_sys_tee		342
#define __NR_sys_vmsplice	343
#endif

#ifndef __NR_preadv2
#define __NR_preadv2		392
#endif
#ifndef __NR_pwritev2
#define __NR_pwritev2		393
#endif

/* Linux syscalls for mips */
#elif defined(ARCH_MIPS64_H)
#ifndef __NR_ioprio_set
#define __NR_ioprio_set		314
#define __NR_ioprio_get		315
#endif

#ifndef __NR_fadvise64
#define __NR_fadvise64		215
#endif

#ifndef __NR_sys_splice
#define __NR_sys_splice		263
#define __NR_sys_tee		265
#define __NR_sys_vmsplice	266
#endif

/* Linux syscalls for sh */
#elif defined(ARCH_SH_H)
#ifndef __NR_ioprio_set
#define __NR_ioprio_set		288
#define __NR_ioprio_get		289
#endif

#ifndef __NR_fadvise64
#define __NR_fadvise64		250
#endif

#ifndef __NR_sys_splice
#define __NR_sys_splice		313
#define __NR_sys_tee		315
#define __NR_sys_vmsplice	316
#endif

/* Linux syscalls for hppa */
#elif defined(ARCH_HPPA_H)
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

/* Linux syscalls for aarch64 */
#elif defined(ARCH_AARCH64_H)
#ifndef __NR_ioprio_set
#define __NR_ioprio_set		30
#define __NR_ioprio_get		31
#endif

/* Linux syscalls for loongarch64 */
#elif defined(ARCH_LOONGARCH64_H)
#ifndef __NR_ioprio_set
#define __NR_ioprio_set         30
#define __NR_ioprio_get         31
#endif

#ifndef __NR_fadvise64
#define __NR_fadvise64          223
#endif

#ifndef __NR_sys_splice
#define __NR_sys_splice         76
#define __NR_sys_tee          	77
#define __NR_sys_vmsplice       75
#endif

/* Linux syscalls for riscv64 */
#elif defined(ARCH_RISCV64_H)
#ifndef __NR_ioprio_set
#define __NR_ioprio_set		30
#define __NR_ioprio_get		31
#endif
#else
#warning "Unknown architecture"
#endif

#endif /* FIO_OS_LINUX_SYSCALL_H */
