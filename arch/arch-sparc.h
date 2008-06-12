#ifndef ARCH_SPARC_H
#define ARCH_SPARC_H

#define ARCH	(arch_sparc)

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

#define read_barrier()	__asm__ __volatile__ ("" : : : "memory")
#define write_barrier()	__asm__ __volatile__ ("" : : : "memory")

typedef struct {
	volatile unsigned char lock;
} spinlock_t;

static inline void spin_lock(spinlock_t *lock)
{
	__asm__ __volatile__(
		"\n1:\n\t"
		"ldstub	[%0], %%g2\n\t"
		"orcc	%%g2, 0x0, %%g0\n\t"
		"bne,a	2f\n\t"
		" ldub	[%0], %%g2\n\t"
		".subsection	2\n"
		"2:\n\t"
		"orcc	%%g2, 0x0, %%g0\n\t"
		"bne,a	2b\n\t"
		" ldub	[%0], %%g2\n\t"
		"b,a	1b\n\t"
		".previous\n"
		: /* no outputs */
		: "r" (lock)
		: "g2", "memory", "cc");
}

static inline void spin_unlock(spinlock_t *lock)
{
	__asm__ __volatile__("stb %%g0, [%0]" : : "r" (lock) : "memory");
}

#endif
