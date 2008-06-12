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
#define writebarrier()	asm volatile ("mf" ::: "memory")

#define ia64_popcnt(x)							\
({									\
	unsigned long ia64_intri_res;					\
	asm ("popcnt %0=%1" : "=r" (ia64_intri_res) : "r" (x));		\
	ia64_intri_res;							\
})

static inline unsigned long arch_ffz(unsigned long bitmask)
{
	return ia64_popcnt(bitmask & (~bitmask - 1));
}
#define ARCH_HAVE_FFZ

typedef struct {
	volatile unsigned int lock;
} spinlock_t;

#define IA64_SPINLOCK_CLOBBERS "ar.ccv", "ar.pfs", "p14", "p15", "r27", "r28", "r29", "r30", "b6", "memory"

static inline void spin_lock(spinlock_t *lock)
{
	register volatile unsigned int *ptr asm ("r31") = &lock->lock;
	unsigned long flags = 0;

	__asm__ __volatile__("{\n\t"
			"  mov ar.ccv = r0\n\t"
			"  mov r28 = ip\n\t"
			"  mov r30 = 1;;\n\t"
			"}\n\t"
			"cmpxchg4.acq r30 = [%1], r30, ar.ccv\n\t"
			"movl r29 = ia64_spinlock_contention_pre3_4;;\n\t"
			"cmp4.ne p14, p0 = r30, r0\n\t"
			"mov b6 = r29;;\n\t"
			"mov r27=%2\n\t"
			"(p14) br.cond.spnt.many b6"
			: "=r"(ptr) : "r"(ptr), "r" (flags)
			: IA64_SPINLOCK_CLOBBERS);
}

static inline void spin_unlock(spinlock_t *lock)
{
	read_barrier();
	__asm__ __volatile__("st4.rel.nta [%0] = r0\n\t" :: "r" (lock));
}

#endif
