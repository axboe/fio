#ifndef ARCH_ALPHA_H
#define ARCH_ALPHA_H

#define ARCH	(arch_alpha)

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

#define nop			do { } while (0)
#define read_barrier()		__asm__ __volatile__("mb": : :"memory")
#define writer_barrier()	__asm__ __volatile__("wmb": : :"memory")

typedef struct {
	volatile unsigned int lock;
} spinlock_t;

static inline void spin_lock(spinlock_t *lock)
{
	long tmp;

	__asm__ __volatile__("1:     ldl_l   %0,%1\n"
			"       bne     %0,2f\n"
			"       lda     %0,1\n"
			"       stl_c   %0,%1\n"
			"       beq     %0,2f\n"
			"       mb\n"
			".subsection 2\n"
			"2:     ldl     %0,%1\n"
			"       bne     %0,2b\n"
			"       br      1b\n"
			".previous"
			: "=&r" (tmp), "=m" (lock->lock)
			: "m"(lock->lock) : "memory");
}

static inline void spin_unlock(spinlock_t *lock)
{
	read_barrier();
	lock->lock = 0;
}

#define __SPIN_LOCK_UNLOCKED	{ 0 }

#endif
