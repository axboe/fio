#ifndef ARCH_S390_H
#define ARCH_S390_H

#define ARCH	(arch_s390)

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

#define nop		asm volatile ("diag 0,0,68" : : : "memory")
#define read_barrier()	asm volatile("bcr 15,0" : : : "memory")
#define write_barrier()	asm volatile("bcr 15,0" : : : "memory")

typedef struct {
	volatile unsigned int lock;
} spinlock_t;

static inline int
_raw_compare_and_swap(volatile unsigned int *lock,
		      unsigned int old, unsigned int new)
{
	__asm__ __volatile__(
		"       cs      %0,%3,0(%4)"
		: "=d" (old), "=m" (*lock)
		: "0" (old), "d" (new), "a" (lock), "m" (*lock)
		: "cc", "memory" );

	return old;
}

static inline void spin_lock(spinlock_t *lock)
{
	if (!_raw_compare_and_swap(&lock->lock, 0, 0x80000000))
		return;

	while (1) {
		if (lock->lock)
			continue;
		if (!_raw_compare_and_swap(&lock->lock, 0, 0x80000000))
			break;
	}
}

static inline void spin_unlock(spinlock_t *lock)
{
	 _raw_compare_and_swap(&lock->lock, 0x80000000, 0);
}

#endif
