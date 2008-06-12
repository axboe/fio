#ifndef FIO_SPINLOCK_H
#define FIO_SPINLOCK_H

struct fio_spinlock {
	spinlock_t slock;
	int lock_fd;
};

extern struct fio_spinlock *fio_spinlock_init(void);
extern void fio_spinlock_remove(struct fio_spinlock *);

static inline void fio_spin_lock(struct fio_spinlock *lock)
{
	spin_lock(&lock->slock);
}

static inline void fio_spin_unlock(struct fio_spinlock *lock)
{
	spin_unlock(&lock->slock);
}

#endif
