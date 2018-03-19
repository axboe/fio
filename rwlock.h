#ifndef FIO_RWLOCK_H
#define FIO_RWLOCK_H

#include <pthread.h>

#define FIO_RWLOCK_MAGIC	0x52574c4fU

struct fio_rwlock {
	pthread_rwlock_t lock;
	int magic;
};

extern void fio_rwlock_read(struct fio_rwlock *);
extern void fio_rwlock_write(struct fio_rwlock *);
extern void fio_rwlock_unlock(struct fio_rwlock *);
extern struct fio_rwlock *fio_rwlock_init(void);
extern void fio_rwlock_remove(struct fio_rwlock *);

#endif
