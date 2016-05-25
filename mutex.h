#ifndef FIO_MUTEX_H
#define FIO_MUTEX_H

#include <pthread.h>
#include "lib/types.h"

#define FIO_MUTEX_MAGIC		0x4d555445U
#define FIO_RWLOCK_MAGIC	0x52574c4fU

struct fio_mutex {
	pthread_mutex_t lock;
	pthread_cond_t cond;
	int value;
	int waiters;
	int magic;
};

struct fio_rwlock {
	pthread_rwlock_t lock;
	int magic;
};

enum {
	FIO_MUTEX_LOCKED	= 0,
	FIO_MUTEX_UNLOCKED	= 1,
};

extern int __fio_mutex_init(struct fio_mutex *, int);
extern struct fio_mutex *fio_mutex_init(int);
extern void __fio_mutex_remove(struct fio_mutex *);
extern void fio_mutex_remove(struct fio_mutex *);
extern void fio_mutex_up(struct fio_mutex *);
extern void fio_mutex_down(struct fio_mutex *);
extern bool fio_mutex_down_trylock(struct fio_mutex *);
extern int fio_mutex_down_timeout(struct fio_mutex *, unsigned int);

extern void fio_rwlock_read(struct fio_rwlock *);
extern void fio_rwlock_write(struct fio_rwlock *);
extern void fio_rwlock_unlock(struct fio_rwlock *);
extern struct fio_rwlock *fio_rwlock_init(void);
extern void fio_rwlock_remove(struct fio_rwlock *);

extern int mutex_init_pshared(pthread_mutex_t *);
extern int cond_init_pshared(pthread_cond_t *);
extern int mutex_cond_init_pshared(pthread_mutex_t *, pthread_cond_t *);

#endif
