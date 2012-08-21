#ifndef FIO_MUTEX_H
#define FIO_MUTEX_H

#include <pthread.h>

struct fio_mutex {
	pthread_mutex_t lock;
	pthread_cond_t cond;
	int value;
	int waiters;
};

enum {
	FIO_MUTEX_LOCKED	= 0,
	FIO_MUTEX_UNLOCKED	= 1,
};

extern struct fio_mutex *fio_mutex_init(int);
extern void fio_mutex_remove(struct fio_mutex *);
extern void fio_mutex_down(struct fio_mutex *);
extern int fio_mutex_down_timeout(struct fio_mutex *, unsigned int);
extern void fio_mutex_down_read(struct fio_mutex *);
extern void fio_mutex_down_write(struct fio_mutex *);
extern void fio_mutex_up(struct fio_mutex *);
extern void fio_mutex_up_read(struct fio_mutex *);
extern void fio_mutex_up_write(struct fio_mutex *);

static inline struct fio_mutex *fio_mutex_rw_init(void)
{
	return fio_mutex_init(0);
}

static inline int fio_mutex_getval(struct fio_mutex *mutex)
{
	return mutex->value;
}

#endif
