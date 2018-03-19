#ifndef FIO_SEM_H
#define FIO_SEM_H

#include <pthread.h>
#include "lib/types.h"

#define FIO_SEM_MAGIC		0x4d555445U

struct fio_sem {
	pthread_mutex_t lock;
	pthread_cond_t cond;
	int value;
	int waiters;
	int magic;
};

enum {
	FIO_SEM_LOCKED	= 0,
	FIO_SEM_UNLOCKED	= 1,
};

extern int __fio_sem_init(struct fio_sem *, int);
extern struct fio_sem *fio_sem_init(int);
extern void __fio_sem_remove(struct fio_sem *);
extern void fio_sem_remove(struct fio_sem *);
extern void fio_sem_up(struct fio_sem *);
extern void fio_sem_down(struct fio_sem *);
extern bool fio_sem_down_trylock(struct fio_sem *);
extern int fio_sem_down_timeout(struct fio_sem *, unsigned int);

#endif
