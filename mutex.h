#ifndef FIO_MUTEX_H
#define FIO_MUTEX_H

#include <pthread.h>

struct fio_sem {
	pthread_mutex_t lock;
	pthread_cond_t cond;
	unsigned int value;

	char sem_name[32];
};

extern struct fio_sem *fio_sem_init(int);
extern void fio_sem_remove(struct fio_sem *);
extern inline void fio_sem_down(struct fio_sem *);
extern inline void fio_sem_up(struct fio_sem *sem);

#endif
