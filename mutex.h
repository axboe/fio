#ifndef FIO_MUTEX_H
#define FIO_MUTEX_H

#include <pthread.h>

struct fio_mutex {
	pthread_mutex_t lock;
	pthread_cond_t cond;
	unsigned int value;

	int mutex_fd;
};

extern struct fio_mutex *fio_mutex_init(int);
extern void fio_mutex_remove(struct fio_mutex *);
extern inline void fio_mutex_down(struct fio_mutex *);
extern inline void fio_mutex_up(struct fio_mutex *);

#endif
