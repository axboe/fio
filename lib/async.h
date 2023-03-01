#ifndef FIO_ASYNC_H
#define FIO_ASYNC_H

#include <stdlib.h>
#include <pthread.h>
#include <string.h>

struct fio_completion {
	pthread_mutex_t mutex;
	pthread_cond_t cv;
	int rc;
};

static inline void fio_init_completion(struct fio_completion *cmpl)
{
	memset(cmpl, 0, sizeof(*cmpl));
	if (pthread_mutex_init(&cmpl->mutex, NULL)) {
		abort();
	}
	if (pthread_cond_init(&cmpl->cv, NULL)) {
		abort();
	}
}

static inline void fio_complete(struct fio_completion *cmpl, int rc)
{
	if (pthread_mutex_lock(&cmpl->mutex)) {
		abort();
	}
	cmpl->rc = rc;
	if (pthread_cond_signal(&cmpl->cv)) {
		abort();
	}
	if (pthread_mutex_unlock(&cmpl->mutex)) {
		abort();
	}
}

static inline int fio_wait_for_completion(struct fio_completion *cmpl)
{
	if (pthread_mutex_lock(&cmpl->mutex)) {
		abort();
	}
	if (pthread_cond_wait(&cmpl->cv, &cmpl->mutex)) {
		abort();
	}
	if (pthread_mutex_unlock(&cmpl->mutex)) {
		abort();
	}
	return cmpl->rc;
}

#endif
