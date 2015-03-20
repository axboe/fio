#ifndef FIO_RATE_H
#define FIO_RATE_H

#include "flist.h"

typedef void (workqueue_fn)(struct thread_data *, struct io_u *);

struct workqueue {
	unsigned int max_workers;

	struct thread_data *td;
	workqueue_fn *fn;

	uint64_t work_seq;
	struct submit_worker *workers;
	unsigned int next_free_worker;

	pthread_cond_t flush_cond;
	pthread_mutex_t flush_lock;
	volatile int wake_idle;
};

int workqueue_init(struct thread_data *td, struct workqueue *wq, workqueue_fn *fn, unsigned int max_workers);
void workqueue_exit(struct workqueue *wq);

int workqueue_enqueue(struct workqueue *wq, struct io_u *io_u);
void workqueue_flush(struct workqueue *wq);

#endif
