#ifndef FIO_RATE_H
#define FIO_RATE_H

#include "flist.h"

struct workqueue_work {
	struct flist_head list;
};

typedef void (workqueue_work_fn)(struct thread_data *, struct workqueue_work *);
typedef bool (workqueue_pre_sleep_flush_fn)(struct thread_data *);
typedef void (workqueue_pre_sleep_fn)(struct thread_data *);

struct workqueue_ops {
	workqueue_work_fn *fn;
	workqueue_pre_sleep_flush_fn *pre_sleep_flush_fn;
	workqueue_pre_sleep_fn *pre_sleep_fn;
};

struct workqueue {
	unsigned int max_workers;

	struct thread_data *td;
	struct workqueue_ops ops;

	uint64_t work_seq;
	struct submit_worker *workers;
	unsigned int next_free_worker;

	pthread_cond_t flush_cond;
	pthread_mutex_t flush_lock;
	pthread_mutex_t stat_lock;
	volatile int wake_idle;
};

int workqueue_init(struct thread_data *td, struct workqueue *wq, struct workqueue_ops *ops, unsigned int max_workers);
void workqueue_exit(struct workqueue *wq);

bool workqueue_enqueue(struct workqueue *wq, struct workqueue_work *work);
void workqueue_flush(struct workqueue *wq);

static inline bool workqueue_pre_sleep_check(struct workqueue *wq)
{
	if (!wq->ops.pre_sleep_flush_fn)
		return false;

	return wq->ops.pre_sleep_flush_fn(wq->td);
}

static inline void workqueue_pre_sleep(struct workqueue *wq)
{
	if (wq->ops.pre_sleep_fn)
		wq->ops.pre_sleep_fn(wq->td);
}

#endif
