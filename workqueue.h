#ifndef FIO_RATE_H
#define FIO_RATE_H

#include "flist.h"

struct workqueue_work {
	struct flist_head list;
};

struct submit_worker {
	pthread_t thread;
	pthread_mutex_t lock;
	pthread_cond_t cond;
	struct flist_head work_list;
	unsigned int flags;
	unsigned int index;
	uint64_t seq;
	struct workqueue *wq;
	void *priv;
	struct sk_out *sk_out;
};

typedef int (workqueue_work_fn)(struct submit_worker *, struct workqueue_work *);
typedef bool (workqueue_pre_sleep_flush_fn)(struct submit_worker *);
typedef void (workqueue_pre_sleep_fn)(struct submit_worker *);
typedef int (workqueue_alloc_worker_fn)(struct submit_worker *);
typedef void (workqueue_free_worker_fn)(struct submit_worker *);
typedef int (workqueue_init_worker_fn)(struct submit_worker *);
typedef void (workqueue_exit_worker_fn)(struct submit_worker *, unsigned int *);
typedef void (workqueue_update_acct_fn)(struct submit_worker *);

struct workqueue_ops {
	workqueue_work_fn *fn;
	workqueue_pre_sleep_flush_fn *pre_sleep_flush_fn;
	workqueue_pre_sleep_fn *pre_sleep_fn;

	workqueue_update_acct_fn *update_acct_fn;

	workqueue_alloc_worker_fn *alloc_worker_fn;
	workqueue_free_worker_fn *free_worker_fn;

	workqueue_init_worker_fn *init_worker_fn;
	workqueue_exit_worker_fn *exit_worker_fn;

	unsigned int nice;
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

int workqueue_init(struct thread_data *td, struct workqueue *wq, struct workqueue_ops *ops, unsigned int max_workers, struct sk_out *sk_out);
void workqueue_exit(struct workqueue *wq);

void workqueue_enqueue(struct workqueue *wq, struct workqueue_work *work);
void workqueue_flush(struct workqueue *wq);

static inline bool workqueue_pre_sleep_check(struct submit_worker *sw)
{
	struct workqueue *wq = sw->wq;

	if (!wq->ops.pre_sleep_flush_fn)
		return false;

	return wq->ops.pre_sleep_flush_fn(sw);
}

static inline void workqueue_pre_sleep(struct submit_worker *sw)
{
	struct workqueue *wq = sw->wq;

	if (wq->ops.pre_sleep_fn)
		wq->ops.pre_sleep_fn(sw);
}

static inline int workqueue_init_worker(struct submit_worker *sw)
{
	struct workqueue *wq = sw->wq;

	if (!wq->ops.init_worker_fn)
		return 0;

	return wq->ops.init_worker_fn(sw);
}

static inline void workqueue_exit_worker(struct submit_worker *sw,
					 unsigned int *sum_cnt)
{
	struct workqueue *wq = sw->wq;
	unsigned int tmp = 1;

	if (!wq->ops.exit_worker_fn)
		return;

	if (!sum_cnt)
		sum_cnt = &tmp;

	wq->ops.exit_worker_fn(sw, sum_cnt);
}
#endif
