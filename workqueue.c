/*
 * Generic workqueue offload mechanism
 *
 * Copyright (C) 2015 Jens Axboe <axboe@kernel.dk>
 *
 */
#include <unistd.h>

#include "fio.h"
#include "flist.h"
#include "workqueue.h"
#include "smalloc.h"

enum {
	SW_F_IDLE	= 1 << 0,
	SW_F_RUNNING	= 1 << 1,
	SW_F_EXIT	= 1 << 2,
	SW_F_ACCOUNTED	= 1 << 3,
	SW_F_ERROR	= 1 << 4,
};

static struct submit_worker *__get_submit_worker(struct workqueue *wq,
						 unsigned int start,
						 unsigned int end,
						 struct submit_worker **best)
{
	struct submit_worker *sw = NULL;

	while (start <= end) {
		sw = &wq->workers[start];
		if (sw->flags & SW_F_IDLE)
			return sw;
		if (!(*best) || sw->seq < (*best)->seq)
			*best = sw;
		start++;
	}

	return NULL;
}

static struct submit_worker *get_submit_worker(struct workqueue *wq)
{
	unsigned int next = wq->next_free_worker;
	struct submit_worker *sw, *best = NULL;

	assert(next < wq->max_workers);

	sw = __get_submit_worker(wq, next, wq->max_workers - 1, &best);
	if (!sw && next)
		sw = __get_submit_worker(wq, 0, next - 1, &best);

	/*
	 * No truly idle found, use best match
	 */
	if (!sw)
		sw = best;

	if (sw->index == wq->next_free_worker) {
		if (sw->index + 1 < wq->max_workers)
			wq->next_free_worker = sw->index + 1;
		else
			wq->next_free_worker = 0;
	}

	return sw;
}

static bool all_sw_idle(struct workqueue *wq)
{
	int i;

	for (i = 0; i < wq->max_workers; i++) {
		struct submit_worker *sw = &wq->workers[i];

		if (!(sw->flags & SW_F_IDLE))
			return false;
	}

	return true;
}

/*
 * Must be serialized wrt workqueue_enqueue() by caller
 */
void workqueue_flush(struct workqueue *wq)
{
	wq->wake_idle = 1;

	while (!all_sw_idle(wq)) {
		pthread_mutex_lock(&wq->flush_lock);
		pthread_cond_wait(&wq->flush_cond, &wq->flush_lock);
		pthread_mutex_unlock(&wq->flush_lock);
	}

	wq->wake_idle = 0;
}

/*
 * Must be serialized by caller. Returns true for queued, false for busy.
 */
void workqueue_enqueue(struct workqueue *wq, struct workqueue_work *work)
{
	struct submit_worker *sw;

	sw = get_submit_worker(wq);
	assert(sw);

	pthread_mutex_lock(&sw->lock);
	flist_add_tail(&work->list, &sw->work_list);
	sw->seq = ++wq->work_seq;
	sw->flags &= ~SW_F_IDLE;
	pthread_mutex_unlock(&sw->lock);

	pthread_cond_signal(&sw->cond);
}

static void handle_list(struct submit_worker *sw, struct flist_head *list)
{
	struct workqueue *wq = sw->wq;
	struct workqueue_work *work;

	while (!flist_empty(list)) {
		work = flist_first_entry(list, struct workqueue_work, list);
		flist_del_init(&work->list);
		wq->ops.fn(sw, work);
	}
}

static void *worker_thread(void *data)
{
	struct submit_worker *sw = data;
	struct workqueue *wq = sw->wq;
	unsigned int ret = 0;
	FLIST_HEAD(local_list);

	sk_out_assign(sw->sk_out);

	if (wq->ops.nice) {
		if (nice(wq->ops.nice) < 0) {
			log_err("workqueue: nice %s\n", strerror(errno));
			ret = 1;
		}
	}

	if (!ret)
		ret = workqueue_init_worker(sw);

	pthread_mutex_lock(&sw->lock);
	sw->flags |= SW_F_RUNNING;
	if (ret)
		sw->flags |= SW_F_ERROR;
	pthread_mutex_unlock(&sw->lock);

	pthread_mutex_lock(&wq->flush_lock);
	pthread_cond_signal(&wq->flush_cond);
	pthread_mutex_unlock(&wq->flush_lock);

	if (sw->flags & SW_F_ERROR)
		goto done;

	while (1) {
		pthread_mutex_lock(&sw->lock);

		if (flist_empty(&sw->work_list)) {
			if (sw->flags & SW_F_EXIT) {
				pthread_mutex_unlock(&sw->lock);
				break;
			}

			if (workqueue_pre_sleep_check(sw)) {
				pthread_mutex_unlock(&sw->lock);
				workqueue_pre_sleep(sw);
				pthread_mutex_lock(&sw->lock);
			}

			/*
			 * We dropped and reaquired the lock, check
			 * state again.
			 */
			if (!flist_empty(&sw->work_list))
				goto handle_work;

			if (sw->flags & SW_F_EXIT) {
				pthread_mutex_unlock(&sw->lock);
				break;
			} else if (!(sw->flags & SW_F_IDLE)) {
				sw->flags |= SW_F_IDLE;
				wq->next_free_worker = sw->index;
				if (wq->wake_idle)
					pthread_cond_signal(&wq->flush_cond);
			}
			if (wq->ops.update_acct_fn)
				wq->ops.update_acct_fn(sw);

			pthread_cond_wait(&sw->cond, &sw->lock);
		} else {
handle_work:
			flist_splice_init(&sw->work_list, &local_list);
		}
		pthread_mutex_unlock(&sw->lock);
		handle_list(sw, &local_list);
	}

	if (wq->ops.update_acct_fn)
		wq->ops.update_acct_fn(sw);

done:
	sk_out_drop();
	return NULL;
}

static void free_worker(struct submit_worker *sw, unsigned int *sum_cnt)
{
	struct workqueue *wq = sw->wq;

	workqueue_exit_worker(sw, sum_cnt);

	pthread_cond_destroy(&sw->cond);
	pthread_mutex_destroy(&sw->lock);

	if (wq->ops.free_worker_fn)
		wq->ops.free_worker_fn(sw);
}

static void shutdown_worker(struct submit_worker *sw, unsigned int *sum_cnt)
{
	pthread_join(sw->thread, NULL);
	free_worker(sw, sum_cnt);
}

void workqueue_exit(struct workqueue *wq)
{
	unsigned int shutdown, sum_cnt = 0;
	struct submit_worker *sw;
	int i;

	if (!wq->workers)
		return;

	for (i = 0; i < wq->max_workers; i++) {
		sw = &wq->workers[i];

		pthread_mutex_lock(&sw->lock);
		sw->flags |= SW_F_EXIT;
		pthread_cond_signal(&sw->cond);
		pthread_mutex_unlock(&sw->lock);
	}

	do {
		shutdown = 0;
		for (i = 0; i < wq->max_workers; i++) {
			sw = &wq->workers[i];
			if (sw->flags & SW_F_ACCOUNTED)
				continue;
			pthread_mutex_lock(&sw->lock);
			sw->flags |= SW_F_ACCOUNTED;
			pthread_mutex_unlock(&sw->lock);
			shutdown_worker(sw, &sum_cnt);
			shutdown++;
		}
	} while (shutdown && shutdown != wq->max_workers);

	sfree(wq->workers);
	wq->workers = NULL;
	pthread_mutex_destroy(&wq->flush_lock);
	pthread_cond_destroy(&wq->flush_cond);
	pthread_mutex_destroy(&wq->stat_lock);
}

static int start_worker(struct workqueue *wq, unsigned int index,
			struct sk_out *sk_out)
{
	struct submit_worker *sw = &wq->workers[index];
	int ret;

	INIT_FLIST_HEAD(&sw->work_list);

	ret = mutex_cond_init_pshared(&sw->lock, &sw->cond);
	if (ret)
		return ret;

	sw->wq = wq;
	sw->index = index;
	sw->sk_out = sk_out;

	if (wq->ops.alloc_worker_fn) {
		ret = wq->ops.alloc_worker_fn(sw);
		if (ret)
			return ret;
	}

	ret = pthread_create(&sw->thread, NULL, worker_thread, sw);
	if (!ret) {
		pthread_mutex_lock(&sw->lock);
		sw->flags = SW_F_IDLE;
		pthread_mutex_unlock(&sw->lock);
		return 0;
	}

	free_worker(sw, NULL);
	return 1;
}

int workqueue_init(struct thread_data *td, struct workqueue *wq,
		   struct workqueue_ops *ops, unsigned int max_workers,
		   struct sk_out *sk_out)
{
	unsigned int running;
	int i, error;
	int ret;

	wq->max_workers = max_workers;
	wq->td = td;
	wq->ops = *ops;
	wq->work_seq = 0;
	wq->next_free_worker = 0;

	ret = mutex_cond_init_pshared(&wq->flush_lock, &wq->flush_cond);
	if (ret)
		goto err;
	ret = mutex_init_pshared(&wq->stat_lock);
	if (ret)
		goto err;

	wq->workers = smalloc(wq->max_workers * sizeof(struct submit_worker));
	if (!wq->workers)
		goto err;

	for (i = 0; i < wq->max_workers; i++)
		if (start_worker(wq, i, sk_out))
			break;

	wq->max_workers = i;
	if (!wq->max_workers)
		goto err;

	/*
	 * Wait for them all to be started and initialized
	 */
	error = 0;
	do {
		struct submit_worker *sw;

		running = 0;
		pthread_mutex_lock(&wq->flush_lock);
		for (i = 0; i < wq->max_workers; i++) {
			sw = &wq->workers[i];
			pthread_mutex_lock(&sw->lock);
			if (sw->flags & SW_F_RUNNING)
				running++;
			if (sw->flags & SW_F_ERROR)
				error++;
			pthread_mutex_unlock(&sw->lock);
		}

		if (error || running == wq->max_workers) {
			pthread_mutex_unlock(&wq->flush_lock);
			break;
		}

		pthread_cond_wait(&wq->flush_cond, &wq->flush_lock);
		pthread_mutex_unlock(&wq->flush_lock);
	} while (1);

	if (!error)
		return 0;

err:
	log_err("Can't create rate workqueue\n");
	td_verror(td, ESRCH, "workqueue_init");
	workqueue_exit(wq);
	return 1;
}
