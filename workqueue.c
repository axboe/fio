/*
 * Rated submission helpers
 *
 * Copyright (C) 2015 Jens Axboe <axboe@kernel.dk>
 *
 */
#include <unistd.h>

#include "fio.h"
#include "ioengine.h"
#include "flist.h"
#include "workqueue.h"
#include "lib/getrusage.h"

struct submit_worker {
	pthread_t thread;
	pthread_mutex_t lock;
	pthread_cond_t cond;
	struct flist_head work_list;
	unsigned int flags;
	unsigned int index;
	uint64_t seq;
	struct workqueue *wq;
	struct thread_data td;
};

enum {
	SW_F_IDLE	= 1 << 0,
	SW_F_RUNNING	= 1 << 1,
	SW_F_EXIT	= 1 << 2,
	SW_F_EXITED	= 1 << 3,
	SW_F_ACCOUNTED	= 1 << 4,
	SW_F_ERROR	= 1 << 5,
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

static int all_sw_idle(struct workqueue *wq)
{
	int i;

	for (i = 0; i < wq->max_workers; i++) {
		struct submit_worker *sw = &wq->workers[i];

		if (!(sw->flags & SW_F_IDLE))
			return 0;
	}

	return 1;
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
 * Must be serialized by caller.
 */
int workqueue_enqueue(struct workqueue *wq, struct io_u *io_u)
{
	struct submit_worker *sw;

	sw = get_submit_worker(wq);
	if (sw) {
		const enum fio_ddir ddir = acct_ddir(io_u);
		struct thread_data *parent = wq->td;

		if (ddir_rw(ddir)) {
			parent->io_issues[ddir]++;
			parent->io_issue_bytes[ddir] += io_u->xfer_buflen;
		}

		pthread_mutex_lock(&sw->lock);
		flist_add_tail(&io_u->verify_list, &sw->work_list);
		sw->seq = ++wq->work_seq;
		sw->flags &= ~SW_F_IDLE;
		pthread_mutex_unlock(&sw->lock);

		pthread_cond_signal(&sw->cond);
		return FIO_Q_QUEUED;
	}

	return FIO_Q_BUSY;
}

static void handle_list(struct submit_worker *sw, struct flist_head *list)
{
	struct workqueue *wq = sw->wq;
	struct io_u *io_u;

	while (!flist_empty(list)) {
		io_u = flist_first_entry(list, struct io_u, verify_list);
		flist_del_init(&io_u->verify_list);
		wq->fn(&sw->td, io_u);
	}
}

static int init_submit_worker(struct submit_worker *sw)
{
	struct thread_data *parent = sw->wq->td;
	struct thread_data *td = &sw->td;
	int fio_unused ret;

	memcpy(&td->o, &parent->o, sizeof(td->o));
	memcpy(&td->ts, &parent->ts, sizeof(td->ts));
	td->o.uid = td->o.gid = -1U;
	dup_files(td, parent);
	fio_options_mem_dupe(td);

	if (ioengine_load(td))
		goto err;

	if (td->o.odirect)
		td->io_ops->flags |= FIO_RAWIO;

	td->pid = gettid();

	INIT_FLIST_HEAD(&td->io_log_list);
	INIT_FLIST_HEAD(&td->io_hist_list);
	INIT_FLIST_HEAD(&td->verify_list);
	INIT_FLIST_HEAD(&td->trim_list);
	INIT_FLIST_HEAD(&td->next_rand_list);
	td->io_hist_tree = RB_ROOT;

	td->o.iodepth = 1;
	if (td_io_init(td))
		goto err_io_init;

	fio_gettime(&td->epoch, NULL);
	fio_getrusage(&td->ru_start);
	clear_io_state(td);

	td_set_runstate(td, TD_RUNNING);
	td->flags |= TD_F_CHILD;
	td->parent = parent;
	return 0;

err_io_init:
	close_ioengine(td);
err:
	return 1;
}

static void sum_val(uint64_t *dst, uint64_t *src)
{
	if (*src) {
		__sync_fetch_and_add(dst, *src);
		*src = 0;
	}
}

static void sum_ddir(struct thread_data *dst, struct thread_data *src,
		     enum fio_ddir ddir)
{
	sum_val(&dst->io_bytes[ddir], &src->io_bytes[ddir]);
	sum_val(&dst->io_blocks[ddir], &src->io_blocks[ddir]);
	sum_val(&dst->this_io_blocks[ddir], &src->this_io_blocks[ddir]);
	sum_val(&dst->this_io_bytes[ddir], &src->this_io_bytes[ddir]);
	sum_val(&dst->bytes_done[ddir], &src->bytes_done[ddir]);
}

static void update_accounting(struct submit_worker *sw)
{
	struct thread_data *src = &sw->td;
	struct thread_data *dst = sw->wq->td;

	if (td_read(src))
		sum_ddir(dst, src, DDIR_READ);
	if (td_write(src))
		sum_ddir(dst, src, DDIR_WRITE);
	if (td_trim(src))
		sum_ddir(dst, src, DDIR_TRIM);
}

static void *worker_thread(void *data)
{
	struct submit_worker *sw = data;
	struct workqueue *wq = sw->wq;
	struct thread_data *td = &sw->td;
	unsigned int eflags = 0, ret;
	FLIST_HEAD(local_list);

	ret = init_submit_worker(sw);
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

			if (td->io_u_queued || td->cur_depth ||
			    td->io_u_in_flight) {
				pthread_mutex_unlock(&sw->lock);
				io_u_quiesce(td);
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
			update_accounting(sw);
			pthread_cond_wait(&sw->cond, &sw->lock);
		} else {
handle_work:
			flist_splice_init(&sw->work_list, &local_list);
		}
		pthread_mutex_unlock(&sw->lock);
		handle_list(sw, &local_list);
	}

	update_accounting(sw);

done:
	pthread_mutex_lock(&sw->lock);
	sw->flags |= (SW_F_EXITED | eflags);
	pthread_mutex_unlock(&sw->lock);
	return NULL;
}

static void free_worker(struct submit_worker *sw)
{
	struct thread_data *td = &sw->td;

	fio_options_free(td);
	close_and_free_files(td);
	if (td->io_ops)
		close_ioengine(td);
	td_set_runstate(td, TD_EXITED);

	pthread_cond_destroy(&sw->cond);
	pthread_mutex_destroy(&sw->lock);
}

static void shutdown_worker(struct submit_worker *sw, unsigned int *sum_cnt)
{
	struct thread_data *parent = sw->wq->td;

	pthread_join(sw->thread, NULL);
	(*sum_cnt)++;
	sum_thread_stats(&parent->ts, &sw->td.ts, *sum_cnt);
	free_worker(sw);
}

void workqueue_exit(struct workqueue *wq)
{
	unsigned int shutdown, sum_cnt = 0;
	struct submit_worker *sw;
	int i;

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
			sw->flags |= SW_F_ACCOUNTED;
			shutdown_worker(sw, &sum_cnt);
			shutdown++;
		}
	} while (shutdown && shutdown != wq->max_workers);

	free(wq->workers);
	pthread_mutex_destroy(&wq->flush_lock);
	pthread_cond_destroy(&wq->flush_cond);
}

static int start_worker(struct workqueue *wq, unsigned int index)
{
	struct submit_worker *sw = &wq->workers[index];
	int ret;

	INIT_FLIST_HEAD(&sw->work_list);
	pthread_cond_init(&sw->cond, NULL);
	pthread_mutex_init(&sw->lock, NULL);
	sw->wq = wq;
	sw->index = index;

	ret = pthread_create(&sw->thread, NULL, worker_thread, sw);
	if (!ret) {
		pthread_mutex_lock(&sw->lock);
		sw->flags = SW_F_IDLE;
		pthread_mutex_unlock(&sw->lock);
		return 0;
	}

	free_worker(sw);
	return 1;
}

int workqueue_init(struct thread_data *td, struct workqueue *wq,
		   workqueue_fn *fn, unsigned max_pending)
{
	unsigned int running;
	int i, error;

	wq->max_workers = max_pending;
	wq->td = td;
	wq->fn = fn;
	wq->work_seq = 0;
	wq->next_free_worker = 0;
	pthread_cond_init(&wq->flush_cond, NULL);
	pthread_mutex_init(&wq->flush_lock, NULL);

	wq->workers = calloc(wq->max_workers, sizeof(struct submit_worker));

	for (i = 0; i < wq->max_workers; i++)
		if (start_worker(wq, i))
			break;

	wq->max_workers = i;
	if (!wq->max_workers) {
err:
		log_err("Can't create rate workqueue\n");
		td_verror(td, ESRCH, "workqueue_init");
		workqueue_exit(wq);
		return 1;
	}

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

	if (error)
		goto err;

	return 0;
}
