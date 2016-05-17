/*
 * Rated submission helpers
 *
 * Copyright (C) 2015 Jens Axboe <axboe@kernel.dk>
 *
 */
#include "fio.h"
#include "ioengine.h"
#include "lib/getrusage.h"
#include "rate-submit.h"

static int io_workqueue_fn(struct submit_worker *sw,
			   struct workqueue_work *work)
{
	struct io_u *io_u = container_of(work, struct io_u, work);
	const enum fio_ddir ddir = io_u->ddir;
	struct thread_data *td = sw->private;
	int ret;

	dprint(FD_RATE, "io_u %p queued by %u\n", io_u, gettid());

	io_u_set(io_u, IO_U_F_NO_FILE_PUT);

	td->cur_depth++;

	do {
		ret = td_io_queue(td, io_u);
		if (ret != FIO_Q_BUSY)
			break;
		ret = io_u_queued_complete(td, 1);
		if (ret > 0)
			td->cur_depth -= ret;
		io_u_clear(io_u, IO_U_F_FLIGHT);
	} while (1);

	dprint(FD_RATE, "io_u %p ret %d by %u\n", io_u, ret, gettid());

	io_queue_event(td, io_u, &ret, ddir, NULL, 0, NULL);

	if (ret == FIO_Q_COMPLETED)
		td->cur_depth--;
	else if (ret == FIO_Q_QUEUED) {
		unsigned int min_evts;

		if (td->o.iodepth == 1)
			min_evts = 1;
		else
			min_evts = 0;

		ret = io_u_queued_complete(td, min_evts);
		if (ret > 0)
			td->cur_depth -= ret;
	} else if (ret == FIO_Q_BUSY) {
		ret = io_u_queued_complete(td, td->cur_depth);
		if (ret > 0)
			td->cur_depth -= ret;
	}

	return 0;
}

static bool io_workqueue_pre_sleep_flush_fn(struct submit_worker *sw)
{
	struct thread_data *td = sw->private;

	if (td->io_u_queued || td->cur_depth || td->io_u_in_flight)
		return true;

	return false;
}

static void io_workqueue_pre_sleep_fn(struct submit_worker *sw)
{
	struct thread_data *td = sw->private;
	int ret;

	ret = io_u_quiesce(td);
	if (ret > 0)
		td->cur_depth -= ret;
}

static int io_workqueue_alloc_fn(struct submit_worker *sw)
{
	struct thread_data *td;

	td = calloc(1, sizeof(*td));
	sw->private = td;
	return 0;
}

static void io_workqueue_free_fn(struct submit_worker *sw)
{
	free(sw->private);
	sw->private = NULL;
}

static int io_workqueue_init_worker_fn(struct submit_worker *sw)
{
	struct thread_data *parent = sw->wq->td;
	struct thread_data *td = sw->private;
	int fio_unused ret;

	memcpy(&td->o, &parent->o, sizeof(td->o));
	memcpy(&td->ts, &parent->ts, sizeof(td->ts));
	td->o.uid = td->o.gid = -1U;
	dup_files(td, parent);
	td->eo = parent->eo;
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
	clear_io_state(td, 1);

	td_set_runstate(td, TD_RUNNING);
	td->flags |= TD_F_CHILD;
	td->parent = parent;
	return 0;

err_io_init:
	close_ioengine(td);
err:
	return 1;

}

static void io_workqueue_exit_worker_fn(struct submit_worker *sw,
					unsigned int *sum_cnt)
{
	struct thread_data *td = sw->private;

	(*sum_cnt)++;
	sum_thread_stats(&sw->wq->td->ts, &td->ts, *sum_cnt == 1);

	fio_options_free(td);
	close_and_free_files(td);
	if (td->io_ops)
		close_ioengine(td);
	td_set_runstate(td, TD_EXITED);
}

#ifdef CONFIG_SFAA
static void sum_val(uint64_t *dst, uint64_t *src)
{
	if (*src) {
		__sync_fetch_and_add(dst, *src);
		*src = 0;
	}
}
#else
static void sum_val(uint64_t *dst, uint64_t *src)
{
	if (*src) {
		*dst += *src;
		*src = 0;
	}
}
#endif

static void pthread_double_unlock(pthread_mutex_t *lock1,
				  pthread_mutex_t *lock2)
{
#ifndef CONFIG_SFAA
	pthread_mutex_unlock(lock1);
	pthread_mutex_unlock(lock2);
#endif
}

static void pthread_double_lock(pthread_mutex_t *lock1, pthread_mutex_t *lock2)
{
#ifndef CONFIG_SFAA
	if (lock1 < lock2) {
		pthread_mutex_lock(lock1);
		pthread_mutex_lock(lock2);
	} else {
		pthread_mutex_lock(lock2);
		pthread_mutex_lock(lock1);
	}
#endif
}

static void sum_ddir(struct thread_data *dst, struct thread_data *src,
		     enum fio_ddir ddir)
{
	pthread_double_lock(&dst->io_wq.stat_lock, &src->io_wq.stat_lock);

	sum_val(&dst->io_bytes[ddir], &src->io_bytes[ddir]);
	sum_val(&dst->io_blocks[ddir], &src->io_blocks[ddir]);
	sum_val(&dst->this_io_blocks[ddir], &src->this_io_blocks[ddir]);
	sum_val(&dst->this_io_bytes[ddir], &src->this_io_bytes[ddir]);
	sum_val(&dst->bytes_done[ddir], &src->bytes_done[ddir]);

	pthread_double_unlock(&dst->io_wq.stat_lock, &src->io_wq.stat_lock);
}

static void io_workqueue_update_acct_fn(struct submit_worker *sw)
{
	struct thread_data *src = sw->private;
	struct thread_data *dst = sw->wq->td;

	if (td_read(src))
		sum_ddir(dst, src, DDIR_READ);
	if (td_write(src))
		sum_ddir(dst, src, DDIR_WRITE);
	if (td_trim(src))
		sum_ddir(dst, src, DDIR_TRIM);

}

static struct workqueue_ops rated_wq_ops = {
	.fn			= io_workqueue_fn,
	.pre_sleep_flush_fn	= io_workqueue_pre_sleep_flush_fn,
	.pre_sleep_fn		= io_workqueue_pre_sleep_fn,
	.update_acct_fn		= io_workqueue_update_acct_fn,
	.alloc_worker_fn	= io_workqueue_alloc_fn,
	.free_worker_fn		= io_workqueue_free_fn,
	.init_worker_fn		= io_workqueue_init_worker_fn,
	.exit_worker_fn		= io_workqueue_exit_worker_fn,
};

int rate_submit_init(struct thread_data *td, struct sk_out *sk_out)
{
	if (td->o.io_submit_mode != IO_MODE_OFFLOAD)
		return 0;

	return workqueue_init(td, &td->io_wq, &rated_wq_ops, td->o.iodepth, sk_out);
}

void rate_submit_exit(struct thread_data *td)
{
	if (td->o.io_submit_mode != IO_MODE_OFFLOAD)
		return;

	workqueue_exit(&td->io_wq);
}
