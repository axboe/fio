/*
 * fio - the flexible io tester
 *
 * Copyright (C) 2005 Jens Axboe <axboe@suse.de>
 * Copyright (C) 2006 Jens Axboe <axboe@kernel.dk>
 *
 * The license below covers all files distributed with fio unless otherwise
 * noted in the file itself.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <locale.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/mman.h>

#include "fio.h"
#include "os.h"

static unsigned long page_mask;
#define ALIGN(buf)	\
	(char *) (((unsigned long) (buf) + page_mask) & ~page_mask)

int groupid = 0;
int thread_number = 0;
int shm_id = 0;
int temp_stall_ts;

static volatile int startup_sem;
static volatile int fio_abort;
static int exit_value;

struct io_log *agg_io_log[2];

#define TERMINATE_ALL		(-1)
#define JOB_START_TIMEOUT	(5 * 1000)

static inline void td_set_runstate(struct thread_data *td, int runstate)
{
	td->runstate = runstate;
}

static void terminate_threads(int group_id, int forced_kill)
{
	struct thread_data *td;
	int i;

	for_each_td(td, i) {
		if (group_id == TERMINATE_ALL || groupid == td->groupid) {
			td->terminate = 1;
			td->start_delay = 0;
			if (forced_kill)
				td_set_runstate(td, TD_EXITED);
		}
	}
}

static void sig_handler(int sig)
{
	switch (sig) {
		case SIGALRM:
			update_io_ticks();
			disk_util_timer_arm();
			print_thread_status();
			break;
		default:
			printf("\nfio: terminating on signal %d\n", sig);
			fflush(stdout);
			terminate_threads(TERMINATE_ALL, 0);
			break;
	}
}

/*
 * Check if we are above the minimum rate given.
 */
static int check_min_rate(struct thread_data *td, struct timeval *now)
{
	unsigned long spent;
	unsigned long rate;
	int ddir = td->ddir;

	/*
	 * allow a 2 second settle period in the beginning
	 */
	if (mtime_since(&td->start, now) < 2000)
		return 0;

	/*
	 * if rate blocks is set, sample is running
	 */
	if (td->rate_bytes) {
		spent = mtime_since(&td->lastrate, now);
		if (spent < td->ratecycle)
			return 0;

		rate = (td->this_io_bytes[ddir] - td->rate_bytes) / spent;
		if (rate < td->ratemin) {
			fprintf(f_out, "%s: min rate %u not met, got %luKiB/sec\n", td->name, td->ratemin, rate);
			return 1;
		}
	}

	td->rate_bytes = td->this_io_bytes[ddir];
	memcpy(&td->lastrate, now, sizeof(*now));
	return 0;
}

static inline int runtime_exceeded(struct thread_data *td, struct timeval *t)
{
	if (!td->timeout)
		return 0;
	if (mtime_since(&td->epoch, t) >= td->timeout * 1000)
		return 1;

	return 0;
}

/*
 * When job exits, we can cancel the in-flight IO if we are using async
 * io. Attempt to do so.
 */
static void cleanup_pending_aio(struct thread_data *td)
{
	struct list_head *entry, *n;
	struct io_u *io_u;
	int r;

	/*
	 * get immediately available events, if any
	 */
	r = io_u_queued_complete(td, 0, NULL);
	if (r < 0)
		return;

	/*
	 * now cancel remaining active events
	 */
	if (td->io_ops->cancel) {
		list_for_each_safe(entry, n, &td->io_u_busylist) {
			io_u = list_entry(entry, struct io_u, list);

			r = td->io_ops->cancel(td, io_u);
			if (!r)
				put_io_u(td, io_u);
		}
	}

	if (td->cur_depth)
		r = io_u_queued_complete(td, td->cur_depth, NULL);
}

/*
 * Helper to handle the final sync of a file. Works just like the normal
 * io path, just does everything sync.
 */
static int fio_io_sync(struct thread_data *td, struct fio_file *f)
{
	struct io_u *io_u = __get_io_u(td);
	int ret;

	if (!io_u)
		return 1;

	io_u->ddir = DDIR_SYNC;
	io_u->file = f;

	if (td_io_prep(td, io_u)) {
		put_io_u(td, io_u);
		return 1;
	}

requeue:
	ret = td_io_queue(td, io_u);
	if (ret < 0) {
		td_verror(td, io_u->error);
		put_io_u(td, io_u);
		return 1;
	} else if (ret == FIO_Q_QUEUED) {
		if (io_u_queued_complete(td, 1, NULL))
			return 1;
	} else if (ret == FIO_Q_COMPLETED) {
		if (io_u->error) {
			td_verror(td, io_u->error);
			return 1;
		}

		if (io_u_sync_complete(td, io_u, NULL) < 0)
			return 1;
	} else if (ret == FIO_Q_BUSY) {
		if (td_io_commit(td))
			return 1;
		goto requeue;
	}

	return 0;
}

/*
 * The main verify engine. Runs over the writes we previusly submitted,
 * reads the blocks back in, and checks the crc/md5 of the data.
 */
static void do_verify(struct thread_data *td)
{
	struct fio_file *f;
	struct io_u *io_u;
	int ret, i, min_events;

	/*
	 * sync io first and invalidate cache, to make sure we really
	 * read from disk.
	 */
	for_each_file(td, f, i) {
		if (fio_io_sync(td, f))
			break;
		if (file_invalidate_cache(td, f))
			break;
	}

	if (td->error)
		return;

	td_set_runstate(td, TD_VERIFYING);

	io_u = NULL;
	while (!td->terminate) {
		io_u = __get_io_u(td);
		if (!io_u)
			break;

		if (runtime_exceeded(td, &io_u->start_time))
			break;

		if (get_next_verify(td, io_u))
			break;

		if (td_io_prep(td, io_u))
			break;

requeue:
		ret = td_io_queue(td, io_u);

		switch (ret) {
		case FIO_Q_COMPLETED:
			if (io_u->error)
				ret = -io_u->error;
			if (io_u->xfer_buflen != io_u->resid && io_u->resid) {
				int bytes = io_u->xfer_buflen - io_u->resid;

				io_u->xfer_buflen = io_u->resid;
				io_u->xfer_buf += bytes;
				goto requeue;
			}
			ret = io_u_sync_complete(td, io_u, verify_io_u);
			if (ret)
				break;
			continue;
		case FIO_Q_QUEUED:
			break;
		case FIO_Q_BUSY:
			requeue_io_u(td, &io_u);
			ret = td_io_commit(td);
			break;
		default:
			assert(ret < 0);
			td_verror(td, -ret);
			break;
		}

		if (ret < 0 || td->error)
			break;

		/*
		 * if we can queue more, do so. but check if there are
		 * completed io_u's first.
		 */
		min_events = 0;
		if (queue_full(td) || ret == FIO_Q_BUSY) {
			min_events = 1;

			if (td->cur_depth > td->iodepth_low)
				min_events = td->cur_depth - td->iodepth_low;
		}

		/*
		 * Reap required number of io units, if any, and do the
		 * verification on them through the callback handler
		 */
		if (io_u_queued_complete(td, min_events, verify_io_u))
			break;
	}

	if (io_u)
		put_io_u(td, io_u);

	if (td->cur_depth)
		cleanup_pending_aio(td);

	td_set_runstate(td, TD_RUNNING);
}

/*
 * Not really an io thread, all it does is burn CPU cycles in the specified
 * manner.
 */
static void do_cpuio(struct thread_data *td)
{
	struct timeval e;
	int split = 100 / td->cpuload;
	int i = 0;

	while (!td->terminate) {
		fio_gettime(&e, NULL);

		if (runtime_exceeded(td, &e))
			break;

		if (!(i % split))
			__usec_sleep(10000);
		else
			usec_sleep(td, 10000);

		i++;
	}
}

/*
 * Main IO worker function. It retrieves io_u's to process and queues
 * and reaps them, checking for rate and errors along the way.
 */
static void do_io(struct thread_data *td)
{
	struct timeval s;
	unsigned long usec;
	int i, ret = 0;

	td_set_runstate(td, TD_RUNNING);

	while ((td->this_io_bytes[0] + td->this_io_bytes[1]) < td->io_size) {
		struct timeval comp_time;
		long bytes_done = 0;
		int min_evts = 0;
		struct io_u *io_u;

		if (td->terminate)
			break;

		io_u = get_io_u(td);
		if (!io_u)
			break;

		memcpy(&s, &io_u->start_time, sizeof(s));

		if (runtime_exceeded(td, &s)) {
			put_io_u(td, io_u);
			break;
		}
requeue:
		ret = td_io_queue(td, io_u);

		switch (ret) {
		case FIO_Q_COMPLETED:
			if (io_u->error) {
				ret = io_u->error;
				break;
			}
			if (io_u->xfer_buflen != io_u->resid && io_u->resid) {
				int bytes = io_u->xfer_buflen - io_u->resid;

				io_u->xfer_buflen = io_u->resid;
				io_u->xfer_buf += bytes;
				goto requeue;
			}
			fio_gettime(&comp_time, NULL);
			bytes_done = io_u_sync_complete(td, io_u, NULL);
			if (bytes_done < 0)
				ret = bytes_done;
			break;
		case FIO_Q_QUEUED:
			/*
			 * if the engine doesn't have a commit hook,
			 * the io_u is really queued. if it does have such
			 * a hook, it has to call io_u_queued() itself.
			 */
			if (td->io_ops->commit == NULL)
				io_u_queued(td, io_u);
			break;
		case FIO_Q_BUSY:
			requeue_io_u(td, &io_u);
			ret = td_io_commit(td);
			break;
		default:
			assert(ret < 0);
			put_io_u(td, io_u);
			break;
		}

		if (ret < 0 || td->error)
			break;

		/*
		 * See if we need to complete some commands
		 */
		if (ret == FIO_Q_QUEUED || ret == FIO_Q_BUSY) {
			min_evts = 0;
			if (queue_full(td) || ret == FIO_Q_BUSY) {
				min_evts = 1;

				if (td->cur_depth > td->iodepth_low)
					min_evts = td->cur_depth - td->iodepth_low;
			}

			fio_gettime(&comp_time, NULL);
			bytes_done = io_u_queued_complete(td, min_evts, NULL);
			if (bytes_done < 0)
				break;
		}

		if (!bytes_done)
			continue;

		/*
		 * the rate is batched for now, it should work for batches
		 * of completions except the very first one which may look
		 * a little bursty
		 */
		usec = utime_since(&s, &comp_time);

		rate_throttle(td, usec, bytes_done, td->ddir);

		if (check_min_rate(td, &comp_time)) {
			if (exitall_on_terminate)
				terminate_threads(td->groupid, 0);
			td_verror(td, ENODATA);
			break;
		}

		if (td->thinktime) {
			unsigned long long b;

			b = td->io_blocks[0] + td->io_blocks[1];
			if (!(b % td->thinktime_blocks)) {
				int left;

				if (td->thinktime_spin)
					__usec_sleep(td->thinktime_spin);

				left = td->thinktime - td->thinktime_spin;
				if (left)
					usec_sleep(td, left);
			}
		}
	}

	if (!td->error) {
		struct fio_file *f;

		if (td->cur_depth)
			cleanup_pending_aio(td);

		if (should_fsync(td) && td->end_fsync) {
			td_set_runstate(td, TD_FSYNCING);
			for_each_file(td, f, i)
				fio_io_sync(td, f);
		}
	}
}

static void cleanup_io_u(struct thread_data *td)
{
	struct list_head *entry, *n;
	struct io_u *io_u;

	list_for_each_safe(entry, n, &td->io_u_freelist) {
		io_u = list_entry(entry, struct io_u, list);

		list_del(&io_u->list);
		free(io_u);
	}

	free_io_mem(td);
}

/*
 * "randomly" fill the buffer contents
 */
static void fill_rand_buf(struct io_u *io_u, int max_bs)
{
	int *ptr = io_u->buf;

	while ((void *) ptr - io_u->buf < max_bs) {
		*ptr = rand() * 0x9e370001;
		ptr++;
	}
}

static int init_io_u(struct thread_data *td)
{
	struct io_u *io_u;
	unsigned int max_bs;
	int i, max_units;
	char *p;

	if (td->io_ops->flags & FIO_CPUIO)
		return 0;

	if (td->io_ops->flags & FIO_SYNCIO)
		max_units = 1;
	else
		max_units = td->iodepth;

	max_bs = max(td->max_bs[DDIR_READ], td->max_bs[DDIR_WRITE]);
	td->orig_buffer_size = max_bs * max_units;

	if (td->mem_type == MEM_SHMHUGE || td->mem_type == MEM_MMAPHUGE)
		td->orig_buffer_size = (td->orig_buffer_size + td->hugepage_size - 1) & ~(td->hugepage_size - 1);
	else
		td->orig_buffer_size += page_mask;

	if (allocate_io_mem(td))
		return 1;

	p = ALIGN(td->orig_buffer);
	for (i = 0; i < max_units; i++) {
		io_u = malloc(sizeof(*io_u));
		memset(io_u, 0, sizeof(*io_u));
		INIT_LIST_HEAD(&io_u->list);

		io_u->buf = p + max_bs * i;
		if (td_write(td) || td_rw(td))
			fill_rand_buf(io_u, max_bs);

		io_u->index = i;
		list_add(&io_u->list, &td->io_u_freelist);
	}

	return 0;
}

static int switch_ioscheduler(struct thread_data *td)
{
	char tmp[256], tmp2[128];
	FILE *f;
	int ret;

	if (td->io_ops->flags & FIO_CPUIO)
		return 0;

	sprintf(tmp, "%s/queue/scheduler", td->sysfs_root);

	f = fopen(tmp, "r+");
	if (!f) {
		td_verror(td, errno);
		return 1;
	}

	/*
	 * Set io scheduler.
	 */
	ret = fwrite(td->ioscheduler, strlen(td->ioscheduler), 1, f);
	if (ferror(f) || ret != 1) {
		td_verror(td, errno);
		fclose(f);
		return 1;
	}

	rewind(f);

	/*
	 * Read back and check that the selected scheduler is now the default.
	 */
	ret = fread(tmp, 1, sizeof(tmp), f);
	if (ferror(f) || ret < 0) {
		td_verror(td, errno);
		fclose(f);
		return 1;
	}

	sprintf(tmp2, "[%s]", td->ioscheduler);
	if (!strstr(tmp, tmp2)) {
		log_err("fio: io scheduler %s not found\n", td->ioscheduler);
		td_verror(td, EINVAL);
		fclose(f);
		return 1;
	}

	fclose(f);
	return 0;
}

static void clear_io_state(struct thread_data *td)
{
	struct fio_file *f;
	int i;

	td->ts.stat_io_bytes[0] = td->ts.stat_io_bytes[1] = 0;
	td->this_io_bytes[0] = td->this_io_bytes[1] = 0;
	td->zone_bytes = 0;

	td->last_was_sync = 0;

	for_each_file(td, f, i) {
		f->last_completed_pos = 0;

		f->last_pos = 0;
		if (td->io_ops->flags & FIO_SYNCIO)
			lseek(f->fd, SEEK_SET, 0);

		if (f->file_map)
			memset(f->file_map, 0, f->num_maps * sizeof(long));
	}
}

/*
 * Entry point for the thread based jobs. The process based jobs end up
 * here as well, after a little setup.
 */
static void *thread_main(void *data)
{
	unsigned long long runtime[2];
	struct thread_data *td = data;

	if (!td->use_thread)
		setsid();

	td->pid = getpid();

	INIT_LIST_HEAD(&td->io_u_freelist);
	INIT_LIST_HEAD(&td->io_u_busylist);
	INIT_LIST_HEAD(&td->io_u_requeues);
	INIT_LIST_HEAD(&td->io_hist_list);
	INIT_LIST_HEAD(&td->io_log_list);

	if (init_io_u(td))
		goto err;

	if (fio_setaffinity(td) == -1) {
		td_verror(td, errno);
		goto err;
	}

	if (init_iolog(td))
		goto err;

	if (td->ioprio) {
		if (ioprio_set(IOPRIO_WHO_PROCESS, 0, td->ioprio) == -1) {
			td_verror(td, errno);
			goto err;
		}
	}

	if (nice(td->nice) == -1) {
		td_verror(td, errno);
		goto err;
	}

	if (init_random_state(td))
		goto err;

	if (td->ioscheduler && switch_ioscheduler(td))
		goto err;

	td_set_runstate(td, TD_INITIALIZED);
	fio_sem_up(&startup_sem);
	fio_sem_down(&td->mutex);

	if (!td->create_serialize && setup_files(td))
		goto err;
	if (open_files(td))
		goto err;

	/*
	 * Do this late, as some IO engines would like to have the
	 * files setup prior to initializing structures.
	 */
	if (td_io_init(td))
		goto err;

	if (td->exec_prerun) {
		if (system(td->exec_prerun) < 0)
			goto err;
	}

	fio_gettime(&td->epoch, NULL);
	getrusage(RUSAGE_SELF, &td->ts.ru_start);

	runtime[0] = runtime[1] = 0;
	while (td->loops--) {
		fio_gettime(&td->start, NULL);
		memcpy(&td->ts.stat_sample_time, &td->start, sizeof(td->start));

		if (td->ratemin)
			memcpy(&td->lastrate, &td->ts.stat_sample_time, sizeof(td->lastrate));

		clear_io_state(td);
		prune_io_piece_log(td);

		if (td->io_ops->flags & FIO_CPUIO)
			do_cpuio(td);
		else
			do_io(td);

		runtime[td->ddir] += utime_since_now(&td->start);
		if (td_rw(td) && td->io_bytes[td->ddir ^ 1])
			runtime[td->ddir ^ 1] = runtime[td->ddir];

		if (td->error || td->terminate)
			break;

		if (td->verify == VERIFY_NONE)
			continue;

		clear_io_state(td);
		fio_gettime(&td->start, NULL);

		do_verify(td);

		runtime[DDIR_READ] += utime_since_now(&td->start);

		if (td->error || td->terminate)
			break;
	}

	update_rusage_stat(td);
	fio_gettime(&td->end_time, NULL);
	td->runtime[0] = runtime[0] / 1000;
	td->runtime[1] = runtime[1] / 1000;

	if (td->ts.bw_log)
		finish_log(td, td->ts.bw_log, "bw");
	if (td->ts.slat_log)
		finish_log(td, td->ts.slat_log, "slat");
	if (td->ts.clat_log)
		finish_log(td, td->ts.clat_log, "clat");
	if (td->write_iolog_file)
		write_iolog_close(td);
	if (td->exec_postrun) {
		if (system(td->exec_postrun) < 0)
			log_err("fio: postrun %s failed\n", td->exec_postrun);
	}

	if (exitall_on_terminate)
		terminate_threads(td->groupid, 0);

err:
	if (td->error)
		printf("fio: pid=%d, err=%d/%s\n", td->pid, td->error, td->verror);
	close_files(td);
	close_ioengine(td);
	cleanup_io_u(td);
	td_set_runstate(td, TD_EXITED);
	return (void *) td->error;
}

/*
 * We cannot pass the td data into a forked process, so attach the td and
 * pass it to the thread worker.
 */
static int fork_main(int shmid, int offset)
{
	struct thread_data *td;
	void *data, *ret;

	data = shmat(shmid, NULL, 0);
	if (data == (void *) -1) {
		int __err = errno;

		perror("shmat");
		return __err;
	}

	td = data + offset * sizeof(struct thread_data);
	ret = thread_main(td);
	shmdt(data);
	return (int) ret;
}

/*
 * Run over the job map and reap the threads that have exited, if any.
 */
static void reap_threads(int *nr_running, int *t_rate, int *m_rate)
{
	struct thread_data *td;
	int i, cputhreads, pending, status, ret;

	/*
	 * reap exited threads (TD_EXITED -> TD_REAPED)
	 */
	pending = cputhreads = 0;
	for_each_td(td, i) {
		/*
		 * ->io_ops is NULL for a thread that has closed its
		 * io engine
		 */
		if (td->io_ops && td->io_ops->flags & FIO_CPUIO)
			cputhreads++;

		if (td->runstate < TD_EXITED) {
			/*
			 * check if someone quit or got killed in an unusual way
			 */
			ret = waitpid(td->pid, &status, WNOHANG);
			if (ret < 0)
				perror("waitpid");
			else if ((ret == td->pid) && WIFSIGNALED(status)) {
				int sig = WTERMSIG(status);

				log_err("fio: pid=%d, got signal=%d\n", td->pid, sig);
				td_set_runstate(td, TD_REAPED);
				goto reaped;
			}
		}

		if (td->runstate != TD_EXITED) {
			if (td->runstate < TD_RUNNING)
				pending++;

			continue;
		}

		if (td->error)
			exit_value++;

		td_set_runstate(td, TD_REAPED);

		if (td->use_thread) {
			long ret;

			if (pthread_join(td->thread, (void *) &ret))
				perror("thread_join");
		} else {
			int status;

			ret = waitpid(td->pid, &status, 0);
			if (ret < 0)
				perror("waitpid");
			else if (WIFEXITED(status) && WEXITSTATUS(status)) {
				if (!exit_value)
					exit_value++;
			}
		}

reaped:
		(*nr_running)--;
		(*m_rate) -= td->ratemin;
		(*t_rate) -= td->rate;
	}

	if (*nr_running == cputhreads && !pending)
		terminate_threads(TERMINATE_ALL, 0);
}

/*
 * Main function for kicking off and reaping jobs, as needed.
 */
static void run_threads(void)
{
	struct thread_data *td;
	unsigned long spent;
	int i, todo, nr_running, m_rate, t_rate, nr_started;

	if (fio_pin_memory())
		return;

	if (!terse_output) {
		printf("Starting %d thread%s\n", thread_number, thread_number > 1 ? "s" : "");
		fflush(stdout);
	}

	signal(SIGINT, sig_handler);
	signal(SIGALRM, sig_handler);

	todo = thread_number;
	nr_running = 0;
	nr_started = 0;
	m_rate = t_rate = 0;

	for_each_td(td, i) {
		print_status_init(td->thread_number - 1);

		if (!td->create_serialize) {
			init_disk_util(td);
			continue;
		}

		/*
		 * do file setup here so it happens sequentially,
		 * we don't want X number of threads getting their
		 * client data interspersed on disk
		 */
		if (setup_files(td)) {
			exit_value++;
			if (td->error)
				log_err("fio: pid=%d, err=%d/%s\n", td->pid, td->error, td->verror);
			td_set_runstate(td, TD_REAPED);
			todo--;
		}

		init_disk_util(td);
	}

	while (todo) {
		struct thread_data *map[MAX_JOBS];
		struct timeval this_start;
		int this_jobs = 0, left;

		/*
		 * create threads (TD_NOT_CREATED -> TD_CREATED)
		 */
		for_each_td(td, i) {
			if (td->runstate != TD_NOT_CREATED)
				continue;

			/*
			 * never got a chance to start, killed by other
			 * thread for some reason
			 */
			if (td->terminate) {
				todo--;
				continue;
			}

			if (td->start_delay) {
				spent = mtime_since_genesis();

				if (td->start_delay * 1000 > spent)
					continue;
			}

			if (td->stonewall && (nr_started || nr_running))
				break;

			/*
			 * Set state to created. Thread will transition
			 * to TD_INITIALIZED when it's done setting up.
			 */
			td_set_runstate(td, TD_CREATED);
			map[this_jobs++] = td;
			fio_sem_init(&startup_sem, 1);
			nr_started++;

			if (td->use_thread) {
				if (pthread_create(&td->thread, NULL, thread_main, td)) {
					perror("thread_create");
					nr_started--;
				}
			} else {
				if (fork())
					fio_sem_down(&startup_sem);
				else {
					int ret = fork_main(shm_id, i);

					exit(ret);
				}
			}
		}

		/*
		 * Wait for the started threads to transition to
		 * TD_INITIALIZED.
		 */
		fio_gettime(&this_start, NULL);
		left = this_jobs;
		while (left && !fio_abort) {
			if (mtime_since_now(&this_start) > JOB_START_TIMEOUT)
				break;

			usleep(100000);

			for (i = 0; i < this_jobs; i++) {
				td = map[i];
				if (!td)
					continue;
				if (td->runstate == TD_INITIALIZED) {
					map[i] = NULL;
					left--;
				} else if (td->runstate >= TD_EXITED) {
					map[i] = NULL;
					left--;
					todo--;
					nr_running++; /* work-around... */
				}
			}
		}

		if (left) {
			log_err("fio: %d jobs failed to start\n", left);
			for (i = 0; i < this_jobs; i++) {
				td = map[i];
				if (!td)
					continue;
				kill(td->pid, SIGTERM);
			}
			break;
		}

		/*
		 * start created threads (TD_INITIALIZED -> TD_RUNNING).
		 */
		for_each_td(td, i) {
			if (td->runstate != TD_INITIALIZED)
				continue;

			td_set_runstate(td, TD_RUNNING);
			nr_running++;
			nr_started--;
			m_rate += td->ratemin;
			t_rate += td->rate;
			todo--;
			fio_sem_up(&td->mutex);
		}

		reap_threads(&nr_running, &t_rate, &m_rate);

		if (todo)
			usleep(100000);
	}

	while (nr_running) {
		reap_threads(&nr_running, &t_rate, &m_rate);
		usleep(10000);
	}

	update_io_ticks();
	fio_unpin_memory();
}

int main(int argc, char *argv[])
{
	long ps;

	/*
	 * We need locale for number printing, if it isn't set then just
	 * go with the US format.
	 */
	if (!getenv("LC_NUMERIC"))
		setlocale(LC_NUMERIC, "en_US");

	if (parse_options(argc, argv))
		return 1;

	if (!thread_number) {
		log_err("Nothing to do\n");
		return 1;
	}

	ps = sysconf(_SC_PAGESIZE);
	if (ps < 0) {
		log_err("Failed to get page size\n");
		return 1;
	}

	page_mask = ps - 1;

	if (write_bw_log) {
		setup_log(&agg_io_log[DDIR_READ]);
		setup_log(&agg_io_log[DDIR_WRITE]);
	}

	disk_util_timer_arm();

	run_threads();

	if (!fio_abort) {
		show_run_stats();
		if (write_bw_log) {
			__finish_log(agg_io_log[DDIR_READ],"agg-read_bw.log");
			__finish_log(agg_io_log[DDIR_WRITE],"agg-write_bw.log");
		}
	}

	return exit_value;
}
