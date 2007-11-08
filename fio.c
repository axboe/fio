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
#include "hash.h"

unsigned long page_mask;
unsigned long page_size;
#define ALIGN(buf)	\
	(char *) (((unsigned long) (buf) + page_mask) & ~page_mask)

int groupid = 0;
int thread_number = 0;
int nr_process = 0;
int nr_thread = 0;
int shm_id = 0;
int temp_stall_ts;

static struct fio_sem *startup_sem;
static volatile int fio_abort;
static int exit_value;

struct io_log *agg_io_log[2];

#define TERMINATE_ALL		(-1)
#define JOB_START_TIMEOUT	(5 * 1000)

static inline void td_set_runstate(struct thread_data *td, int runstate)
{
	td->runstate = runstate;
}

static void terminate_threads(int group_id)
{
	struct thread_data *td;
	int i;

	for_each_td(td, i) {
		if (group_id == TERMINATE_ALL || groupid == td->groupid) {
			/*
			 * if the thread is running, just let it exit
			 */
			if (td->runstate < TD_RUNNING)
				kill(td->pid, SIGQUIT);
			td->terminate = 1;
			td->o.start_delay = 0;
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
			terminate_threads(TERMINATE_ALL);
			break;
	}
}

/*
 * Check if we are above the minimum rate given.
 */
static int check_min_rate(struct thread_data *td, struct timeval *now)
{
	unsigned long long bytes = 0;
	unsigned long iops = 0;
	unsigned long spent;
	unsigned long rate;

	/*
	 * No minimum rate set, always ok
	 */
	if (!td->o.ratemin && !td->o.rate_iops_min)
		return 0;

	/*
	 * allow a 2 second settle period in the beginning
	 */
	if (mtime_since(&td->start, now) < 2000)
		return 0;

	if (td_read(td)) {
		iops += td->io_blocks[DDIR_READ];
		bytes += td->this_io_bytes[DDIR_READ];
	}
	if (td_write(td)) {
		iops += td->io_blocks[DDIR_WRITE];
		bytes += td->this_io_bytes[DDIR_WRITE];
	}

	/*
	 * if rate blocks is set, sample is running
	 */
	if (td->rate_bytes || td->rate_blocks) {
		spent = mtime_since(&td->lastrate, now);
		if (spent < td->o.ratecycle)
			return 0;

		if (td->o.rate) {
			/*
			 * check bandwidth specified rate
			 */
			if (bytes < td->rate_bytes) {
				log_err("%s: min rate %u not met\n", td->o.name, td->o.ratemin);
				return 1;
			} else {
				rate = (bytes - td->rate_bytes) / spent;
				if (rate < td->o.ratemin || bytes < td->rate_bytes) {
					log_err("%s: min rate %u not met, got %luKiB/sec\n", td->o.name, td->o.ratemin, rate);
					return 1;
				}
			}
		} else {
			/*
			 * checks iops specified rate
			 */
			if (iops < td->o.rate_iops) {
				log_err("%s: min iops rate %u not met\n", td->o.name, td->o.rate_iops);
				return 1;
			} else {
				rate = (iops - td->rate_blocks) / spent;
				if (rate < td->o.rate_iops_min || iops < td->rate_blocks) {
					log_err("%s: min iops rate %u not met, got %lu\n", td->o.name, td->o.rate_iops_min, rate);
				}
			}
		}
	}

	td->rate_bytes = bytes;
	td->rate_blocks = iops;
	memcpy(&td->lastrate, now, sizeof(*now));
	return 0;
}

static inline int runtime_exceeded(struct thread_data *td, struct timeval *t)
{
	if (!td->o.timeout)
		return 0;
	if (mtime_since(&td->epoch, t) >= td->o.timeout * 1000)
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
	r = io_u_queued_complete(td, 0);
	if (r < 0)
		return;

	/*
	 * now cancel remaining active events
	 */
	if (td->io_ops->cancel) {
		list_for_each_safe(entry, n, &td->io_u_busylist) {
			io_u = list_entry(entry, struct io_u, list);

			/*
			 * if the io_u isn't in flight, then that generally
			 * means someone leaked an io_u. complain but fix
			 * it up, so we don't stall here.
			 */
			if ((io_u->flags & IO_U_F_FLIGHT) == 0) {
				log_err("fio: non-busy IO on busy list\n");
				put_io_u(td, io_u);
			} else {
				r = td->io_ops->cancel(td, io_u);
				if (!r)
					put_io_u(td, io_u);
			}
		}
	}

	if (td->cur_depth)
		r = io_u_queued_complete(td, td->cur_depth);
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
		td_verror(td, io_u->error, "td_io_queue");
		put_io_u(td, io_u);
		return 1;
	} else if (ret == FIO_Q_QUEUED) {
		if (io_u_queued_complete(td, 1) < 0)
			return 1;
	} else if (ret == FIO_Q_COMPLETED) {
		if (io_u->error) {
			td_verror(td, io_u->error, "td_io_queue");
			return 1;
		}

		if (io_u_sync_complete(td, io_u) < 0)
			return 1;
	} else if (ret == FIO_Q_BUSY) {
		if (td_io_commit(td))
			return 1;
		goto requeue;
	}

	return 0;
}

/*
 * The main verify engine. Runs over the writes we previously submitted,
 * reads the blocks back in, and checks the crc/md5 of the data.
 */
static void do_verify(struct thread_data *td)
{
	struct fio_file *f;
	struct io_u *io_u;
	int ret, min_events;
	unsigned int i;

	/*
	 * sync io first and invalidate cache, to make sure we really
	 * read from disk.
	 */
	for_each_file(td, f, i) {
		if (!(f->flags & FIO_FILE_OPEN))
			continue;
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
		int ret2;

		io_u = __get_io_u(td);
		if (!io_u)
			break;

		if (runtime_exceeded(td, &io_u->start_time)) {
			put_io_u(td, io_u);
			td->terminate = 1;
			break;
		}

		if (get_next_verify(td, io_u)) {
			put_io_u(td, io_u);
			break;
		}

		if (td_io_prep(td, io_u)) {
			put_io_u(td, io_u);
			break;
		}

		io_u->end_io = verify_io_u;

		ret = td_io_queue(td, io_u);
		switch (ret) {
		case FIO_Q_COMPLETED:
			if (io_u->error)
				ret = -io_u->error;
			else if (io_u->resid) {
				int bytes = io_u->xfer_buflen - io_u->resid;
				struct fio_file *f = io_u->file;

				/*
				 * zero read, fail
				 */
				if (!bytes) {
					td_verror(td, ENODATA, "full resid");
					put_io_u(td, io_u);
					break;
				}

				io_u->xfer_buflen = io_u->resid;
				io_u->xfer_buf += bytes;
				io_u->offset += bytes;
				f->last_completed_pos = io_u->offset;

				td->ts.short_io_u[io_u->ddir]++;

				if (io_u->offset == f->real_file_size)
					goto sync_done;

				requeue_io_u(td, &io_u);
			} else {
sync_done:
				ret = io_u_sync_complete(td, io_u);
				if (ret < 0)
					break;
			}
			continue;
		case FIO_Q_QUEUED:
			break;
		case FIO_Q_BUSY:
			requeue_io_u(td, &io_u);
			ret2 = td_io_commit(td);
			if (ret2 < 0)
				ret = ret2;
			break;
		default:
			assert(ret < 0);
			td_verror(td, -ret, "td_io_queue");
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

			if (td->cur_depth > td->o.iodepth_low)
				min_events = td->cur_depth - td->o.iodepth_low;
		}

		/*
		 * Reap required number of io units, if any, and do the
		 * verification on them through the callback handler
		 */
		if (io_u_queued_complete(td, min_events) < 0)
			break;
	}

	if (!td->error) {
		min_events = td->cur_depth;

		if (min_events)
			ret = io_u_queued_complete(td, min_events);
	} else
		cleanup_pending_aio(td);

	td_set_runstate(td, TD_RUNNING);
}

/*
 * Main IO worker function. It retrieves io_u's to process and queues
 * and reaps them, checking for rate and errors along the way.
 */
static void do_io(struct thread_data *td)
{
	struct timeval s;
	unsigned long usec;
	unsigned int i;
	int ret = 0;

	td_set_runstate(td, TD_RUNNING);

	while ((td->this_io_bytes[0] + td->this_io_bytes[1]) < td->o.size) {
		struct timeval comp_time;
		long bytes_done = 0;
		int min_evts = 0;
		struct io_u *io_u;
		int ret2;

		if (td->terminate)
			break;

		io_u = get_io_u(td);
		if (!io_u)
			break;

		memcpy(&s, &io_u->start_time, sizeof(s));

		if (runtime_exceeded(td, &s)) {
			put_io_u(td, io_u);
			td->terminate = 1;
			break;
		}

		/*
		 * Add verification end_io handler, if asked to verify
		 * a previously written file.
		 */
		if (td->o.verify != VERIFY_NONE)
			io_u->end_io = verify_io_u;

		ret = td_io_queue(td, io_u);
		switch (ret) {
		case FIO_Q_COMPLETED:
			if (io_u->error)
				ret = -io_u->error;
			else if (io_u->resid) {
				int bytes = io_u->xfer_buflen - io_u->resid;
				struct fio_file *f = io_u->file;

				/*
				 * zero read, fail
				 */
				if (!bytes) {
					td_verror(td, ENODATA, "full resid");
					put_io_u(td, io_u);
					break;
				}

				io_u->xfer_buflen = io_u->resid;
				io_u->xfer_buf += bytes;
				io_u->offset += bytes;
				f->last_completed_pos = io_u->offset;

				td->ts.short_io_u[io_u->ddir]++;

				if (io_u->offset == f->real_file_size)
					goto sync_done;

				requeue_io_u(td, &io_u);
			} else {
sync_done:
				fio_gettime(&comp_time, NULL);
				bytes_done = io_u_sync_complete(td, io_u);
				if (bytes_done < 0)
					ret = bytes_done;
			}
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
			ret2 = td_io_commit(td);
			if (ret2 < 0)
				ret = ret2;
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

				if (td->cur_depth > td->o.iodepth_low)
					min_evts = td->cur_depth - td->o.iodepth_low;
			}

			fio_gettime(&comp_time, NULL);
			bytes_done = io_u_queued_complete(td, min_evts);
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

		rate_throttle(td, usec, bytes_done);

		if (check_min_rate(td, &comp_time)) {
			if (exitall_on_terminate)
				terminate_threads(td->groupid);
			td_verror(td, ENODATA, "check_min_rate");
			break;
		}

		if (td->o.thinktime) {
			unsigned long long b;

			b = td->io_blocks[0] + td->io_blocks[1];
			if (!(b % td->o.thinktime_blocks)) {
				int left;

				if (td->o.thinktime_spin)
					__usec_sleep(td->o.thinktime_spin);

				left = td->o.thinktime - td->o.thinktime_spin;
				if (left)
					usec_sleep(td, left);
			}
		}
	}

	if (!td->error) {
		struct fio_file *f;

		i = td->cur_depth;
		if (i)
			ret = io_u_queued_complete(td, i);

		if (should_fsync(td) && td->o.end_fsync) {
			td_set_runstate(td, TD_FSYNCING);

			for_each_file(td, f, i) {
				if (!(f->flags & FIO_FILE_OPEN))
					continue;
				fio_io_sync(td, f);
			}
		}
	} else
		cleanup_pending_aio(td);
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
static void fill_io_buf(struct thread_data *td, struct io_u *io_u, int max_bs)
{
	long *ptr = io_u->buf;

	if (!td->o.zero_buffers) {
		while ((void *) ptr - io_u->buf < max_bs) {
			*ptr = rand() * GOLDEN_RATIO_PRIME;
			ptr++;
		}
	} else
		memset(ptr, 0, max_bs);
}

static int init_io_u(struct thread_data *td)
{
	struct io_u *io_u;
	unsigned int max_bs;
	int i, max_units;
	char *p;

	if (td->io_ops->flags & FIO_SYNCIO)
		max_units = 1;
	else
		max_units = td->o.iodepth;

	max_bs = max(td->o.max_bs[DDIR_READ], td->o.max_bs[DDIR_WRITE]);
	td->orig_buffer_size = (unsigned long long) max_bs * (unsigned long long) max_units;

	if (td->o.mem_type == MEM_SHMHUGE || td->o.mem_type == MEM_MMAPHUGE)
		td->orig_buffer_size = (td->orig_buffer_size + td->o.hugepage_size - 1) & ~(td->o.hugepage_size - 1);

	if (td->orig_buffer_size != (size_t) td->orig_buffer_size) {
		log_err("fio: IO memory too large. Reduce max_bs or iodepth\n");
		return 1;
	}

	if (allocate_io_mem(td))
		return 1;

	if (td->o.odirect)
		p = ALIGN(td->orig_buffer);
	else
		p = td->orig_buffer;

	for (i = 0; i < max_units; i++) {
		if (td->terminate)
			return 1;
		io_u = malloc(sizeof(*io_u));
		memset(io_u, 0, sizeof(*io_u));
		INIT_LIST_HEAD(&io_u->list);

		if (!(td->io_ops->flags & FIO_NOIO)) {
			io_u->buf = p + max_bs * i;

			if (td_write(td))
				fill_io_buf(td, io_u, max_bs);
		}

		io_u->index = i;
		io_u->flags = IO_U_F_FREE;
		list_add(&io_u->list, &td->io_u_freelist);
	}

	io_u_init_timeout();

	return 0;
}

static int switch_ioscheduler(struct thread_data *td)
{
	char tmp[256], tmp2[128];
	FILE *f;
	int ret;

	if (td->io_ops->flags & FIO_DISKLESSIO)
		return 0;

	sprintf(tmp, "%s/queue/scheduler", td->sysfs_root);

	f = fopen(tmp, "r+");
	if (!f) {
		if (errno == ENOENT) {
			log_err("fio: os or kernel doesn't support IO scheduler switching\n");
			return 0;
		}
		td_verror(td, errno, "fopen iosched");
		return 1;
	}

	/*
	 * Set io scheduler.
	 */
	ret = fwrite(td->o.ioscheduler, strlen(td->o.ioscheduler), 1, f);
	if (ferror(f) || ret != 1) {
		td_verror(td, errno, "fwrite");
		fclose(f);
		return 1;
	}

	rewind(f);

	/*
	 * Read back and check that the selected scheduler is now the default.
	 */
	ret = fread(tmp, 1, sizeof(tmp), f);
	if (ferror(f) || ret < 0) {
		td_verror(td, errno, "fread");
		fclose(f);
		return 1;
	}

	sprintf(tmp2, "[%s]", td->o.ioscheduler);
	if (!strstr(tmp, tmp2)) {
		log_err("fio: io scheduler %s not found\n", td->o.ioscheduler);
		td_verror(td, EINVAL, "iosched_switch");
		fclose(f);
		return 1;
	}

	fclose(f);
	return 0;
}

static int keep_running(struct thread_data *td)
{
	unsigned long long io_done;

	if (td->done)
		return 0;
	if (td->o.time_based)
		return 1;
	if (td->o.loops) {
		td->o.loops--;
		return 1;
	}

	io_done = td->io_bytes[DDIR_READ] + td->io_bytes[DDIR_WRITE] + td->io_skip_bytes;
	if (io_done < td->o.size)
		return 1;

	return 0;
}

static int clear_io_state(struct thread_data *td)
{
	struct fio_file *f;
	unsigned int i;
	int ret;

	td->ts.stat_io_bytes[0] = td->ts.stat_io_bytes[1] = 0;
	td->this_io_bytes[0] = td->this_io_bytes[1] = 0;
	td->zone_bytes = 0;
	td->rate_bytes = 0;
	td->rate_blocks = 0;
	td->rw_end_set[0] = td->rw_end_set[1] = 0;

	td->last_was_sync = 0;

	if (td->o.time_based)
		td->nr_done_files = 0;

	for_each_file(td, f, i)
		td_io_close_file(td, f);

	ret = 0;
	for_each_file(td, f, i) {
		f->flags &= ~FIO_FILE_DONE;
		ret = td_io_open_file(td, f);
		if (ret)
			break;
	}

	return ret;
}

/*
 * Entry point for the thread based jobs. The process based jobs end up
 * here as well, after a little setup.
 */
static void *thread_main(void *data)
{
	unsigned long long runtime[2];
	struct thread_data *td = data;
	unsigned long elapsed;
	int clear_state;

	if (!td->o.use_thread)
		setsid();

	td->pid = getpid();

	INIT_LIST_HEAD(&td->io_u_freelist);
	INIT_LIST_HEAD(&td->io_u_busylist);
	INIT_LIST_HEAD(&td->io_u_requeues);
	INIT_LIST_HEAD(&td->io_log_list);
	INIT_LIST_HEAD(&td->io_hist_list);
	td->io_hist_tree = RB_ROOT;

	td_set_runstate(td, TD_INITIALIZED);
	fio_sem_up(startup_sem);
	fio_sem_down(td->mutex);

	/*
	 * the ->mutex semaphore is now no longer used, close it to avoid
	 * eating a file descriptor
	 */
	fio_sem_remove(td->mutex);

	/*
	 * May alter parameters that init_io_u() will use, so we need to
	 * do this first.
	 */
	if (init_iolog(td))
		goto err;

	if (init_io_u(td))
		goto err;

	if (td->o.cpumask_set && fio_setaffinity(td) == -1) {
		td_verror(td, errno, "cpu_set_affinity");
		goto err;
	}

	if (td->ioprio_set) {
		if (ioprio_set(IOPRIO_WHO_PROCESS, 0, td->ioprio) == -1) {
			td_verror(td, errno, "ioprio_set");
			goto err;
		}
	}

	if (nice(td->o.nice) == -1) {
		td_verror(td, errno, "nice");
		goto err;
	}

	if (td->o.ioscheduler && switch_ioscheduler(td))
		goto err;

	if (!td->o.create_serialize && setup_files(td))
		goto err;

	if (td_io_init(td))
		goto err;

	if (open_files(td))
		goto err;

	if (init_random_map(td))
		goto err;

	if (td->o.exec_prerun) {
		if (system(td->o.exec_prerun) < 0)
			goto err;
	}

	fio_gettime(&td->epoch, NULL);
	memcpy(&td->timeout_end, &td->epoch, sizeof(td->epoch));
	getrusage(RUSAGE_SELF, &td->ts.ru_start);

	runtime[0] = runtime[1] = 0;
	clear_state = 0;
	while (keep_running(td)) {
		fio_gettime(&td->start, NULL);
		memcpy(&td->ts.stat_sample_time, &td->start, sizeof(td->start));

		if (td->o.ratemin)
			memcpy(&td->lastrate, &td->ts.stat_sample_time, sizeof(td->lastrate));

		if (clear_state && clear_io_state(td))
			break;

		prune_io_piece_log(td);

		do_io(td);

		clear_state = 1;

		if (td_read(td) && td->io_bytes[DDIR_READ]) {
			if (td->rw_end_set[DDIR_READ])
				elapsed = utime_since(&td->start, &td->rw_end[DDIR_READ]);
			else
				elapsed = utime_since_now(&td->start);

			runtime[DDIR_READ] += elapsed;
		}
		if (td_write(td) && td->io_bytes[DDIR_WRITE]) {
			if (td->rw_end_set[DDIR_WRITE])
				elapsed = utime_since(&td->start, &td->rw_end[DDIR_WRITE]);
			else
				elapsed = utime_since_now(&td->start);

			runtime[DDIR_WRITE] += elapsed;
		}
		
		if (td->error || td->terminate)
			break;

		if (!td->o.do_verify ||
		    td->o.verify == VERIFY_NONE ||
		    (td->io_ops->flags & FIO_UNIDIR))
			continue;

		if (clear_io_state(td))
			break;

		fio_gettime(&td->start, NULL);

		do_verify(td);

		runtime[DDIR_READ] += utime_since_now(&td->start);

		if (td->error || td->terminate)
			break;
	}

	update_rusage_stat(td);
	td->ts.runtime[0] = (runtime[0] + 999) / 1000;
	td->ts.runtime[1] = (runtime[1] + 999) / 1000;
	td->ts.total_run_time = mtime_since_now(&td->epoch);
	td->ts.io_bytes[0] = td->io_bytes[0];
	td->ts.io_bytes[1] = td->io_bytes[1];

	if (td->ts.bw_log)
		finish_log(td, td->ts.bw_log, "bw");
	if (td->ts.slat_log)
		finish_log(td, td->ts.slat_log, "slat");
	if (td->ts.clat_log)
		finish_log(td, td->ts.clat_log, "clat");
	if (td->o.exec_postrun) {
		if (system(td->o.exec_postrun) < 0)
			log_err("fio: postrun %s failed\n", td->o.exec_postrun);
	}

	if (exitall_on_terminate)
		terminate_threads(td->groupid);

err:
	if (td->error)
		printf("fio: pid=%d, err=%d/%s\n", td->pid, td->error, td->verror);
	close_files(td);
	close_ioengine(td);
	cleanup_io_u(td);

	/*
	 * do this very late, it will log file closing as well
	 */
	if (td->o.write_iolog_file)
		write_iolog_close(td);

	options_mem_free(td);
	td_set_runstate(td, TD_EXITED);
	return (void *) (unsigned long) td->error;
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
	return (int) (unsigned long) ret;
}

/*
 * Run over the job map and reap the threads that have exited, if any.
 */
static void reap_threads(int *nr_running, int *t_rate, int *m_rate)
{
	struct thread_data *td;
	int i, cputhreads, realthreads, pending, status, ret;

	/*
	 * reap exited threads (TD_EXITED -> TD_REAPED)
	 */
	realthreads = pending = cputhreads = 0;
	for_each_td(td, i) {
		int flags = 0;

		/*
		 * ->io_ops is NULL for a thread that has closed its
		 * io engine
		 */
		if (td->io_ops && !strcmp(td->io_ops->name, "cpuio"))
			cputhreads++;
		else
			realthreads++;

		if (!td->pid || td->runstate == TD_REAPED)
			continue;
		if (td->o.use_thread) {
			if (td->runstate == TD_EXITED) {
				td_set_runstate(td, TD_REAPED);
				goto reaped;
			}
			continue;
		}

		flags = WNOHANG;
		if (td->runstate == TD_EXITED)
			flags = 0;

		/*
		 * check if someone quit or got killed in an unusual way
		 */
		ret = waitpid(td->pid, &status, flags);
		if (ret < 0) {
			if (errno == ECHILD) {
				log_err("fio: pid=%d disappeared %d\n", td->pid, td->runstate);
				td_set_runstate(td, TD_REAPED);
				goto reaped;
			}
			perror("waitpid");
		} else if (ret == td->pid) {
			if (WIFSIGNALED(status)) {
				int sig = WTERMSIG(status);

				if (sig != SIGQUIT)
					log_err("fio: pid=%d, got signal=%d\n", td->pid, sig);
				td_set_runstate(td, TD_REAPED);
				goto reaped;
			}
			if (WIFEXITED(status)) {
				if (WEXITSTATUS(status) && !td->error)
					td->error = WEXITSTATUS(status);

				td_set_runstate(td, TD_REAPED);
				goto reaped;
			}
		}

		/*
		 * thread is not dead, continue
		 */
		pending++;
		continue;
reaped:
		if (td->o.use_thread) {
			long ret;

			if (pthread_join(td->thread, (void *) &ret))
				perror("pthread_join");
		}

		(*nr_running)--;
		(*m_rate) -= td->o.ratemin;
		(*t_rate) -= td->o.rate;
		pending--;

		if (td->error)
			exit_value++;
	}

	if (*nr_running == cputhreads && !pending && realthreads)
		terminate_threads(TERMINATE_ALL);
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
		printf("Starting ");
		if (nr_thread)
			printf("%d thread%s", nr_thread, nr_thread > 1 ? "s" : "");
		if (nr_process) {
			if (nr_thread)
				printf(" and ");
			printf("%d process%s", nr_process, nr_process > 1 ? "es" : "");
		}
		printf("\n");
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

		if (!td->o.create_serialize) {
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

	set_genesis_time();

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

			if (td->o.start_delay) {
				spent = mtime_since_genesis();

				if (td->o.start_delay * 1000 > spent)
					continue;
			}

			if (td->o.stonewall && (nr_started || nr_running))
				break;

			/*
			 * Set state to created. Thread will transition
			 * to TD_INITIALIZED when it's done setting up.
			 */
			td_set_runstate(td, TD_CREATED);
			map[this_jobs++] = td;
			nr_started++;

			if (td->o.use_thread) {
				if (pthread_create(&td->thread, NULL, thread_main, td)) {
					perror("thread_create");
					nr_started--;
					break;
				}
			} else {
				if (!fork()) {
					int ret = fork_main(shm_id, i);

					exit(ret);
				}
			}
			fio_sem_down(startup_sem);
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
			m_rate += td->o.ratemin;
			t_rate += td->o.rate;
			todo--;
			fio_sem_up(td->mutex);
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

	if (!thread_number)
		return 0;

	ps = sysconf(_SC_PAGESIZE);
	if (ps < 0) {
		log_err("Failed to get page size\n");
		return 1;
	}

	page_size = ps;
	page_mask = ps - 1;

	if (write_bw_log) {
		setup_log(&agg_io_log[DDIR_READ]);
		setup_log(&agg_io_log[DDIR_WRITE]);
	}

	startup_sem = fio_sem_init(0);

	set_genesis_time();

	disk_util_timer_arm();

	run_threads();

	if (!fio_abort) {
		show_run_stats();
		if (write_bw_log) {
			__finish_log(agg_io_log[DDIR_READ],"agg-read_bw.log");
			__finish_log(agg_io_log[DDIR_WRITE],"agg-write_bw.log");
		}
	}

	fio_sem_remove(startup_sem);
	return exit_value;
}
