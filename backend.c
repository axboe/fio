/*
 * fio - the flexible io tester
 *
 * Copyright (C) 2005 Jens Axboe <axboe@suse.de>
 * Copyright (C) 2006-2012 Jens Axboe <axboe@kernel.dk>
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
#include <limits.h>
#include <signal.h>
#include <time.h>
#include <locale.h>
#include <assert.h>
#include <time.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/mman.h>

#include "fio.h"
#ifndef FIO_NO_HAVE_SHM_H
#include <sys/shm.h>
#endif
#include "hash.h"
#include "smalloc.h"
#include "verify.h"
#include "trim.h"
#include "diskutil.h"
#include "cgroup.h"
#include "profile.h"
#include "lib/rand.h"
#include "memalign.h"
#include "server.h"
#include "lib/getrusage.h"
#include "idletime.h"
#include "err.h"

static pthread_t disk_util_thread;
static struct fio_mutex *disk_thread_mutex;
static struct fio_mutex *startup_mutex;
static struct flist_head *cgroup_list;
static char *cgroup_mnt;
static int exit_value;
static volatile int fio_abort;
static unsigned int nr_process = 0;
static unsigned int nr_thread = 0;

struct io_log *agg_io_log[DDIR_RWDIR_CNT];

int groupid = 0;
unsigned int thread_number = 0;
unsigned int stat_number = 0;
int shm_id = 0;
int temp_stall_ts;
unsigned long done_secs = 0;
volatile int disk_util_exit = 0;

#define PAGE_ALIGN(buf)	\
	(char *) (((uintptr_t) (buf) + page_mask) & ~page_mask)

#define JOB_START_TIMEOUT	(5 * 1000)

static void sig_int(int sig)
{
	if (threads) {
		if (is_backend)
			fio_server_got_signal(sig);
		else {
			log_info("\nfio: terminating on signal %d\n", sig);
			fflush(stdout);
			exit_value = 128;
		}

		fio_terminate_threads(TERMINATE_ALL);
	}
}

static void sig_show_status(int sig)
{
	show_running_run_stats();
}

static void set_sig_handlers(void)
{
	struct sigaction act;

	memset(&act, 0, sizeof(act));
	act.sa_handler = sig_int;
	act.sa_flags = SA_RESTART;
	sigaction(SIGINT, &act, NULL);

	memset(&act, 0, sizeof(act));
	act.sa_handler = sig_int;
	act.sa_flags = SA_RESTART;
	sigaction(SIGTERM, &act, NULL);

/* Windows uses SIGBREAK as a quit signal from other applications */
#ifdef WIN32
	memset(&act, 0, sizeof(act));
	act.sa_handler = sig_int;
	act.sa_flags = SA_RESTART;
	sigaction(SIGBREAK, &act, NULL);
#endif

	memset(&act, 0, sizeof(act));
	act.sa_handler = sig_show_status;
	act.sa_flags = SA_RESTART;
	sigaction(SIGUSR1, &act, NULL);

	if (is_backend) {
		memset(&act, 0, sizeof(act));
		act.sa_handler = sig_int;
		act.sa_flags = SA_RESTART;
		sigaction(SIGPIPE, &act, NULL);
	}
}

/*
 * Check if we are above the minimum rate given.
 */
static int __check_min_rate(struct thread_data *td, struct timeval *now,
			    enum fio_ddir ddir)
{
	unsigned long long bytes = 0;
	unsigned long iops = 0;
	unsigned long spent;
	unsigned long rate;
	unsigned int ratemin = 0;
	unsigned int rate_iops = 0;
	unsigned int rate_iops_min = 0;

	assert(ddir_rw(ddir));

	if (!td->o.ratemin[ddir] && !td->o.rate_iops_min[ddir])
		return 0;

	/*
	 * allow a 2 second settle period in the beginning
	 */
	if (mtime_since(&td->start, now) < 2000)
		return 0;

	iops += td->this_io_blocks[ddir];
	bytes += td->this_io_bytes[ddir];
	ratemin += td->o.ratemin[ddir];
	rate_iops += td->o.rate_iops[ddir];
	rate_iops_min += td->o.rate_iops_min[ddir];

	/*
	 * if rate blocks is set, sample is running
	 */
	if (td->rate_bytes[ddir] || td->rate_blocks[ddir]) {
		spent = mtime_since(&td->lastrate[ddir], now);
		if (spent < td->o.ratecycle)
			return 0;

		if (td->o.rate[ddir]) {
			/*
			 * check bandwidth specified rate
			 */
			if (bytes < td->rate_bytes[ddir]) {
				log_err("%s: min rate %u not met\n", td->o.name,
								ratemin);
				return 1;
			} else {
				if (spent)
					rate = ((bytes - td->rate_bytes[ddir]) * 1000) / spent;
				else
					rate = 0;

				if (rate < ratemin ||
				    bytes < td->rate_bytes[ddir]) {
					log_err("%s: min rate %u not met, got"
						" %luKB/sec\n", td->o.name,
							ratemin, rate);
					return 1;
				}
			}
		} else {
			/*
			 * checks iops specified rate
			 */
			if (iops < rate_iops) {
				log_err("%s: min iops rate %u not met\n",
						td->o.name, rate_iops);
				return 1;
			} else {
				if (spent)
					rate = ((iops - td->rate_blocks[ddir]) * 1000) / spent;
				else
					rate = 0;

				if (rate < rate_iops_min ||
				    iops < td->rate_blocks[ddir]) {
					log_err("%s: min iops rate %u not met,"
						" got %lu\n", td->o.name,
							rate_iops_min, rate);
				}
			}
		}
	}

	td->rate_bytes[ddir] = bytes;
	td->rate_blocks[ddir] = iops;
	memcpy(&td->lastrate[ddir], now, sizeof(*now));
	return 0;
}

static int check_min_rate(struct thread_data *td, struct timeval *now,
			  uint64_t *bytes_done)
{
	int ret = 0;

	if (bytes_done[DDIR_READ])
		ret |= __check_min_rate(td, now, DDIR_READ);
	if (bytes_done[DDIR_WRITE])
		ret |= __check_min_rate(td, now, DDIR_WRITE);
	if (bytes_done[DDIR_TRIM])
		ret |= __check_min_rate(td, now, DDIR_TRIM);

	return ret;
}

/*
 * When job exits, we can cancel the in-flight IO if we are using async
 * io. Attempt to do so.
 */
static void cleanup_pending_aio(struct thread_data *td)
{
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
		struct io_u *io_u;
		int i;

		io_u_qiter(&td->io_u_all, io_u, i) {
			if (io_u->flags & IO_U_F_FLIGHT) {
				r = td->io_ops->cancel(td, io_u);
				if (!r)
					put_io_u(td, io_u);
			}
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
		td_verror(td, io_u->error, "td_io_queue");
		put_io_u(td, io_u);
		return 1;
	} else if (ret == FIO_Q_QUEUED) {
		if (io_u_queued_complete(td, 1, NULL) < 0)
			return 1;
	} else if (ret == FIO_Q_COMPLETED) {
		if (io_u->error) {
			td_verror(td, io_u->error, "td_io_queue");
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

static int fio_file_fsync(struct thread_data *td, struct fio_file *f)
{
	int ret;

	if (fio_file_open(f))
		return fio_io_sync(td, f);

	if (td_io_open_file(td, f))
		return 1;

	ret = fio_io_sync(td, f);
	td_io_close_file(td, f);
	return ret;
}

static inline void __update_tv_cache(struct thread_data *td)
{
	fio_gettime(&td->tv_cache, NULL);
}

static inline void update_tv_cache(struct thread_data *td)
{
	if ((++td->tv_cache_nr & td->tv_cache_mask) == td->tv_cache_mask)
		__update_tv_cache(td);
}

static inline int runtime_exceeded(struct thread_data *td, struct timeval *t)
{
	if (in_ramp_time(td))
		return 0;
	if (!td->o.timeout)
		return 0;
	if (utime_since(&td->epoch, t) >= td->o.timeout)
		return 1;

	return 0;
}

static int break_on_this_error(struct thread_data *td, enum fio_ddir ddir,
			       int *retptr)
{
	int ret = *retptr;

	if (ret < 0 || td->error) {
		int err = td->error;
		enum error_type_bit eb;

		if (ret < 0)
			err = -ret;

		eb = td_error_type(ddir, err);
		if (!(td->o.continue_on_error & (1 << eb)))
			return 1;

		if (td_non_fatal_error(td, eb, err)) {
		        /*
		         * Continue with the I/Os in case of
			 * a non fatal error.
			 */
			update_error_count(td, err);
			td_clear_error(td);
			*retptr = 0;
			return 0;
		} else if (td->o.fill_device && err == ENOSPC) {
			/*
			 * We expect to hit this error if
			 * fill_device option is set.
			 */
			td_clear_error(td);
			td->terminate = 1;
			return 1;
		} else {
			/*
			 * Stop the I/O in case of a fatal
			 * error.
			 */
			update_error_count(td, err);
			return 1;
		}
	}

	return 0;
}

static void check_update_rusage(struct thread_data *td)
{
	if (td->update_rusage) {
		td->update_rusage = 0;
		update_rusage_stat(td);
		fio_mutex_up(td->rusage_sem);
	}
}

/*
 * The main verify engine. Runs over the writes we previously submitted,
 * reads the blocks back in, and checks the crc/md5 of the data.
 */
static void do_verify(struct thread_data *td, uint64_t verify_bytes)
{
	uint64_t bytes_done[DDIR_RWDIR_CNT] = { 0, 0, 0 };
	struct fio_file *f;
	struct io_u *io_u;
	int ret, min_events;
	unsigned int i;

	dprint(FD_VERIFY, "starting loop\n");

	/*
	 * sync io first and invalidate cache, to make sure we really
	 * read from disk.
	 */
	for_each_file(td, f, i) {
		if (!fio_file_open(f))
			continue;
		if (fio_io_sync(td, f))
			break;
		if (file_invalidate_cache(td, f))
			break;
	}

	check_update_rusage(td);

	if (td->error)
		return;

	td_set_runstate(td, TD_VERIFYING);

	io_u = NULL;
	while (!td->terminate) {
		enum fio_ddir ddir;
		int ret2, full;

		update_tv_cache(td);
		check_update_rusage(td);

		if (runtime_exceeded(td, &td->tv_cache)) {
			__update_tv_cache(td);
			if (runtime_exceeded(td, &td->tv_cache)) {
				td->terminate = 1;
				break;
			}
		}

		if (flow_threshold_exceeded(td))
			continue;

		if (!td->o.experimental_verify) {
			io_u = __get_io_u(td);
			if (!io_u)
				break;

			if (get_next_verify(td, io_u)) {
				put_io_u(td, io_u);
				break;
			}

			if (td_io_prep(td, io_u)) {
				put_io_u(td, io_u);
				break;
			}
		} else {
			if (ddir_rw_sum(bytes_done) + td->o.rw_min_bs > verify_bytes)
				break;

			while ((io_u = get_io_u(td)) != NULL) {
				if (IS_ERR(io_u)) {
					io_u = NULL;
					ret = FIO_Q_BUSY;
					goto reap;
				}

				/*
				 * We are only interested in the places where
				 * we wrote or trimmed IOs. Turn those into
				 * reads for verification purposes.
				 */
				if (io_u->ddir == DDIR_READ) {
					/*
					 * Pretend we issued it for rwmix
					 * accounting
					 */
					td->io_issues[DDIR_READ]++;
					put_io_u(td, io_u);
					continue;
				} else if (io_u->ddir == DDIR_TRIM) {
					io_u->ddir = DDIR_READ;
					io_u->flags |= IO_U_F_TRIMMED;
					break;
				} else if (io_u->ddir == DDIR_WRITE) {
					io_u->ddir = DDIR_READ;
					break;
				} else {
					put_io_u(td, io_u);
					continue;
				}
			}

			if (!io_u)
				break;
		}

		if (td->o.verify_async)
			io_u->end_io = verify_io_u_async;
		else
			io_u->end_io = verify_io_u;

		ddir = io_u->ddir;

		ret = td_io_queue(td, io_u);
		switch (ret) {
		case FIO_Q_COMPLETED:
			if (io_u->error) {
				ret = -io_u->error;
				clear_io_u(td, io_u);
			} else if (io_u->resid) {
				int bytes = io_u->xfer_buflen - io_u->resid;

				/*
				 * zero read, fail
				 */
				if (!bytes) {
					td_verror(td, EIO, "full resid");
					put_io_u(td, io_u);
					break;
				}

				io_u->xfer_buflen = io_u->resid;
				io_u->xfer_buf += bytes;
				io_u->offset += bytes;

				if (ddir_rw(io_u->ddir))
					td->ts.short_io_u[io_u->ddir]++;

				f = io_u->file;
				if (io_u->offset == f->real_file_size)
					goto sync_done;

				requeue_io_u(td, &io_u);
			} else {
sync_done:
				ret = io_u_sync_complete(td, io_u, bytes_done);
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

		if (break_on_this_error(td, ddir, &ret))
			break;

		/*
		 * if we can queue more, do so. but check if there are
		 * completed io_u's first. Note that we can get BUSY even
		 * without IO queued, if the system is resource starved.
		 */
reap:
		full = queue_full(td) || (ret == FIO_Q_BUSY && td->cur_depth);
		if (full || !td->o.iodepth_batch_complete) {
			min_events = min(td->o.iodepth_batch_complete,
					 td->cur_depth);
			/*
			 * if the queue is full, we MUST reap at least 1 event
			 */
			if (full && !min_events)
				min_events = 1;

			do {
				/*
				 * Reap required number of io units, if any,
				 * and do the verification on them through
				 * the callback handler
				 */
				if (io_u_queued_complete(td, min_events, bytes_done) < 0) {
					ret = -1;
					break;
				}
			} while (full && (td->cur_depth > td->o.iodepth_low));
		}
		if (ret < 0)
			break;
	}

	check_update_rusage(td);

	if (!td->error) {
		min_events = td->cur_depth;

		if (min_events)
			ret = io_u_queued_complete(td, min_events, NULL);
	} else
		cleanup_pending_aio(td);

	td_set_runstate(td, TD_RUNNING);

	dprint(FD_VERIFY, "exiting loop\n");
}

static unsigned int exceeds_number_ios(struct thread_data *td)
{
	unsigned long long number_ios;

	if (!td->o.number_ios)
		return 0;

	number_ios = ddir_rw_sum(td->this_io_blocks);
	number_ios += td->io_u_queued + td->io_u_in_flight;

	return number_ios >= td->o.number_ios;
}

static int io_bytes_exceeded(struct thread_data *td)
{
	unsigned long long bytes, limit;

	if (td_rw(td))
		bytes = td->this_io_bytes[DDIR_READ] + td->this_io_bytes[DDIR_WRITE];
	else if (td_write(td))
		bytes = td->this_io_bytes[DDIR_WRITE];
	else if (td_read(td))
		bytes = td->this_io_bytes[DDIR_READ];
	else
		bytes = td->this_io_bytes[DDIR_TRIM];

	if (td->o.io_limit)
		limit = td->o.io_limit;
	else
		limit = td->o.size;

	return bytes >= limit || exceeds_number_ios(td);
}

/*
 * Main IO worker function. It retrieves io_u's to process and queues
 * and reaps them, checking for rate and errors along the way.
 *
 * Returns number of bytes written and trimmed.
 */
static uint64_t do_io(struct thread_data *td)
{
	uint64_t bytes_done[DDIR_RWDIR_CNT] = { 0, 0, 0 };
	unsigned int i;
	int ret = 0;
	uint64_t total_bytes, bytes_issued = 0;

	if (in_ramp_time(td))
		td_set_runstate(td, TD_RAMP);
	else
		td_set_runstate(td, TD_RUNNING);

	lat_target_init(td);

	/*
	 * If verify_backlog is enabled, we'll run the verify in this
	 * handler as well. For that case, we may need up to twice the
	 * amount of bytes.
	 */
	total_bytes = td->o.size;
	if (td->o.verify != VERIFY_NONE &&
	   (td_write(td) && td->o.verify_backlog))
		total_bytes += td->o.size;

	while ((td->o.read_iolog_file && !flist_empty(&td->io_log_list)) ||
		(!flist_empty(&td->trim_list)) || !io_bytes_exceeded(td) ||
		td->o.time_based) {
		struct timeval comp_time;
		int min_evts = 0;
		struct io_u *io_u;
		int ret2, full;
		enum fio_ddir ddir;

		check_update_rusage(td);

		if (td->terminate || td->done)
			break;

		update_tv_cache(td);

		if (runtime_exceeded(td, &td->tv_cache)) {
			__update_tv_cache(td);
			if (runtime_exceeded(td, &td->tv_cache)) {
				td->terminate = 1;
				break;
			}
		}

		if (flow_threshold_exceeded(td))
			continue;

		if (bytes_issued >= total_bytes)
			break;

		io_u = get_io_u(td);
		if (IS_ERR_OR_NULL(io_u)) {
			int err = PTR_ERR(io_u);

			io_u = NULL;
			if (err == -EBUSY) {
				ret = FIO_Q_BUSY;
				goto reap;
			}
			if (td->o.latency_target)
				goto reap;
			break;
		}

		ddir = io_u->ddir;

		/*
		 * Add verification end_io handler if:
		 *	- Asked to verify (!td_rw(td))
		 *	- Or the io_u is from our verify list (mixed write/ver)
		 */
		if (td->o.verify != VERIFY_NONE && io_u->ddir == DDIR_READ &&
		    ((io_u->flags & IO_U_F_VER_LIST) || !td_rw(td))) {

			if (!td->o.verify_pattern_bytes) {
				io_u->rand_seed = __rand(&td->__verify_state);
				if (sizeof(int) != sizeof(long *))
					io_u->rand_seed *= __rand(&td->__verify_state);
			}

			if (td->o.verify_async)
				io_u->end_io = verify_io_u_async;
			else
				io_u->end_io = verify_io_u;
			td_set_runstate(td, TD_VERIFYING);
		} else if (in_ramp_time(td))
			td_set_runstate(td, TD_RAMP);
		else
			td_set_runstate(td, TD_RUNNING);

		/*
		 * Always log IO before it's issued, so we know the specific
		 * order of it. The logged unit will track when the IO has
		 * completed.
		 */
		if (td_write(td) && io_u->ddir == DDIR_WRITE &&
		    td->o.do_verify &&
		    td->o.verify != VERIFY_NONE &&
		    !td->o.experimental_verify)
			log_io_piece(td, io_u);

		ret = td_io_queue(td, io_u);
		switch (ret) {
		case FIO_Q_COMPLETED:
			if (io_u->error) {
				ret = -io_u->error;
				unlog_io_piece(td, io_u);
				clear_io_u(td, io_u);
			} else if (io_u->resid) {
				int bytes = io_u->xfer_buflen - io_u->resid;
				struct fio_file *f = io_u->file;

				bytes_issued += bytes;

				trim_io_piece(td, io_u);

				/*
				 * zero read, fail
				 */
				if (!bytes) {
					unlog_io_piece(td, io_u);
					td_verror(td, EIO, "full resid");
					put_io_u(td, io_u);
					break;
				}

				io_u->xfer_buflen = io_u->resid;
				io_u->xfer_buf += bytes;
				io_u->offset += bytes;

				if (ddir_rw(io_u->ddir))
					td->ts.short_io_u[io_u->ddir]++;

				if (io_u->offset == f->real_file_size)
					goto sync_done;

				requeue_io_u(td, &io_u);
			} else {
sync_done:
				if (__should_check_rate(td, DDIR_READ) ||
				    __should_check_rate(td, DDIR_WRITE) ||
				    __should_check_rate(td, DDIR_TRIM))
					fio_gettime(&comp_time, NULL);

				ret = io_u_sync_complete(td, io_u, bytes_done);
				if (ret < 0)
					break;
				bytes_issued += io_u->xfer_buflen;
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
			bytes_issued += io_u->xfer_buflen;
			break;
		case FIO_Q_BUSY:
			unlog_io_piece(td, io_u);
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

		if (break_on_this_error(td, ddir, &ret))
			break;

		/*
		 * See if we need to complete some commands. Note that we
		 * can get BUSY even without IO queued, if the system is
		 * resource starved.
		 */
reap:
		full = queue_full(td) || (ret == FIO_Q_BUSY && td->cur_depth);
		if (full || !td->o.iodepth_batch_complete) {
			min_evts = min(td->o.iodepth_batch_complete,
					td->cur_depth);
			/*
			 * if the queue is full, we MUST reap at least 1 event
			 */
			if (full && !min_evts)
				min_evts = 1;

			if (__should_check_rate(td, DDIR_READ) ||
			    __should_check_rate(td, DDIR_WRITE) ||
			    __should_check_rate(td, DDIR_TRIM))
				fio_gettime(&comp_time, NULL);

			do {
				ret = io_u_queued_complete(td, min_evts, bytes_done);
				if (ret < 0)
					break;

			} while (full && (td->cur_depth > td->o.iodepth_low));
		}

		if (ret < 0)
			break;
		if (!ddir_rw_sum(bytes_done) && !(td->io_ops->flags & FIO_NOIO))
			continue;

		if (!in_ramp_time(td) && should_check_rate(td, bytes_done)) {
			if (check_min_rate(td, &comp_time, bytes_done)) {
				if (exitall_on_terminate)
					fio_terminate_threads(td->groupid);
				td_verror(td, EIO, "check_min_rate");
				break;
			}
		}
		if (!in_ramp_time(td) && td->o.latency_target)
			lat_target_check(td);

		if (td->o.thinktime) {
			unsigned long long b;

			b = ddir_rw_sum(td->io_blocks);
			if (!(b % td->o.thinktime_blocks)) {
				int left;

				io_u_quiesce(td);

				if (td->o.thinktime_spin)
					usec_spin(td->o.thinktime_spin);

				left = td->o.thinktime - td->o.thinktime_spin;
				if (left)
					usec_sleep(td, left);
			}
		}
	}

	check_update_rusage(td);

	if (td->trim_entries)
		log_err("fio: %lu trim entries leaked?\n", td->trim_entries);

	if (td->o.fill_device && td->error == ENOSPC) {
		td->error = 0;
		td->terminate = 1;
	}
	if (!td->error) {
		struct fio_file *f;

		i = td->cur_depth;
		if (i) {
			ret = io_u_queued_complete(td, i, bytes_done);
			if (td->o.fill_device && td->error == ENOSPC)
				td->error = 0;
		}

		if (should_fsync(td) && td->o.end_fsync) {
			td_set_runstate(td, TD_FSYNCING);

			for_each_file(td, f, i) {
				if (!fio_file_fsync(td, f))
					continue;

				log_err("fio: end_fsync failed for file %s\n",
								f->file_name);
			}
		}
	} else
		cleanup_pending_aio(td);

	/*
	 * stop job if we failed doing any IO
	 */
	if (!ddir_rw_sum(td->this_io_bytes))
		td->done = 1;

	return bytes_done[DDIR_WRITE] + bytes_done[DDIR_TRIM];
}

static void cleanup_io_u(struct thread_data *td)
{
	struct io_u *io_u;

	while ((io_u = io_u_qpop(&td->io_u_freelist)) != NULL) {

		if (td->io_ops->io_u_free)
			td->io_ops->io_u_free(td, io_u);

		fio_memfree(io_u, sizeof(*io_u));
	}

	free_io_mem(td);

	io_u_rexit(&td->io_u_requeues);
	io_u_qexit(&td->io_u_freelist);
	io_u_qexit(&td->io_u_all);
}

static int init_io_u(struct thread_data *td)
{
	struct io_u *io_u;
	unsigned int max_bs, min_write;
	int cl_align, i, max_units;
	int data_xfer = 1, err;
	char *p;

	max_units = td->o.iodepth;
	max_bs = td_max_bs(td);
	min_write = td->o.min_bs[DDIR_WRITE];
	td->orig_buffer_size = (unsigned long long) max_bs
					* (unsigned long long) max_units;

	if ((td->io_ops->flags & FIO_NOIO) || !(td_read(td) || td_write(td)))
		data_xfer = 0;

	err = 0;
	err += io_u_rinit(&td->io_u_requeues, td->o.iodepth);
	err += io_u_qinit(&td->io_u_freelist, td->o.iodepth);
	err += io_u_qinit(&td->io_u_all, td->o.iodepth);

	if (err) {
		log_err("fio: failed setting up IO queues\n");
		return 1;
	}

	/*
	 * if we may later need to do address alignment, then add any
	 * possible adjustment here so that we don't cause a buffer
	 * overflow later. this adjustment may be too much if we get
	 * lucky and the allocator gives us an aligned address.
	 */
	if (td->o.odirect || td->o.mem_align || td->o.oatomic ||
	    (td->io_ops->flags & FIO_RAWIO))
		td->orig_buffer_size += page_mask + td->o.mem_align;

	if (td->o.mem_type == MEM_SHMHUGE || td->o.mem_type == MEM_MMAPHUGE) {
		unsigned long bs;

		bs = td->orig_buffer_size + td->o.hugepage_size - 1;
		td->orig_buffer_size = bs & ~(td->o.hugepage_size - 1);
	}

	if (td->orig_buffer_size != (size_t) td->orig_buffer_size) {
		log_err("fio: IO memory too large. Reduce max_bs or iodepth\n");
		return 1;
	}

	if (data_xfer && allocate_io_mem(td))
		return 1;

	if (td->o.odirect || td->o.mem_align || td->o.oatomic ||
	    (td->io_ops->flags & FIO_RAWIO))
		p = PAGE_ALIGN(td->orig_buffer) + td->o.mem_align;
	else
		p = td->orig_buffer;

	cl_align = os_cache_line_size();

	for (i = 0; i < max_units; i++) {
		void *ptr;

		if (td->terminate)
			return 1;

		ptr = fio_memalign(cl_align, sizeof(*io_u));
		if (!ptr) {
			log_err("fio: unable to allocate aligned memory\n");
			break;
		}

		io_u = ptr;
		memset(io_u, 0, sizeof(*io_u));
		INIT_FLIST_HEAD(&io_u->verify_list);
		dprint(FD_MEM, "io_u alloc %p, index %u\n", io_u, i);

		if (data_xfer) {
			io_u->buf = p;
			dprint(FD_MEM, "io_u %p, mem %p\n", io_u, io_u->buf);

			if (td_write(td))
				io_u_fill_buffer(td, io_u, min_write, max_bs);
			if (td_write(td) && td->o.verify_pattern_bytes) {
				/*
				 * Fill the buffer with the pattern if we are
				 * going to be doing writes.
				 */
				fill_verify_pattern(td, io_u->buf, max_bs, io_u, 0, 0);
			}
		}

		io_u->index = i;
		io_u->flags = IO_U_F_FREE;
		io_u_qpush(&td->io_u_freelist, io_u);

		/*
		 * io_u never leaves this stack, used for iteration of all
		 * io_u buffers.
		 */
		io_u_qpush(&td->io_u_all, io_u);

		if (td->io_ops->io_u_init) {
			int ret = td->io_ops->io_u_init(td, io_u);

			if (ret) {
				log_err("fio: failed to init engine data: %d\n", ret);
				return 1;
			}
		}

		p += max_bs;
	}

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
			log_err("fio: os or kernel doesn't support IO scheduler"
				" switching\n");
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
	ret = fread(tmp, sizeof(tmp), 1, f);
	if (ferror(f) || ret < 0) {
		td_verror(td, errno, "fread");
		fclose(f);
		return 1;
	}
	tmp[sizeof(tmp) - 1] = '\0';


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
	unsigned long long limit;

	if (td->done)
		return 0;
	if (td->o.time_based)
		return 1;
	if (td->o.loops) {
		td->o.loops--;
		return 1;
	}
	if (exceeds_number_ios(td))
		return 0;

	if (td->o.io_limit)
		limit = td->o.io_limit;
	else
		limit = td->o.size;

	if (limit != -1ULL && ddir_rw_sum(td->io_bytes) < limit) {
		uint64_t diff;

		/*
		 * If the difference is less than the minimum IO size, we
		 * are done.
		 */
		diff = limit - ddir_rw_sum(td->io_bytes);
		if (diff < td_max_bs(td))
			return 0;

		if (fio_files_done(td))
			return 0;

		return 1;
	}

	return 0;
}

static int exec_string(struct thread_options *o, const char *string, const char *mode)
{
	int ret, newlen = strlen(string) + strlen(o->name) + strlen(mode) + 9 + 1;
	char *str;

	str = malloc(newlen);
	sprintf(str, "%s &> %s.%s.txt", string, o->name, mode);

	log_info("%s : Saving output of %s in %s.%s.txt\n",o->name, mode, o->name, mode);
	ret = system(str);
	if (ret == -1)
		log_err("fio: exec of cmd <%s> failed\n", str);

	free(str);
	return ret;
}

/*
 * Dry run to compute correct state of numberio for verification.
 */
static uint64_t do_dry_run(struct thread_data *td)
{
	uint64_t bytes_done[DDIR_RWDIR_CNT] = { 0, 0, 0 };

	td_set_runstate(td, TD_RUNNING);

	while ((td->o.read_iolog_file && !flist_empty(&td->io_log_list)) ||
		(!flist_empty(&td->trim_list)) || !io_bytes_exceeded(td)) {
		struct io_u *io_u;
		int ret;

		if (td->terminate || td->done)
			break;

		io_u = get_io_u(td);
		if (!io_u)
			break;

		io_u->flags |= IO_U_F_FLIGHT;
		io_u->error = 0;
		io_u->resid = 0;
		if (ddir_rw(acct_ddir(io_u)))
			td->io_issues[acct_ddir(io_u)]++;
		if (ddir_rw(io_u->ddir)) {
			io_u_mark_depth(td, 1);
			td->ts.total_io_u[io_u->ddir]++;
		}

		if (td_write(td) && io_u->ddir == DDIR_WRITE &&
		    td->o.do_verify &&
		    td->o.verify != VERIFY_NONE &&
		    !td->o.experimental_verify)
			log_io_piece(td, io_u);

		ret = io_u_sync_complete(td, io_u, bytes_done);
		(void) ret;
	}

	return bytes_done[DDIR_WRITE] + bytes_done[DDIR_TRIM];
}

/*
 * Entry point for the thread based jobs. The process based jobs end up
 * here as well, after a little setup.
 */
static void *thread_main(void *data)
{
	unsigned long long elapsed;
	struct thread_data *td = data;
	struct thread_options *o = &td->o;
	pthread_condattr_t attr;
	int clear_state;
	int ret;

	if (!o->use_thread) {
		setsid();
		td->pid = getpid();
	} else
		td->pid = gettid();

	/*
	 * fio_time_init() may not have been called yet if running as a server
	 */
	fio_time_init();

	fio_local_clock_init(o->use_thread);

	dprint(FD_PROCESS, "jobs pid=%d started\n", (int) td->pid);

	if (is_backend)
		fio_server_send_start(td);

	INIT_FLIST_HEAD(&td->io_log_list);
	INIT_FLIST_HEAD(&td->io_hist_list);
	INIT_FLIST_HEAD(&td->verify_list);
	INIT_FLIST_HEAD(&td->trim_list);
	INIT_FLIST_HEAD(&td->next_rand_list);
	pthread_mutex_init(&td->io_u_lock, NULL);
	td->io_hist_tree = RB_ROOT;

	pthread_condattr_init(&attr);
	pthread_cond_init(&td->verify_cond, &attr);
	pthread_cond_init(&td->free_cond, &attr);

	td_set_runstate(td, TD_INITIALIZED);
	dprint(FD_MUTEX, "up startup_mutex\n");
	fio_mutex_up(startup_mutex);
	dprint(FD_MUTEX, "wait on td->mutex\n");
	fio_mutex_down(td->mutex);
	dprint(FD_MUTEX, "done waiting on td->mutex\n");

	/*
	 * A new gid requires privilege, so we need to do this before setting
	 * the uid.
	 */
	if (o->gid != -1U && setgid(o->gid)) {
		td_verror(td, errno, "setgid");
		goto err;
	}
	if (o->uid != -1U && setuid(o->uid)) {
		td_verror(td, errno, "setuid");
		goto err;
	}

	/*
	 * If we have a gettimeofday() thread, make sure we exclude that
	 * thread from this job
	 */
	if (o->gtod_cpu)
		fio_cpu_clear(&o->cpumask, o->gtod_cpu);

	/*
	 * Set affinity first, in case it has an impact on the memory
	 * allocations.
	 */
	if (o->cpumask_set) {
		if (o->cpus_allowed_policy == FIO_CPUS_SPLIT) {
			ret = fio_cpus_split(&o->cpumask, td->thread_number - 1);
			if (!ret) {
				log_err("fio: no CPUs set\n");
				log_err("fio: Try increasing number of available CPUs\n");
				td_verror(td, EINVAL, "cpus_split");
				goto err;
			}
		}
		ret = fio_setaffinity(td->pid, o->cpumask);
		if (ret == -1) {
			td_verror(td, errno, "cpu_set_affinity");
			goto err;
		}
	}

#ifdef CONFIG_LIBNUMA
	/* numa node setup */
	if (o->numa_cpumask_set || o->numa_memmask_set) {
		struct bitmask *mask;
		int ret;

		if (numa_available() < 0) {
			td_verror(td, errno, "Does not support NUMA API\n");
			goto err;
		}

		if (o->numa_cpumask_set) {
			mask = numa_parse_nodestring(o->numa_cpunodes);
			ret = numa_run_on_node_mask(mask);
			numa_free_nodemask(mask);
			if (ret == -1) {
				td_verror(td, errno, \
					"numa_run_on_node_mask failed\n");
				goto err;
			}
		}

		if (o->numa_memmask_set) {

			mask = NULL;
			if (o->numa_memnodes)
				mask = numa_parse_nodestring(o->numa_memnodes);

			switch (o->numa_mem_mode) {
			case MPOL_INTERLEAVE:
				numa_set_interleave_mask(mask);
				break;
			case MPOL_BIND:
				numa_set_membind(mask);
				break;
			case MPOL_LOCAL:
				numa_set_localalloc();
				break;
			case MPOL_PREFERRED:
				numa_set_preferred(o->numa_mem_prefer_node);
				break;
			case MPOL_DEFAULT:
			default:
				break;
			}

			if (mask)
				numa_free_nodemask(mask);

		}
	}
#endif

	if (fio_pin_memory(td))
		goto err;

	/*
	 * May alter parameters that init_io_u() will use, so we need to
	 * do this first.
	 */
	if (init_iolog(td))
		goto err;

	if (init_io_u(td))
		goto err;

	if (o->verify_async && verify_async_init(td))
		goto err;

	if (o->ioprio) {
		ret = ioprio_set(IOPRIO_WHO_PROCESS, 0, o->ioprio_class, o->ioprio);
		if (ret == -1) {
			td_verror(td, errno, "ioprio_set");
			goto err;
		}
	}

	if (o->cgroup && cgroup_setup(td, cgroup_list, &cgroup_mnt))
		goto err;

	errno = 0;
	if (nice(o->nice) == -1 && errno != 0) {
		td_verror(td, errno, "nice");
		goto err;
	}

	if (o->ioscheduler && switch_ioscheduler(td))
		goto err;

	if (!o->create_serialize && setup_files(td))
		goto err;

	if (td_io_init(td))
		goto err;

	if (init_random_map(td))
		goto err;

	if (o->exec_prerun && exec_string(o, o->exec_prerun, (const char *)"prerun"))
		goto err;

	if (o->pre_read) {
		if (pre_read_files(td) < 0)
			goto err;
	}

	fio_verify_init(td);

	fio_gettime(&td->epoch, NULL);
	fio_getrusage(&td->ru_start);
	clear_state = 0;
	while (keep_running(td)) {
		uint64_t verify_bytes;

		fio_gettime(&td->start, NULL);
		memcpy(&td->bw_sample_time, &td->start, sizeof(td->start));
		memcpy(&td->iops_sample_time, &td->start, sizeof(td->start));
		memcpy(&td->tv_cache, &td->start, sizeof(td->start));

		if (o->ratemin[DDIR_READ] || o->ratemin[DDIR_WRITE] ||
				o->ratemin[DDIR_TRIM]) {
		        memcpy(&td->lastrate[DDIR_READ], &td->bw_sample_time,
						sizeof(td->bw_sample_time));
		        memcpy(&td->lastrate[DDIR_WRITE], &td->bw_sample_time,
						sizeof(td->bw_sample_time));
		        memcpy(&td->lastrate[DDIR_TRIM], &td->bw_sample_time,
						sizeof(td->bw_sample_time));
		}

		if (clear_state)
			clear_io_state(td);

		prune_io_piece_log(td);

		if (td->o.verify_only && (td_write(td) || td_rw(td)))
			verify_bytes = do_dry_run(td);
		else
			verify_bytes = do_io(td);

		clear_state = 1;

		if (td_read(td) && td->io_bytes[DDIR_READ]) {
			elapsed = utime_since_now(&td->start);
			td->ts.runtime[DDIR_READ] += elapsed;
		}
		if (td_write(td) && td->io_bytes[DDIR_WRITE]) {
			elapsed = utime_since_now(&td->start);
			td->ts.runtime[DDIR_WRITE] += elapsed;
		}
		if (td_trim(td) && td->io_bytes[DDIR_TRIM]) {
			elapsed = utime_since_now(&td->start);
			td->ts.runtime[DDIR_TRIM] += elapsed;
		}

		if (td->error || td->terminate)
			break;

		if (!o->do_verify ||
		    o->verify == VERIFY_NONE ||
		    (td->io_ops->flags & FIO_UNIDIR))
			continue;

		clear_io_state(td);

		fio_gettime(&td->start, NULL);

		do_verify(td, verify_bytes);

		td->ts.runtime[DDIR_READ] += utime_since_now(&td->start);

		if (td->error || td->terminate)
			break;
	}

	update_rusage_stat(td);
	td->ts.runtime[DDIR_READ] = (td->ts.runtime[DDIR_READ] + 999) / 1000;
	td->ts.runtime[DDIR_WRITE] = (td->ts.runtime[DDIR_WRITE] + 999) / 1000;
	td->ts.runtime[DDIR_TRIM] = (td->ts.runtime[DDIR_TRIM] + 999) / 1000;
	td->ts.total_run_time = mtime_since_now(&td->epoch);
	td->ts.io_bytes[DDIR_READ] = td->io_bytes[DDIR_READ];
	td->ts.io_bytes[DDIR_WRITE] = td->io_bytes[DDIR_WRITE];
	td->ts.io_bytes[DDIR_TRIM] = td->io_bytes[DDIR_TRIM];

	fio_unpin_memory(td);

	fio_writeout_logs(td);

	if (o->exec_postrun)
		exec_string(o, o->exec_postrun, (const char *)"postrun");

	if (exitall_on_terminate)
		fio_terminate_threads(td->groupid);

err:
	if (td->error)
		log_info("fio: pid=%d, err=%d/%s\n", (int) td->pid, td->error,
							td->verror);

	if (o->verify_async)
		verify_async_exit(td);

	close_and_free_files(td);
	cleanup_io_u(td);
	close_ioengine(td);
	cgroup_shutdown(td, &cgroup_mnt);

	if (o->cpumask_set) {
		int ret = fio_cpuset_exit(&o->cpumask);

		td_verror(td, ret, "fio_cpuset_exit");
	}

	/*
	 * do this very late, it will log file closing as well
	 */
	if (o->write_iolog_file)
		write_iolog_close(td);

	fio_mutex_remove(td->rusage_sem);
	td->rusage_sem = NULL;

	fio_mutex_remove(td->mutex);
	td->mutex = NULL;

	td_set_runstate(td, TD_EXITED);
	return (void *) (uintptr_t) td->error;
}


/*
 * We cannot pass the td data into a forked process, so attach the td and
 * pass it to the thread worker.
 */
static int fork_main(int shmid, int offset)
{
	struct thread_data *td;
	void *data, *ret;

#ifndef __hpux
	data = shmat(shmid, NULL, 0);
	if (data == (void *) -1) {
		int __err = errno;

		perror("shmat");
		return __err;
	}
#else
	/*
	 * HP-UX inherits shm mappings?
	 */
	data = threads;
#endif

	td = data + offset * sizeof(struct thread_data);
	ret = thread_main(td);
	shmdt(data);
	return (int) (uintptr_t) ret;
}

/*
 * Run over the job map and reap the threads that have exited, if any.
 */
static void reap_threads(unsigned int *nr_running, unsigned int *t_rate,
			 unsigned int *m_rate)
{
	struct thread_data *td;
	unsigned int cputhreads, realthreads, pending;
	int i, status, ret;

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

		if (!td->pid) {
			pending++;
			continue;
		}
		if (td->runstate == TD_REAPED)
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
				log_err("fio: pid=%d disappeared %d\n",
						(int) td->pid, td->runstate);
				td->sig = ECHILD;
				td_set_runstate(td, TD_REAPED);
				goto reaped;
			}
			perror("waitpid");
		} else if (ret == td->pid) {
			if (WIFSIGNALED(status)) {
				int sig = WTERMSIG(status);

				if (sig != SIGTERM && sig != SIGUSR2)
					log_err("fio: pid=%d, got signal=%d\n",
							(int) td->pid, sig);
				td->sig = sig;
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
		(*nr_running)--;
		(*m_rate) -= ddir_rw_sum(td->o.ratemin);
		(*t_rate) -= ddir_rw_sum(td->o.rate);
		if (!td->pid)
			pending--;

		if (td->error)
			exit_value++;

		done_secs += mtime_since_now(&td->epoch) / 1000;
		profile_td_exit(td);
	}

	if (*nr_running == cputhreads && !pending && realthreads)
		fio_terminate_threads(TERMINATE_ALL);
}

static void do_usleep(unsigned int usecs)
{
	check_for_running_stats();
	usleep(usecs);
}

/*
 * Main function for kicking off and reaping jobs, as needed.
 */
static void run_threads(void)
{
	struct thread_data *td;
	unsigned int i, todo, nr_running, m_rate, t_rate, nr_started;
	uint64_t spent;

	if (fio_gtod_offload && fio_start_gtod_thread())
		return;

	fio_idle_prof_init();

	set_sig_handlers();

	nr_thread = nr_process = 0;
	for_each_td(td, i) {
		if (td->o.use_thread)
			nr_thread++;
		else
			nr_process++;
	}

	if (output_format == FIO_OUTPUT_NORMAL) {
		log_info("Starting ");
		if (nr_thread)
			log_info("%d thread%s", nr_thread,
						nr_thread > 1 ? "s" : "");
		if (nr_process) {
			if (nr_thread)
				log_info(" and ");
			log_info("%d process%s", nr_process,
						nr_process > 1 ? "es" : "");
		}
		log_info("\n");
		fflush(stdout);
	}

	todo = thread_number;
	nr_running = 0;
	nr_started = 0;
	m_rate = t_rate = 0;

	for_each_td(td, i) {
		print_status_init(td->thread_number - 1);

		if (!td->o.create_serialize)
			continue;

		/*
		 * do file setup here so it happens sequentially,
		 * we don't want X number of threads getting their
		 * client data interspersed on disk
		 */
		if (setup_files(td)) {
			exit_value++;
			if (td->error)
				log_err("fio: pid=%d, err=%d/%s\n",
					(int) td->pid, td->error, td->verror);
			td_set_runstate(td, TD_REAPED);
			todo--;
		} else {
			struct fio_file *f;
			unsigned int j;

			/*
			 * for sharing to work, each job must always open
			 * its own files. so close them, if we opened them
			 * for creation
			 */
			for_each_file(td, f, j) {
				if (fio_file_open(f))
					td_io_close_file(td, f);
			}
		}
	}

	/* start idle threads before io threads start to run */
	fio_idle_prof_start();

	set_genesis_time();

	while (todo) {
		struct thread_data *map[REAL_MAX_JOBS];
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
				spent = utime_since_genesis();

				if (td->o.start_delay > spent)
					continue;
			}

			if (td->o.stonewall && (nr_started || nr_running)) {
				dprint(FD_PROCESS, "%s: stonewall wait\n",
							td->o.name);
				break;
			}

			init_disk_util(td);

			td->rusage_sem = fio_mutex_init(FIO_MUTEX_LOCKED);
			td->update_rusage = 0;

			/*
			 * Set state to created. Thread will transition
			 * to TD_INITIALIZED when it's done setting up.
			 */
			td_set_runstate(td, TD_CREATED);
			map[this_jobs++] = td;
			nr_started++;

			if (td->o.use_thread) {
				int ret;

				dprint(FD_PROCESS, "will pthread_create\n");
				ret = pthread_create(&td->thread, NULL,
							thread_main, td);
				if (ret) {
					log_err("pthread_create: %s\n",
							strerror(ret));
					nr_started--;
					break;
				}
				ret = pthread_detach(td->thread);
				if (ret)
					log_err("pthread_detach: %s",
							strerror(ret));
			} else {
				pid_t pid;
				dprint(FD_PROCESS, "will fork\n");
				pid = fork();
				if (!pid) {
					int ret = fork_main(shm_id, i);

					_exit(ret);
				} else if (i == fio_debug_jobno)
					*fio_debug_jobp = pid;
			}
			dprint(FD_MUTEX, "wait on startup_mutex\n");
			if (fio_mutex_down_timeout(startup_mutex, 10)) {
				log_err("fio: job startup hung? exiting.\n");
				fio_terminate_threads(TERMINATE_ALL);
				fio_abort = 1;
				nr_started--;
				break;
			}
			dprint(FD_MUTEX, "done waiting on startup_mutex\n");
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

			do_usleep(100000);

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
			log_err("fio: %d job%s failed to start\n", left,
					left > 1 ? "s" : "");
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

			if (in_ramp_time(td))
				td_set_runstate(td, TD_RAMP);
			else
				td_set_runstate(td, TD_RUNNING);
			nr_running++;
			nr_started--;
			m_rate += ddir_rw_sum(td->o.ratemin);
			t_rate += ddir_rw_sum(td->o.rate);
			todo--;
			fio_mutex_up(td->mutex);
		}

		reap_threads(&nr_running, &t_rate, &m_rate);

		if (todo)
			do_usleep(100000);
	}

	while (nr_running) {
		reap_threads(&nr_running, &t_rate, &m_rate);
		do_usleep(10000);
	}

	fio_idle_prof_stop();

	update_io_ticks();
}

void wait_for_disk_thread_exit(void)
{
	fio_mutex_down(disk_thread_mutex);
}

static void free_disk_util(void)
{
	disk_util_start_exit();
	wait_for_disk_thread_exit();
	disk_util_prune_entries();
}

static void *disk_thread_main(void *data)
{
	int ret = 0;

	fio_mutex_up(startup_mutex);

	while (threads && !ret) {
		usleep(DISK_UTIL_MSEC * 1000);
		if (!threads)
			break;
		ret = update_io_ticks();

		if (!is_backend)
			print_thread_status();
	}

	fio_mutex_up(disk_thread_mutex);
	return NULL;
}

static int create_disk_util_thread(void)
{
	int ret;

	setup_disk_util();

	disk_thread_mutex = fio_mutex_init(FIO_MUTEX_LOCKED);

	ret = pthread_create(&disk_util_thread, NULL, disk_thread_main, NULL);
	if (ret) {
		fio_mutex_remove(disk_thread_mutex);
		log_err("Can't create disk util thread: %s\n", strerror(ret));
		return 1;
	}

	ret = pthread_detach(disk_util_thread);
	if (ret) {
		fio_mutex_remove(disk_thread_mutex);
		log_err("Can't detatch disk util thread: %s\n", strerror(ret));
		return 1;
	}

	dprint(FD_MUTEX, "wait on startup_mutex\n");
	fio_mutex_down(startup_mutex);
	dprint(FD_MUTEX, "done waiting on startup_mutex\n");
	return 0;
}

int fio_backend(void)
{
	struct thread_data *td;
	int i;

	if (exec_profile) {
		if (load_profile(exec_profile))
			return 1;
		free(exec_profile);
		exec_profile = NULL;
	}
	if (!thread_number)
		return 0;

	if (write_bw_log) {
		setup_log(&agg_io_log[DDIR_READ], 0, IO_LOG_TYPE_BW);
		setup_log(&agg_io_log[DDIR_WRITE], 0, IO_LOG_TYPE_BW);
		setup_log(&agg_io_log[DDIR_TRIM], 0, IO_LOG_TYPE_BW);
	}

	startup_mutex = fio_mutex_init(FIO_MUTEX_LOCKED);
	if (startup_mutex == NULL)
		return 1;

	set_genesis_time();
	stat_init();
	create_disk_util_thread();

	cgroup_list = smalloc(sizeof(*cgroup_list));
	INIT_FLIST_HEAD(cgroup_list);

	run_threads();

	if (!fio_abort) {
		show_run_stats();
		if (write_bw_log) {
			__finish_log(agg_io_log[DDIR_READ], "agg-read_bw.log");
			__finish_log(agg_io_log[DDIR_WRITE],
					"agg-write_bw.log");
			__finish_log(agg_io_log[DDIR_TRIM],
					"agg-write_bw.log");
		}
	}

	for_each_td(td, i)
		fio_options_free(td);

	free_disk_util();
	cgroup_kill(cgroup_list);
	sfree(cgroup_list);
	sfree(cgroup_mnt);

	fio_mutex_remove(startup_mutex);
	fio_mutex_remove(disk_thread_mutex);
	stat_exit();
	return exit_value;
}
