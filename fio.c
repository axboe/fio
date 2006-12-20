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
#include <assert.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "fio.h"
#include "os.h"

#define MASK	(4095)

#define ALIGN(buf)	(char *) (((unsigned long) (buf) + MASK) & ~(MASK))

int groupid = 0;
int thread_number = 0;
int shm_id = 0;
int temp_stall_ts;

static volatile int startup_sem;

#define TERMINATE_ALL		(-1)
#define JOB_START_TIMEOUT	(5 * 1000)

static void terminate_threads(int group_id)
{
	struct thread_data *td;
	int i;

	for_each_td(td, i) {
		if (group_id == TERMINATE_ALL || groupid == td->groupid) {
			td->terminate = 1;
			td->start_delay = 0;
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
			printf("\nfio: terminating on signal\n");
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

static inline void td_set_runstate(struct thread_data *td, int runstate)
{
	td->runstate = runstate;
}

static struct fio_file *get_next_file(struct thread_data *td)
{
	unsigned int old_next_file = td->next_file;
	struct fio_file *f;

	do {
		f = &td->files[td->next_file];

		td->next_file++;
		if (td->next_file >= td->nr_files)
			td->next_file = 0;

		if (f->fd != -1)
			break;

		f = NULL;
	} while (td->next_file != old_next_file);

	return f;
}

/*
 * When job exits, we can cancel the in-flight IO if we are using async
 * io. Attempt to do so.
 */
static void cleanup_pending_aio(struct thread_data *td)
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 0};
	struct list_head *entry, *n;
	struct io_completion_data icd;
	struct io_u *io_u;
	int r;

	/*
	 * get immediately available events, if any
	 */
	r = td_io_getevents(td, 0, td->cur_depth, &ts);
	if (r > 0) {
		icd.nr = r;
		ios_completed(td, &icd);
	}

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

	if (td->cur_depth) {
		r = td_io_getevents(td, td->cur_depth, td->cur_depth, NULL);
		if (r > 0) {
			icd.nr = r;
			ios_completed(td, &icd);
		}
	}
}

/*
 * Helper to handle the final sync of a file. Works just like the normal
 * io path, just does everything sync.
 */
static int fio_io_sync(struct thread_data *td, struct fio_file *f)
{
	struct io_u *io_u = __get_io_u(td);
	struct io_completion_data icd;
	int ret;

	if (!io_u)
		return 1;

	io_u->ddir = DDIR_SYNC;
	io_u->file = f;

	if (td_io_prep(td, io_u)) {
		put_io_u(td, io_u);
		return 1;
	}

	ret = td_io_queue(td, io_u);
	if (ret) {
		td_verror(td, io_u->error);
		put_io_u(td, io_u);
		return 1;
	}

	ret = td_io_getevents(td, 1, td->cur_depth, NULL);
	if (ret < 0) {
		td_verror(td, ret);
		return 1;
	}

	icd.nr = ret;
	ios_completed(td, &icd);
	if (icd.error) {
		td_verror(td, icd.error);
		return 1;
	}

	return 0;
}

/*
 * The main verify engine. Runs over the writes we previusly submitted,
 * reads the blocks back in, and checks the crc/md5 of the data.
 */
static void do_verify(struct thread_data *td)
{
	struct io_u *io_u, *v_io_u = NULL;
	struct io_completion_data icd;
	struct fio_file *f;
	int ret, i;

	/*
	 * sync io first and invalidate cache, to make sure we really
	 * read from disk.
	 */
	for_each_file(td, f, i) {
		fio_io_sync(td, f);
		file_invalidate_cache(td, f);
	}

	td_set_runstate(td, TD_VERIFYING);

	do {
		if (td->terminate)
			break;

		io_u = __get_io_u(td);
		if (!io_u)
			break;

		if (runtime_exceeded(td, &io_u->start_time)) {
			put_io_u(td, io_u);
			break;
		}

		if (get_next_verify(td, io_u)) {
			put_io_u(td, io_u);
			break;
		}

		f = get_next_file(td);
		if (!f)
			break;

		io_u->file = f;

		if (td_io_prep(td, io_u)) {
			put_io_u(td, io_u);
			break;
		}

		ret = td_io_queue(td, io_u);
		if (ret) {
			td_verror(td, io_u->error);
			put_io_u(td, io_u);
			break;
		}

		/*
		 * we have one pending to verify, do that while
		 * we are doing io on the next one
		 */
		if (do_io_u_verify(td, &v_io_u))
			break;

		ret = td_io_getevents(td, 1, 1, NULL);
		if (ret != 1) {
			if (ret < 0)
				td_verror(td, ret);
			break;
		}

		v_io_u = td->io_ops->event(td, 0);
		icd.nr = 1;
		icd.error = 0;
		fio_gettime(&icd.time, NULL);
		io_completed(td, v_io_u, &icd);

		if (icd.error) {
			td_verror(td, icd.error);
			put_io_u(td, v_io_u);
			v_io_u = NULL;
			break;
		}

		/*
		 * if we can't submit more io, we need to verify now
		 */
		if (queue_full(td) && do_io_u_verify(td, &v_io_u))
			break;

	} while (1);

	do_io_u_verify(td, &v_io_u);

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
	struct io_completion_data icd;
	struct timeval s;
	unsigned long usec;
	struct fio_file *f;
	int i, ret = 0;

	td_set_runstate(td, TD_RUNNING);

	while (td->this_io_bytes[td->ddir] < td->io_size) {
		struct timespec ts = { .tv_sec = 0, .tv_nsec = 0};
		struct timespec *timeout;
		int min_evts = 0;
		struct io_u *io_u;

		if (td->terminate)
			break;

		f = get_next_file(td);
		if (!f)
			break;

		io_u = get_io_u(td, f);
		if (!io_u)
			break;

		memcpy(&s, &io_u->start_time, sizeof(s));

		ret = td_io_queue(td, io_u);
		if (ret) {
			td_verror(td, io_u->error);
			put_io_u(td, io_u);
			break;
		}

		add_slat_sample(td, io_u->ddir, mtime_since(&io_u->start_time, &io_u->issue_time));

		if (td->cur_depth < td->iodepth) {
			timeout = &ts;
			min_evts = 0;
		} else {
			timeout = NULL;
			min_evts = 1;
		}

		ret = td_io_getevents(td, min_evts, td->cur_depth, timeout);
		if (ret < 0) {
			td_verror(td, ret);
			break;
		} else if (!ret)
			continue;

		icd.nr = ret;
		ios_completed(td, &icd);
		if (icd.error) {
			td_verror(td, icd.error);
			break;
		}

		/*
		 * the rate is batched for now, it should work for batches
		 * of completions except the very first one which may look
		 * a little bursty
		 */
		usec = utime_since(&s, &icd.time);

		rate_throttle(td, usec, icd.bytes_done[td->ddir], td->ddir);

		if (check_min_rate(td, &icd.time)) {
			if (exitall_on_terminate)
				terminate_threads(td->groupid);
			td_verror(td, ENOMEM);
			break;
		}

		if (runtime_exceeded(td, &icd.time))
			break;

		if (td->thinktime)
			usec_sleep(td, td->thinktime);
	}

	if (!td->error) {
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
		td->orig_buffer_size += MASK;

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

	td->stat_io_bytes[0] = td->stat_io_bytes[1] = 0;
	td->this_io_bytes[0] = td->this_io_bytes[1] = 0;
	td->zone_bytes = 0;

	for_each_file(td, f, i) {
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
	INIT_LIST_HEAD(&td->io_hist_list);
	INIT_LIST_HEAD(&td->io_log_list);

	if (init_io_u(td))
		goto err;

	if (fio_setaffinity(td) == -1) {
		td_verror(td, errno);
		goto err;
	}

	if (td_io_init(td))
		goto err;

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

	if (td->exec_prerun)
		system(td->exec_prerun);

	fio_gettime(&td->epoch, NULL);
	getrusage(RUSAGE_SELF, &td->ru_start);

	runtime[0] = runtime[1] = 0;
	while (td->loops--) {
		fio_gettime(&td->start, NULL);
		memcpy(&td->stat_sample_time, &td->start, sizeof(td->start));

		if (td->ratemin)
			memcpy(&td->lastrate, &td->stat_sample_time, sizeof(td->lastrate));

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

	if (td->bw_log)
		finish_log(td, td->bw_log, "bw");
	if (td->slat_log)
		finish_log(td, td->slat_log, "slat");
	if (td->clat_log)
		finish_log(td, td->clat_log, "clat");
	if (td->write_iolog_file)
		write_iolog_close(td);
	if (td->exec_postrun)
		system(td->exec_postrun);

	if (exitall_on_terminate)
		terminate_threads(td->groupid);

err:
	close_files(td);
	close_ioengine(td);
	cleanup_io_u(td);
	td_set_runstate(td, TD_EXITED);
	return NULL;

}

/*
 * We cannot pass the td data into a forked process, so attach the td and
 * pass it to the thread worker.
 */
static void *fork_main(int shmid, int offset)
{
	struct thread_data *td;
	void *data;

	data = shmat(shmid, NULL, 0);
	if (data == (void *) -1) {
		perror("shmat");
		return NULL;
	}

	td = data + offset * sizeof(struct thread_data);
	thread_main(td);
	shmdt(data);
	return NULL;
}

/*
 * Run over the job map and reap the threads that have exited, if any.
 */
static void reap_threads(int *nr_running, int *t_rate, int *m_rate)
{
	struct thread_data *td;
	int i, cputhreads, pending;

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

		if (td->runstate != TD_EXITED) {
			if (td->runstate < TD_RUNNING)
				pending++;

			continue;
		}

		td_set_runstate(td, TD_REAPED);

		if (td->use_thread) {
			long ret;

			if (pthread_join(td->thread, (void *) &ret))
				perror("thread_join");
		} else
			waitpid(td->pid, NULL, 0);

		(*nr_running)--;
		(*m_rate) -= td->ratemin;
		(*t_rate) -= td->rate;
	}

	if (*nr_running == cputhreads && !pending)
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

		init_disk_util(td);

		if (!td->create_serialize)
			continue;

		/*
		 * do file setup here so it happens sequentially,
		 * we don't want X number of threads getting their
		 * client data interspersed on disk
		 */
		if (setup_files(td)) {
			td_set_runstate(td, TD_REAPED);
			todo--;
		}
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
					fork_main(shm_id, i);
					exit(0);
				}
			}
		}

		/*
		 * Wait for the started threads to transition to
		 * TD_INITIALIZED.
		 */
		fio_gettime(&this_start, NULL);
		left = this_jobs;
		while (left) {
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
	if (parse_options(argc, argv))
		return 1;

	if (!thread_number) {
		log_err("Nothing to do\n");
		return 1;
	}

	disk_util_timer_arm();

	run_threads();
	show_run_stats();

	return 0;
}
