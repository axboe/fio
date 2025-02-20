/*
 * Read a file and write the contents to stdout. If a given read takes
 * longer than 'max_us' time, then we schedule a new thread to handle
 * the next read. This avoids the coordinated omission problem, where
 * one request appears to take a long time, but in reality a lot of
 * requests would have been slow, but we don't notice since new submissions
 * are not being issued if just 1 is held up.
 *
 * One test case:
 *
 * $ time (./read-to-pipe-async -f randfile.gz | gzip -dc > outfile; sync)
 *
 * This will read randfile.gz and log the latencies of doing so, while
 * piping the output to gzip to decompress it. Any latencies over max_us
 * are logged when they happen, and latency buckets are displayed at the
 * end of the run
 *
 * gcc -Wall -g -O2 -o read-to-pipe-async read-to-pipe-async.c -lpthread
 *
 * Copyright (C) 2016 Jens Axboe
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>

#include "../flist.h"
#include "../log.h"

#include "compiler/compiler.h"

static int bs = 4096;
static int max_us = 10000;
static char *file;
static int separate_writer = 1;

#define PLAT_BITS	8
#define PLAT_VAL	(1 << PLAT_BITS)
#define PLAT_GROUP_NR	19
#define PLAT_NR		(PLAT_GROUP_NR * PLAT_VAL)
#define PLAT_LIST_MAX	20

#ifndef NDEBUG
#define CHECK_ZERO_OR_ABORT(code) assert(code)
#else
#define CHECK_ZERO_OR_ABORT(code) 										\
	do { 																\
		if (fio_unlikely((code) != 0)) { 								\
			log_err("failed checking code %i != 0", (code)); 	\
			abort();													\
		} 																\
	} while (0)
#endif

struct stats {
	unsigned int plat[PLAT_NR];
	unsigned int nr_samples;
	unsigned int max;
	unsigned int min;
	unsigned int over;
};

static double plist[PLAT_LIST_MAX] = { 50.0, 75.0, 90.0, 95.0, 99.0, 99.5, 99.9, 99.99, 99.999, 99.9999, };

struct thread_data {
	int exit;
	int done;
	pthread_mutex_t lock;
	pthread_cond_t cond;
	pthread_mutex_t done_lock;
	pthread_cond_t done_cond;
	pthread_t thread;
};

struct writer_thread {
	struct flist_head list;
	struct flist_head done_list;
	struct stats s;
	struct thread_data thread;
};

struct reader_thread {
	struct flist_head list;
	struct flist_head done_list;
	int started;
	int busy;
	int write_seq;
	struct stats s;
	struct thread_data thread;
};

struct work_item {
	struct flist_head list;
	void *buf;
	size_t buf_size;
	off_t off;
	int fd;
	int seq;
	struct writer_thread *writer;
	struct reader_thread *reader;
	pthread_mutex_t lock;
	pthread_cond_t cond;
	pthread_t thread;
};

static struct reader_thread reader_thread;
static struct writer_thread writer_thread;

uint64_t utime_since(const struct timespec *s, const struct timespec *e)
{
	long sec, usec;
	uint64_t ret;

	sec = e->tv_sec - s->tv_sec;
	usec = (e->tv_nsec - s->tv_nsec) / 1000;
	if (sec > 0 && usec < 0) {
		sec--;
		usec += 1000000;
	}

	if (sec < 0 || (sec == 0 && usec < 0))
		return 0;

	ret = sec * 1000000ULL + usec;

	return ret;
}

static struct work_item *find_seq(struct writer_thread *w, int seq)
{
	struct work_item *work;
	struct flist_head *entry;

	if (flist_empty(&w->list))
		return NULL;

	flist_for_each(entry, &w->list) {
		work = flist_entry(entry, struct work_item, list);
		if (work->seq == seq)
			return work;
	}

	return NULL;
}

static unsigned int plat_val_to_idx(unsigned int val)
{
	unsigned int msb, error_bits, base, offset;

	/* Find MSB starting from bit 0 */
	if (val == 0)
		msb = 0;
	else
		msb = sizeof(val)*8 - __builtin_clz(val) - 1;

	/*
	 * MSB <= (PLAT_BITS-1), cannot be rounded off. Use
	 * all bits of the sample as index
	 */
	if (msb <= PLAT_BITS)
		return val;

	/* Compute the number of error bits to discard*/
	error_bits = msb - PLAT_BITS;

	/* Compute the number of buckets before the group */
	base = (error_bits + 1) << PLAT_BITS;

	/*
	 * Discard the error bits and apply the mask to find the
	 * index for the buckets in the group
	 */
	offset = (PLAT_VAL - 1) & (val >> error_bits);

	/* Make sure the index does not exceed (array size - 1) */
	return (base + offset) < (PLAT_NR - 1) ?
		(base + offset) : (PLAT_NR - 1);
}

/*
 * Convert the given index of the bucket array to the value
 * represented by the bucket
 */
static unsigned int plat_idx_to_val(unsigned int idx)
{
	unsigned int error_bits, k, base;

	assert(idx < PLAT_NR);

	/* MSB <= (PLAT_BITS-1), cannot be rounded off. Use
	 * all bits of the sample as index */
	if (idx < (PLAT_VAL << 1))
		return idx;

	/* Find the group and compute the minimum value of that group */
	error_bits = (idx >> PLAT_BITS) - 1;
	base = 1 << (error_bits + PLAT_BITS);

	/* Find its bucket number of the group */
	k = idx % PLAT_VAL;

	/* Return the mean of the range of the bucket */
	return base + ((k + 0.5) * (1 << error_bits));
}

static void add_lat(struct stats *s, unsigned int us, const char *name)
{
	int lat_index = 0;

	if (us > s->max)
		s->max = us;
	if (us < s->min)
		s->min = us;

	if (us > max_us) {
		fprintf(stderr, "%s latency=%u usec\n", name, us);
		s->over++;
	}

	lat_index = plat_val_to_idx(us);
	__sync_fetch_and_add(&s->plat[lat_index], 1);
	__sync_fetch_and_add(&s->nr_samples, 1);
}

static int write_work(struct work_item *work)
{
	struct timespec s, e;
	ssize_t ret;

	clock_gettime(CLOCK_MONOTONIC, &s);
	ret = write(STDOUT_FILENO, work->buf, work->buf_size);
	if (ret < 0)
		return (int)ret;
	clock_gettime(CLOCK_MONOTONIC, &e);
	assert(ret == work->buf_size);

	add_lat(&work->writer->s, utime_since(&s, &e), "write");
	return work->seq + 1;
}

static void thread_exiting(struct thread_data *thread)
{
	__sync_fetch_and_add(&thread->done, 1);
	pthread_cond_signal(&thread->done_cond);
}

static void *writer_fn(void *data)
{
	struct writer_thread *wt = data;
	struct work_item *work;
	int seq = 1;

	work = NULL;
	while (!(seq < 0) && (!wt->thread.exit || !flist_empty(&wt->list))) {
		pthread_mutex_lock(&wt->thread.lock);

		if (work)
			flist_add_tail(&work->list, &wt->done_list);
	
		work = find_seq(wt, seq);
		if (work)
			flist_del_init(&work->list);
		else
			pthread_cond_wait(&wt->thread.cond, &wt->thread.lock);

		pthread_mutex_unlock(&wt->thread.lock);

		if (work)
			seq = write_work(work);
	}

	thread_exiting(&wt->thread);
	return NULL;
}

static void reader_work(struct work_item *work)
{
	struct timespec s, e;
	ssize_t ret;
	size_t left;
	void *buf;
	off_t off;

	clock_gettime(CLOCK_MONOTONIC, &s);

	left = work->buf_size;
	buf = work->buf;
	off = work->off;
	while (left) {
		ret = pread(work->fd, buf, left, off);
		if (!ret) {
			fprintf(stderr, "zero read\n");
			break;
		} else if (ret < 0) {
			fprintf(stderr, "errno=%d\n", errno);
			break;
		}
		left -= ret;
		off += ret;
		buf += ret;
	}

	clock_gettime(CLOCK_MONOTONIC, &e);

	add_lat(&work->reader->s, utime_since(&s, &e), "read");

	pthread_cond_signal(&work->cond);

	if (separate_writer) {
		pthread_mutex_lock(&work->writer->thread.lock);
		flist_add_tail(&work->list, &work->writer->list);
		pthread_mutex_unlock(&work->writer->thread.lock);
		pthread_cond_signal(&work->writer->thread.cond);
	} else {
		struct reader_thread *rt = work->reader;
		struct work_item *next = NULL;
		struct flist_head *entry;

		/*
		 * Write current work if it matches in sequence.
		 */
		if (work->seq == rt->write_seq)
			goto write_it;

		pthread_mutex_lock(&rt->thread.lock);

		flist_add_tail(&work->list, &rt->done_list);

		/*
		 * See if the next work item is here, if so, write it
		 */
		work = NULL;
		flist_for_each(entry, &rt->done_list) {
			next = flist_entry(entry, struct work_item, list);
			if (next->seq == rt->write_seq) {
				work = next;
				flist_del(&work->list);
				break;
			}
		}

		pthread_mutex_unlock(&rt->thread.lock);
	
		if (work) {
write_it:
			write_work(work);
			__sync_fetch_and_add(&rt->write_seq, 1);
		}
	}
}

static void *reader_one_off(void *data)
{
	reader_work(data);
	return NULL;
}

static void *reader_fn(void *data)
{
	struct reader_thread *rt = data;
	struct work_item *work;

	while (!rt->thread.exit || !flist_empty(&rt->list)) {
		work = NULL;
		pthread_mutex_lock(&rt->thread.lock);
		if (!flist_empty(&rt->list)) {
			work = flist_first_entry(&rt->list, struct work_item, list);
			flist_del_init(&work->list);
		} else
			pthread_cond_wait(&rt->thread.cond, &rt->thread.lock);
		pthread_mutex_unlock(&rt->thread.lock);

		if (work) {
			__sync_fetch_and_add(&rt->busy, 1);
			reader_work(work);
			__sync_fetch_and_sub(&rt->busy, 1);
		}
	}

	thread_exiting(&rt->thread);
	return NULL;
}

static void queue_work(struct reader_thread *rt, struct work_item *work)
{
	if (!rt->started) {
		pthread_mutex_lock(&rt->thread.lock);
		flist_add_tail(&work->list, &rt->list);
		pthread_mutex_unlock(&rt->thread.lock);

		rt->started = 1;
		pthread_create(&rt->thread.thread, NULL, reader_fn, rt);
	} else if (!rt->busy && !pthread_mutex_trylock(&rt->thread.lock)) {
		flist_add_tail(&work->list, &rt->list);
		pthread_mutex_unlock(&rt->thread.lock);

		pthread_cond_signal(&rt->thread.cond);
	} else {
		int ret = pthread_create(&work->thread, NULL, reader_one_off, work);
		if (ret) {
			fprintf(stderr, "pthread_create=%d\n", ret);
		} else {
			ret = pthread_detach(work->thread);
			if (ret)
				fprintf(stderr, "pthread_detach=%d\n", ret);
		}
	}
}

static unsigned int calc_percentiles(unsigned int *io_u_plat, unsigned long nr,
				     unsigned int **output)
{
	unsigned long sum = 0;
	unsigned int len, i, j = 0;
	unsigned int oval_len = 0;
	unsigned int *ovals = NULL;
	int is_last;

	len = 0;
	while (len < PLAT_LIST_MAX && plist[len] != 0.0)
		len++;

	if (!len)
		return 0;

	/*
	 * Calculate bucket values, note down max and min values
	 */
	is_last = 0;
	for (i = 0; i < PLAT_NR && !is_last; i++) {
		sum += io_u_plat[i];
		while (sum >= (plist[j] / 100.0 * nr)) {
			assert(plist[j] <= 100.0);

			if (j == oval_len) {
				oval_len += 100;
				ovals = realloc(ovals, oval_len * sizeof(unsigned int));
			}

			ovals[j] = plat_idx_to_val(i);
			is_last = (j == len - 1);
			if (is_last)
				break;

			j++;
		}
	}

	*output = ovals;
	return len;
}

static void show_latencies(struct stats *s, const char *msg)
{
	unsigned int *ovals = NULL;
	unsigned int len, i;

	len = calc_percentiles(s->plat, s->nr_samples, &ovals);
	if (len) {
		fprintf(stderr, "Latency percentiles (usec) (%s)\n", msg);
		for (i = 0; i < len; i++)
			fprintf(stderr, "\t%2.4fth: %u\n", plist[i], ovals[i]);
	}

	if (ovals)
		free(ovals);

	fprintf(stderr, "\tOver=%u, min=%u, max=%u\n", s->over, s->min, s->max);
}

static void init_thread(struct thread_data *thread)
{
	pthread_condattr_t cattr;
	int ret;

	ret = pthread_condattr_init(&cattr);
	CHECK_ZERO_OR_ABORT(ret);
#ifdef CONFIG_PTHREAD_CONDATTR_SETCLOCK
	ret = pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC);
	CHECK_ZERO_OR_ABORT(ret);
#endif
	pthread_cond_init(&thread->cond, &cattr);
	pthread_cond_init(&thread->done_cond, &cattr);
	pthread_mutex_init(&thread->lock, NULL);
	pthread_mutex_init(&thread->done_lock, NULL);
	thread->exit = 0;
}

static void exit_thread(struct thread_data *thread,
			void fn(struct writer_thread *),
			struct writer_thread *wt)
{
	__sync_fetch_and_add(&thread->exit, 1);
	pthread_cond_signal(&thread->cond);

	while (!thread->done) {
		pthread_mutex_lock(&thread->done_lock);

		if (fn) {
			struct timespec ts;

#ifdef CONFIG_PTHREAD_CONDATTR_SETCLOCK
			clock_gettime(CLOCK_MONOTONIC, &ts);
#else
			clock_gettime(CLOCK_REALTIME, &ts);
#endif
			ts.tv_sec++;

			pthread_cond_timedwait(&thread->done_cond, &thread->done_lock, &ts);
			fn(wt);
		} else
			pthread_cond_wait(&thread->done_cond, &thread->done_lock);

		pthread_mutex_unlock(&thread->done_lock);
	}
}

static int usage(char *argv[])
{
	fprintf(stderr, "%s: [-b blocksize] [-t max usec] [-w separate writer] -f file\n", argv[0]);
	return 1;
}

static int parse_options(int argc, char *argv[])
{
	int c;

	while ((c = getopt(argc, argv, "f:b:t:w:")) != -1) {
		switch (c) {
		case 'f':
			if (file)
				return usage(argv);
			file = strdup(optarg);
			break;
		case 'b':
			bs = atoi(optarg);
			break;
		case 't':
			max_us = atoi(optarg);
			break;
		case 'w':
			separate_writer = atoi(optarg);
			if (!separate_writer)
				fprintf(stderr, "inline writing is broken\n");
			break;
		case '?':
		default:
			return usage(argv);
		}
	}

	if (!file)
		return usage(argv);

	return 0;
}

static void prune_done_entries(struct writer_thread *wt)
{
	FLIST_HEAD(list);

	if (flist_empty(&wt->done_list))
		return;

	if (pthread_mutex_trylock(&wt->thread.lock))
		return;

	if (!flist_empty(&wt->done_list))
		flist_splice_init(&wt->done_list, &list);
	pthread_mutex_unlock(&wt->thread.lock);

	while (!flist_empty(&list)) {
		struct work_item *work;

		work = flist_first_entry(&list, struct work_item, list);
		flist_del(&work->list);

		pthread_cond_destroy(&work->cond);
		pthread_mutex_destroy(&work->lock);
		free(work->buf);
		free(work);
	}
}

int main(int argc, char *argv[])
{
	pthread_condattr_t cattr;
	struct timespec s, re, we;
	struct reader_thread *rt;
	struct writer_thread *wt;
	unsigned long rate;
	uint64_t elapsed;
	struct stat sb;
	size_t bytes;
	off_t off;
	int fd, seq;
	int ret;

	if (parse_options(argc, argv))
		return 1;

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		perror("open");
		return 2;
	}

	if (fstat(fd, &sb) < 0) {
		perror("stat");
		return 3;
	}

	wt = &writer_thread;
	init_thread(&wt->thread);
	INIT_FLIST_HEAD(&wt->list);
	INIT_FLIST_HEAD(&wt->done_list);
	wt->s.max = 0;
	wt->s.min = -1U;
	pthread_create(&wt->thread.thread, NULL, writer_fn, wt);

	rt = &reader_thread;
	init_thread(&rt->thread);
	INIT_FLIST_HEAD(&rt->list);
	INIT_FLIST_HEAD(&rt->done_list);
	rt->s.max = 0;
	rt->s.min = -1U;
	rt->write_seq = 1;

	off = 0;
	seq = 0;
	bytes = 0;

	ret = pthread_condattr_init(&cattr);
	CHECK_ZERO_OR_ABORT(ret);
#ifdef CONFIG_PTHREAD_CONDATTR_SETCLOCK
	ret = pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC);
	CHECK_ZERO_OR_ABORT(ret);
#endif

	clock_gettime(CLOCK_MONOTONIC, &s);

	while (sb.st_size) {
		struct work_item *work;
		size_t this_len;
		struct timespec ts;

		prune_done_entries(wt);

		this_len = sb.st_size;
		if (this_len > bs)
			this_len = bs;

		work = calloc(1, sizeof(*work));
		work->buf = malloc(this_len);
		work->buf_size = this_len;
		work->off = off;
		work->fd = fd;
		work->seq = ++seq;
		work->writer = wt;
		work->reader = rt;
		pthread_cond_init(&work->cond, &cattr);
		pthread_mutex_init(&work->lock, NULL);

		queue_work(rt, work);

#ifdef CONFIG_PTHREAD_CONDATTR_SETCLOCK
		clock_gettime(CLOCK_MONOTONIC, &ts);
#else
		clock_gettime(CLOCK_REALTIME, &ts);
#endif
		ts.tv_nsec += max_us * 1000ULL;
		if (ts.tv_nsec >= 1000000000ULL) {
			ts.tv_nsec -= 1000000000ULL;
			ts.tv_sec++;
		}

		pthread_mutex_lock(&work->lock);
		pthread_cond_timedwait(&work->cond, &work->lock, &ts);
		pthread_mutex_unlock(&work->lock);

		off += this_len;
		sb.st_size -= this_len;
		bytes += this_len;
	}

	exit_thread(&rt->thread, NULL, NULL);
	clock_gettime(CLOCK_MONOTONIC, &re);

	exit_thread(&wt->thread, prune_done_entries, wt);
	clock_gettime(CLOCK_MONOTONIC, &we);

	show_latencies(&rt->s, "READERS");
	show_latencies(&wt->s, "WRITERS");

	bytes /= 1024;
	elapsed = utime_since(&s, &re);
	rate = elapsed ? (bytes * 1000UL * 1000UL) / elapsed : 0;
	fprintf(stderr, "Read rate (KiB/sec) : %lu\n", rate);
	elapsed = utime_since(&s, &we);
	rate = elapsed ? (bytes * 1000UL * 1000UL) / elapsed : 0;
	fprintf(stderr, "Write rate (KiB/sec): %lu\n", rate);

	close(fd);
	return 0;
}
