/*
 * fio - the flexible io tester
 *
 * Copyright (C) 2005 Jens Axboe <axboe@suse.de>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <math.h>
#include <assert.h>
#include <dirent.h>
#include <libgen.h>
#include <sys/types.h>
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
static char run_str[MAX_JOBS + 1];
int shm_id = 0;
static LIST_HEAD(disk_list);
static struct itimerval itimer;
static struct timeval genesis;

static void update_io_ticks(void);
static void disk_util_timer_arm(void);
static void print_thread_status(void);

/*
 * thread life cycle
 */
enum {
	TD_NOT_CREATED = 0,
	TD_CREATED,
	TD_RUNNING,
	TD_VERIFYING,
	TD_EXITED,
	TD_REAPED,
};

#define should_fsync(td)	(td_write(td) && (!(td)->odirect || (td)->override_sync))

static sem_t startup_sem;

#define TERMINATE_ALL		(-1)

static void terminate_threads(int group_id)
{
	int i;

	for (i = 0; i < thread_number; i++) {
		struct thread_data *td = &threads[i];

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

static unsigned long utime_since(struct timeval *s, struct timeval *e)
{
	double sec, usec;

	sec = e->tv_sec - s->tv_sec;
	usec = e->tv_usec - s->tv_usec;
	if (sec > 0 && usec < 0) {
		sec--;
		usec += 1000000;
	}

	sec *= (double) 1000000;

	return sec + usec;
}

static unsigned long utime_since_now(struct timeval *s)
{
	struct timeval t;

	gettimeofday(&t, NULL);
	return utime_since(s, &t);
}

static unsigned long mtime_since(struct timeval *s, struct timeval *e)
{
	double sec, usec;

	sec = e->tv_sec - s->tv_sec;
	usec = e->tv_usec - s->tv_usec;
	if (sec > 0 && usec < 0) {
		sec--;
		usec += 1000000;
	}

	sec *= (double) 1000;
	usec /= (double) 1000;

	return sec + usec;
}

static unsigned long mtime_since_now(struct timeval *s)
{
	struct timeval t;

	gettimeofday(&t, NULL);
	return mtime_since(s, &t);
}

static inline unsigned long msec_now(struct timeval *s)
{
	return s->tv_sec * 1000 + s->tv_usec / 1000;
}

static unsigned long time_since_now(struct timeval *s)
{
	return mtime_since_now(s) / 1000;
}

static int random_map_free(struct thread_data *td, unsigned long long block)
{
	unsigned int idx = RAND_MAP_IDX(td, block);
	unsigned int bit = RAND_MAP_BIT(td, block);

	return (td->file_map[idx] & (1UL << bit)) == 0;
}

static int get_next_free_block(struct thread_data *td, unsigned long long *b)
{
	int i;

	*b = 0;
	i = 0;
	while ((*b) * td->min_bs < td->io_size) {
		if (td->file_map[i] != -1UL) {
			*b += ffz(td->file_map[i]);
			return 0;
		}

		*b += BLOCKS_PER_MAP;
		i++;
	}

	return 1;
}

static void mark_random_map(struct thread_data *td, struct io_u *io_u)
{
	unsigned long block = io_u->offset / td->min_bs;
	unsigned int blocks = 0;

	while (blocks < (io_u->buflen / td->min_bs)) {
		unsigned int idx, bit;

		if (!random_map_free(td, block))
			break;

		idx = RAND_MAP_IDX(td, block);
		bit = RAND_MAP_BIT(td, block);

		assert(idx < td->num_maps);

		td->file_map[idx] |= (1UL << bit);
		block++;
		blocks++;
	}

	if ((blocks * td->min_bs) < io_u->buflen)
		io_u->buflen = blocks * td->min_bs;
}

static inline void add_stat_sample(struct io_stat *is, unsigned long val)
{
	if (val > is->max_val)
		is->max_val = val;
	if (val < is->min_val)
		is->min_val = val;

	is->val += val;
	is->val_sq += val * val;
	is->samples++;
}

static void add_log_sample(struct thread_data *td, struct io_log *iolog,
			   unsigned long val, int ddir)
{
	if (iolog->nr_samples == iolog->max_samples) {
		int new_size = sizeof(struct io_sample) * iolog->max_samples*2;

		iolog->log = realloc(iolog->log, new_size);
		iolog->max_samples <<= 1;
	}

	iolog->log[iolog->nr_samples].val = val;
	iolog->log[iolog->nr_samples].time = mtime_since_now(&td->epoch);
	iolog->log[iolog->nr_samples].ddir = ddir;
	iolog->nr_samples++;
}

static void add_clat_sample(struct thread_data *td, int ddir,unsigned long msec)
{
	add_stat_sample(&td->clat_stat[ddir], msec);

	if (td->clat_log)
		add_log_sample(td, td->clat_log, msec, ddir);
}

static void add_slat_sample(struct thread_data *td, int ddir,unsigned long msec)
{
	add_stat_sample(&td->slat_stat[ddir], msec);

	if (td->slat_log)
		add_log_sample(td, td->slat_log, msec, ddir);
}

static void add_bw_sample(struct thread_data *td, int ddir)
{
	unsigned long spent = mtime_since_now(&td->stat_sample_time[ddir]);
	unsigned long rate;

	if (spent < td->bw_avg_time)
		return;

	rate = (td->this_io_bytes[ddir] - td->stat_io_bytes[ddir]) / spent;
	add_stat_sample(&td->bw_stat[ddir], rate);

	if (td->bw_log)
		add_log_sample(td, td->bw_log, rate, ddir);

	gettimeofday(&td->stat_sample_time[ddir], NULL);
	td->stat_io_bytes[ddir] = td->this_io_bytes[ddir];
}

static int get_next_offset(struct thread_data *td, unsigned long long *offset)
{
	unsigned long long b, rb;
	long r;

	if (!td->sequential) {
		unsigned long max_blocks = td->io_size / td->min_bs;
		int loops = 50;

		do {
			lrand48_r(&td->random_state, &r);
			b = ((max_blocks - 1) * r / (RAND_MAX+1.0));
			rb = b + (td->file_offset / td->min_bs);
			loops--;
		} while (!random_map_free(td, rb) && loops);

		if (!loops) {
			if (get_next_free_block(td, &b))
				return 1;
		}
	} else
		b = td->last_pos / td->min_bs;

	*offset = (b * td->min_bs) + td->file_offset;
	if (*offset > td->file_size)
		return 1;

	return 0;
}

static unsigned int get_next_buflen(struct thread_data *td)
{
	unsigned int buflen;
	long r;

	if (td->min_bs == td->max_bs)
		buflen = td->min_bs;
	else {
		lrand48_r(&td->bsrange_state, &r);
		buflen = (1 + (double) (td->max_bs - 1) * r / (RAND_MAX + 1.0));
		buflen = (buflen + td->min_bs - 1) & ~(td->min_bs - 1);
	}

	if (buflen > td->io_size - td->this_io_bytes[td->ddir])
		buflen = td->io_size - td->this_io_bytes[td->ddir];

	return buflen;
}

/*
 * busy looping version for the last few usec
 */
static void __usec_sleep(unsigned int usec)
{
	struct timeval start;

	gettimeofday(&start, NULL);
	while (utime_since_now(&start) < usec)
		nop;
}

static void usec_sleep(struct thread_data *td, unsigned long usec)
{
	struct timespec req, rem;

	req.tv_sec = usec / 1000000;
	req.tv_nsec = usec * 1000 - req.tv_sec * 1000000;

	do {
		if (usec < 5000) {
			__usec_sleep(usec);
			break;
		}

		rem.tv_sec = rem.tv_nsec = 0;
		if (nanosleep(&req, &rem) < 0)
			break;

		if ((rem.tv_sec + rem.tv_nsec) == 0)
			break;

		req.tv_nsec = rem.tv_nsec;
		req.tv_sec = rem.tv_sec;

		usec = rem.tv_sec * 1000000 + rem.tv_nsec / 1000;
	} while (!td->terminate);
}

static void rate_throttle(struct thread_data *td, unsigned long time_spent,
			  unsigned int bytes)
{
	unsigned long usec_cycle;

	if (!td->rate)
		return;

	usec_cycle = td->rate_usec_cycle * (bytes / td->min_bs);

	if (time_spent < usec_cycle) {
		unsigned long s = usec_cycle - time_spent;

		td->rate_pending_usleep += s;
		if (td->rate_pending_usleep >= 100000) {
			usec_sleep(td, td->rate_pending_usleep);
			td->rate_pending_usleep = 0;
		}
	} else {
		long overtime = time_spent - usec_cycle;

		td->rate_pending_usleep -= overtime;
	}
}

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
			printf("Client%d: min rate %d not met, got %ldKiB/sec\n", td->thread_number, td->ratemin, rate);
			if (rate_quit)
				terminate_threads(td->groupid);
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

static void fill_random_bytes(struct thread_data *td,
			      unsigned char *p, unsigned int len)
{
	unsigned int todo;
	double r;

	while (len) {
		drand48_r(&td->verify_state, &r);

		/*
		 * lrand48_r seems to be broken and only fill the bottom
		 * 32-bits, even on 64-bit archs with 64-bit longs
		 */
		todo = sizeof(r);
		if (todo > len)
			todo = len;

		memcpy(p, &r, todo);

		len -= todo;
		p += todo;
	}
}

static void hexdump(void *buffer, int len)
{
	unsigned char *p = buffer;
	int i;

	for (i = 0; i < len; i++)
		printf("%02x", p[i]);
	printf("\n");
}

static int verify_io_u_crc32(struct verify_header *hdr, struct io_u *io_u)
{
	unsigned char *p = (unsigned char *) io_u->buf;
	unsigned long c;
	int ret;

	p += sizeof(*hdr);
	c = crc32(p, hdr->len - sizeof(*hdr));
	ret = c != hdr->crc32;

	if (ret) {
		fprintf(stderr, "crc32: verify failed at %llu/%u\n", io_u->offset, io_u->buflen);
		fprintf(stderr, "crc32: wanted %lx, got %lx\n", hdr->crc32, c);
	}

	return ret;
}

static int verify_io_u_md5(struct verify_header *hdr, struct io_u *io_u)
{
	unsigned char *p = (unsigned char *) io_u->buf;
	struct md5_ctx md5_ctx;
	int ret;

	memset(&md5_ctx, 0, sizeof(md5_ctx));
	p += sizeof(*hdr);
	md5_update(&md5_ctx, p, hdr->len - sizeof(*hdr));

	ret = memcmp(hdr->md5_digest, md5_ctx.hash, sizeof(md5_ctx.hash));
	if (ret) {
		fprintf(stderr, "md5: verify failed at %llu/%u\n", io_u->offset, io_u->buflen);
		hexdump(hdr->md5_digest, sizeof(hdr->md5_digest));
		hexdump(md5_ctx.hash, sizeof(md5_ctx.hash));
	}

	return ret;
}

static int verify_io_u(struct io_u *io_u)
{
	struct verify_header *hdr = (struct verify_header *) io_u->buf;
	int ret;

	if (hdr->fio_magic != FIO_HDR_MAGIC)
		return 1;

	if (hdr->verify_type == VERIFY_MD5)
		ret = verify_io_u_md5(hdr, io_u);
	else if (hdr->verify_type == VERIFY_CRC32)
		ret = verify_io_u_crc32(hdr, io_u);
	else {
		fprintf(stderr, "Bad verify type %d\n", hdr->verify_type);
		ret = 1;
	}

	return ret;
}

static void fill_crc32(struct verify_header *hdr, void *p, unsigned int len)
{
	hdr->crc32 = crc32(p, len);
}

static void fill_md5(struct verify_header *hdr, void *p, unsigned int len)
{
	struct md5_ctx md5_ctx;

	memset(&md5_ctx, 0, sizeof(md5_ctx));
	md5_update(&md5_ctx, p, len);
	memcpy(hdr->md5_digest, md5_ctx.hash, sizeof(md5_ctx.hash));
}

/*
 * fill body of io_u->buf with random data and add a header with the
 * (eg) sha1sum of that data.
 */
static void populate_io_u(struct thread_data *td, struct io_u *io_u)
{
	unsigned char *p = (unsigned char *) io_u->buf;
	struct verify_header hdr;

	hdr.fio_magic = FIO_HDR_MAGIC;
	hdr.len = io_u->buflen;
	p += sizeof(hdr);
	fill_random_bytes(td, p, io_u->buflen - sizeof(hdr));

	if (td->verify == VERIFY_MD5) {
		fill_md5(&hdr, p, io_u->buflen - sizeof(hdr));
		hdr.verify_type = VERIFY_MD5;
	} else {
		fill_crc32(&hdr, p, io_u->buflen - sizeof(hdr));
		hdr.verify_type = VERIFY_CRC32;
	}

	memcpy(io_u->buf, &hdr, sizeof(hdr));
}

static int td_io_prep(struct thread_data *td, struct io_u *io_u, int read)
{
	if (read)
		io_u->ddir = DDIR_READ;
	else
		io_u->ddir = DDIR_WRITE;

	if (td->io_prep && td->io_prep(td, io_u))
		return 1;

	return 0;
}

static void put_io_u(struct thread_data *td, struct io_u *io_u)
{
	list_del(&io_u->list);
	list_add(&io_u->list, &td->io_u_freelist);
	td->cur_depth--;
}

#define queue_full(td)	(list_empty(&(td)->io_u_freelist))

static struct io_u *__get_io_u(struct thread_data *td)
{
	struct io_u *io_u;

	if (queue_full(td))
		return NULL;

	io_u = list_entry(td->io_u_freelist.next, struct io_u, list);
	io_u->error = 0;
	io_u->resid = 0;
	list_del(&io_u->list);
	list_add(&io_u->list, &td->io_u_busylist);
	td->cur_depth++;
	return io_u;
}

static struct io_u *get_io_u(struct thread_data *td)
{
	struct io_u *io_u;

	io_u = __get_io_u(td);
	if (!io_u)
		return NULL;

	if (td->zone_bytes >= td->zone_size) {
		td->zone_bytes = 0;
		td->last_pos += td->zone_skip;
	}

	if (get_next_offset(td, &io_u->offset)) {
		put_io_u(td, io_u);
		return NULL;
	}

	io_u->buflen = get_next_buflen(td);
	if (!io_u->buflen) {
		put_io_u(td, io_u);
		return NULL;
	}

	if (io_u->buflen + io_u->offset > td->file_size)
		io_u->buflen = td->file_size - io_u->offset;

	if (!io_u->buflen) {
		put_io_u(td, io_u);
		return NULL;
	}

	if (!td->sequential)
		mark_random_map(td, io_u);

	td->last_pos += io_u->buflen;

	if (td->verify != VERIFY_NONE)
		populate_io_u(td, io_u);

	if (td_io_prep(td, io_u, td_read(td))) {
		put_io_u(td, io_u);
		return NULL;
	}

	gettimeofday(&io_u->start_time, NULL);
	return io_u;
}

static inline void td_set_runstate(struct thread_data *td, int runstate)
{
	td->old_runstate = td->runstate;
	td->runstate = runstate;
}

static int get_next_verify(struct thread_data *td,
			   unsigned long long *offset, unsigned int *len)
{
	struct io_piece *ipo;

	if (list_empty(&td->io_hist_list))
		return 1;

	ipo = list_entry(td->io_hist_list.next, struct io_piece, list);
	list_del(&ipo->list);

	*offset = ipo->offset;
	*len = ipo->len;
	free(ipo);
	return 0;
}

static void prune_io_piece_log(struct thread_data *td)
{
	struct io_piece *ipo;

	while (!list_empty(&td->io_hist_list)) {
		ipo = list_entry(td->io_hist_list.next, struct io_piece, list);

		list_del(&ipo->list);
		free(ipo);
	}
}

/*
 * log a succesful write, so we can unwind the log for verify
 */
static void log_io_piece(struct thread_data *td, struct io_u *io_u)
{
	struct io_piece *ipo = malloc(sizeof(struct io_piece));
	struct list_head *entry;

	INIT_LIST_HEAD(&ipo->list);
	ipo->offset = io_u->offset;
	ipo->len = io_u->buflen;

	/*
	 * for random io where the writes extend the file, it will typically
	 * be laid out with the block scattered as written. it's faster to
	 * read them in in that order again, so don't sort
	 */
	if (td->sequential || !td->overwrite) {
		list_add_tail(&ipo->list, &td->io_hist_list);
		return;
	}

	/*
	 * for random io, sort the list so verify will run faster
	 */
	entry = &td->io_hist_list;
	while ((entry = entry->prev) != &td->io_hist_list) {
		struct io_piece *__ipo = list_entry(entry, struct io_piece, list);

		if (__ipo->offset < ipo->offset)
			break;
	}

	list_add(&ipo->list, entry);
}

static int sync_td(struct thread_data *td)
{
	if (td->io_sync)
		return td->io_sync(td);

	return 0;
}

static int io_u_getevents(struct thread_data *td, int min, int max,
			  struct timespec *t)
{
	return td->io_getevents(td, min, max, t);
}

static int io_u_queue(struct thread_data *td, struct io_u *io_u)
{
	gettimeofday(&io_u->issue_time, NULL);

	return td->io_queue(td, io_u);
}

#define iocb_time(iocb)	((unsigned long) (iocb)->data)

static void io_completed(struct thread_data *td, struct io_u *io_u,
			 struct io_completion_data *icd)
{
	struct timeval e;
	unsigned long msec;

	gettimeofday(&e, NULL);

	if (!io_u->error) {
		unsigned int bytes = io_u->buflen - io_u->resid;
		int idx = io_u->ddir;

		td->io_blocks[idx]++;
		td->io_bytes[idx] += bytes;
		td->zone_bytes += bytes;
		td->this_io_bytes[idx] += bytes;

		msec = mtime_since(&io_u->issue_time, &e);

		add_clat_sample(td, io_u->ddir, msec);
		add_bw_sample(td, io_u->ddir);

		if (td_write(td) && io_u->ddir == DDIR_WRITE)
			log_io_piece(td, io_u);

		icd->bytes_done[idx] += bytes;
	} else
		icd->error = io_u->error;
}

static void ios_completed(struct thread_data *td,struct io_completion_data *icd)
{
	struct io_u *io_u;
	int i;

	icd->error = 0;
	icd->bytes_done[0] = icd->bytes_done[1] = 0;

	for (i = 0; i < icd->nr; i++) {
		io_u = td->io_event(td, i);

		io_completed(td, io_u, icd);
		put_io_u(td, io_u);
	}
}

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
	r = io_u_getevents(td, 0, td->cur_depth, &ts);
	if (r > 0) {
		icd.nr = r;
		ios_completed(td, &icd);
	}

	/*
	 * now cancel remaining active events
	 */
	if (td->io_cancel) {
		list_for_each_safe(entry, n, &td->io_u_busylist) {
			io_u = list_entry(entry, struct io_u, list);

			r = td->io_cancel(td, io_u);
			if (!r)
				put_io_u(td, io_u);
		}
	}

	if (td->cur_depth) {
		r = io_u_getevents(td, td->cur_depth, td->cur_depth, NULL);
		if (r > 0) {
			icd.nr = r;
			ios_completed(td, &icd);
		}
	}
}

static int do_io_u_verify(struct thread_data *td, struct io_u **io_u)
{
	struct io_u *v_io_u = *io_u;
	int ret = 0;

	if (v_io_u) {
		ret = verify_io_u(v_io_u);
		put_io_u(td, v_io_u);
		*io_u = NULL;
	}

	return ret;
}

static void do_verify(struct thread_data *td)
{
	struct timeval t;
	struct io_u *io_u, *v_io_u = NULL;
	struct io_completion_data icd;
	int ret;

	td_set_runstate(td, TD_VERIFYING);

	do {
		if (td->terminate)
			break;

		gettimeofday(&t, NULL);
		if (runtime_exceeded(td, &t))
			break;

		io_u = __get_io_u(td);
		if (!io_u)
			break;

		if (get_next_verify(td, &io_u->offset, &io_u->buflen)) {
			put_io_u(td, io_u);
			break;
		}

		if (td_io_prep(td, io_u, 1)) {
			put_io_u(td, io_u);
			break;
		}

		ret = io_u_queue(td, io_u);
		if (ret) {
			put_io_u(td, io_u);
			td_verror(td, ret);
			break;
		}

		/*
		 * we have one pending to verify, do that while
		 * we are doing io on the next one
		 */
		if (do_io_u_verify(td, &v_io_u))
			break;

		ret = io_u_getevents(td, 1, 1, NULL);
		if (ret != 1) {
			if (ret < 0)
				td_verror(td, ret);
			break;
		}

		v_io_u = td->io_event(td, 0);
		icd.nr = 1;
		icd.error = 0;
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

static void do_io(struct thread_data *td)
{
	struct io_completion_data icd;
	struct timeval s, e;
	unsigned long usec;

	while (td->this_io_bytes[td->ddir] < td->io_size) {
		struct timespec ts = { .tv_sec = 0, .tv_nsec = 0};
		struct timespec *timeout;
		int ret, min_evts = 0;
		struct io_u *io_u;

		if (td->terminate)
			break;

		io_u = get_io_u(td);
		if (!io_u)
			break;

		memcpy(&s, &io_u->start_time, sizeof(s));

		ret = io_u_queue(td, io_u);
		if (ret) {
			put_io_u(td, io_u);
			td_verror(td, ret);
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

		ret = io_u_getevents(td, min_evts, td->cur_depth, timeout);
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
		gettimeofday(&e, NULL);
		usec = utime_since(&s, &e);

		rate_throttle(td, usec, icd.bytes_done[td->ddir]);

		if (check_min_rate(td, &e)) {
			td_verror(td, ENOMEM);
			break;
		}

		if (runtime_exceeded(td, &e))
			break;

		if (td->thinktime)
			usec_sleep(td, td->thinktime);

		if (should_fsync(td) && td->fsync_blocks &&
		    (td->io_blocks[DDIR_WRITE] % td->fsync_blocks) == 0)
			sync_td(td);
	}

	if (td->cur_depth)
		cleanup_pending_aio(td);

	if (should_fsync(td))
		sync_td(td);
}

static void cleanup_io(struct thread_data *td)
{
	if (td->io_cleanup)
		td->io_cleanup(td);
}

static int init_io(struct thread_data *td)
{
	if (td->io_engine == FIO_SYNCIO)
		return fio_syncio_init(td);
	else if (td->io_engine == FIO_MMAPIO)
		return fio_mmapio_init(td);
	else if (td->io_engine == FIO_LIBAIO)
		return fio_libaio_init(td);
	else if (td->io_engine == FIO_POSIXAIO)
		return fio_posixaio_init(td);
	else if (td->io_engine == FIO_SGIO)
		return fio_sgio_init(td);
	else {
		fprintf(stderr, "bad io_engine %d\n", td->io_engine);
		return 1;
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

	if (td->mem_type == MEM_MALLOC)
		free(td->orig_buffer);
	else if (td->mem_type == MEM_SHM) {
		struct shmid_ds sbuf;

		shmdt(td->orig_buffer);
		shmctl(td->shm_id, IPC_RMID, &sbuf);
	} else if (td->mem_type == MEM_MMAP)
		munmap(td->orig_buffer, td->orig_buffer_size);
	else
		fprintf(stderr, "Bad memory type %d\n", td->mem_type);

	td->orig_buffer = NULL;
}

static int init_io_u(struct thread_data *td)
{
	struct io_u *io_u;
	int i, max_units;
	char *p;

	if (td->io_engine & FIO_SYNCIO)
		max_units = 1;
	else
		max_units = td->iodepth;

	td->orig_buffer_size = td->max_bs * max_units + MASK;

	if (td->mem_type == MEM_MALLOC)
		td->orig_buffer = malloc(td->orig_buffer_size);
	else if (td->mem_type == MEM_SHM) {
		td->shm_id = shmget(IPC_PRIVATE, td->orig_buffer_size, IPC_CREAT | 0600);
		if (td->shm_id < 0) {
			td_verror(td, errno);
			perror("shmget");
			return 1;
		}

		td->orig_buffer = shmat(td->shm_id, NULL, 0);
		if (td->orig_buffer == (void *) -1) {
			td_verror(td, errno);
			perror("shmat");
			td->orig_buffer = NULL;
			return 1;
		}
	} else if (td->mem_type == MEM_MMAP) {
		td->orig_buffer = mmap(NULL, td->orig_buffer_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | OS_MAP_ANON, 0, 0);
		if (td->orig_buffer == MAP_FAILED) {
			td_verror(td, errno);
			perror("mmap");
			td->orig_buffer = NULL;
			return 1;
		}
	}

	INIT_LIST_HEAD(&td->io_u_freelist);
	INIT_LIST_HEAD(&td->io_u_busylist);
	INIT_LIST_HEAD(&td->io_hist_list);

	p = ALIGN(td->orig_buffer);
	for (i = 0; i < max_units; i++) {
		io_u = malloc(sizeof(*io_u));
		memset(io_u, 0, sizeof(*io_u));
		INIT_LIST_HEAD(&io_u->list);

		io_u->buf = p + td->max_bs * i;
		list_add(&io_u->list, &td->io_u_freelist);
	}

	return 0;
}

static int create_file(struct thread_data *td, unsigned long long size,
		       int extend)
{
	unsigned long long left;
	unsigned int bs;
	int r, oflags;
	char *b;

	/*
	 * unless specifically asked for overwrite, let normal io extend it
	 */
	if (td_write(td) && !td->overwrite)
		return 0;

	if (!size) {
		fprintf(stderr, "Need size for create\n");
		td_verror(td, EINVAL);
		return 1;
	}

	if (!extend) {
		oflags = O_CREAT | O_TRUNC;
		printf("Client%d: Laying out IO file (%LuMiB)\n", td->thread_number, size >> 20);
	} else {
		oflags = O_APPEND;
		printf("Client%d: Extending IO file (%Lu -> %LuMiB)\n", td->thread_number, (td->file_size - size) >> 20, td->file_size >> 20);
	}

	td->fd = open(td->file_name, O_WRONLY | oflags, 0644);
	if (td->fd < 0) {
		td_verror(td, errno);
		return 1;
	}

	if (!extend && ftruncate(td->fd, td->file_size) == -1) {
		td_verror(td, errno);
		return 1;
	}

	td->io_size = td->file_size;
	b = malloc(td->max_bs);
	memset(b, 0, td->max_bs);

	left = size;
	while (left && !td->terminate) {
		bs = td->max_bs;
		if (bs > left)
			bs = left;

		r = write(td->fd, b, bs);

		if (r == (int) bs) {
			left -= bs;
			continue;
		} else {
			if (r < 0)
				td_verror(td, errno);
			else
				td_verror(td, EIO);

			break;
		}
	}

	if (td->terminate)
		unlink(td->file_name);
	else if (td->create_fsync)
		fsync(td->fd);

	close(td->fd);
	td->fd = -1;
	free(b);
	return 0;
}

static int file_size(struct thread_data *td)
{
	struct stat st;

	if (fstat(td->fd, &st) == -1) {
		td_verror(td, errno);
		return 1;
	}

	if (!td->file_size)
		td->file_size = st.st_size;

	return 0;
}

static int bdev_size(struct thread_data *td)
{
	size_t bytes;
	int r;

	r = blockdev_size(td->fd, &bytes);
	if (r) {
		td_verror(td, r);
		return 1;
	}

	/*
	 * no extend possibilities, so limit size to device size if too large
	 */
	if (!td->file_size || td->file_size > bytes)
		td->file_size = bytes;

	return 0;
}

static int get_file_size(struct thread_data *td)
{
	int ret;

	if (td->filetype == FIO_TYPE_FILE)
		ret = file_size(td);
	else
		ret = bdev_size(td);

	if (ret)
		return ret;

	if (td->file_offset > td->file_size) {
		fprintf(stderr, "Client%d: offset larger than length (%Lu > %Lu)\n", td->thread_number, td->file_offset, td->file_size);
		return 1;
	}

	td->io_size = td->file_size - td->file_offset;
	if (td->io_size == 0) {
		fprintf(stderr, "Client%d: no io blocks\n", td->thread_number);
		td_verror(td, EINVAL);
		return 1;
	}

	if (!td->zone_size)
		td->zone_size = td->io_size;

	td->total_io_size = td->io_size * td->loops;
	return 0;
}

static int setup_file_mmap(struct thread_data *td)
{
	int flags;

	if (td_read(td))
		flags = PROT_READ;
	else {
		flags = PROT_WRITE;

		if (td->verify != VERIFY_NONE)
			flags |= PROT_READ;
	}

	td->mmap = mmap(NULL, td->file_size, flags, MAP_SHARED, td->fd, td->file_offset);
	if (td->mmap == MAP_FAILED) {
		td->mmap = NULL;
		td_verror(td, errno);
		return 1;
	}

	if (td->invalidate_cache) {
		if (madvise(td->mmap, td->file_size, MADV_DONTNEED) < 0) {
			td_verror(td, errno);
			return 1;
		}
	}

	if (td->sequential) {
		if (madvise(td->mmap, td->file_size, MADV_SEQUENTIAL) < 0) {
			td_verror(td, errno);
			return 1;
		}
	} else {
		if (madvise(td->mmap, td->file_size, MADV_RANDOM) < 0) {
			td_verror(td, errno);
			return 1;
		}
	}

	return 0;
}

static int setup_file_plain(struct thread_data *td)
{
	if (td->invalidate_cache) {
		if (fadvise(td->fd, td->file_offset, td->file_size, POSIX_FADV_DONTNEED) < 0) {
			td_verror(td, errno);
			return 1;
		}
	}

	if (td->sequential) {
		if (fadvise(td->fd, td->file_offset, td->file_size, POSIX_FADV_SEQUENTIAL) < 0) {
			td_verror(td, errno);
			return 1;
		}
	} else {
		if (fadvise(td->fd, td->file_offset, td->file_size, POSIX_FADV_RANDOM) < 0) {
			td_verror(td, errno);
			return 1;
		}
	}

	return 0;
}

static int setup_file(struct thread_data *td)
{
	struct stat st;
	int flags = 0;

	if (stat(td->file_name, &st) == -1) {
		if (errno != ENOENT) {
			td_verror(td, errno);
			return 1;
		}
		if (!td->create_file) {
			td_verror(td, ENOENT);
			return 1;
		}
		if (create_file(td, td->file_size, 0))
			return 1;
	} else if (td->filetype == FIO_TYPE_FILE) {
		if (st.st_size < td->file_size) {
			if (create_file(td, td->file_size - st.st_size, 1))
				return 1;
		}
	}

	if (td->odirect)
		flags |= O_DIRECT;

	if (td_read(td))
		td->fd = open(td->file_name, flags | O_RDONLY);
	else {
		if (td->filetype == FIO_TYPE_FILE) {
			if (!td->overwrite)
				flags |= O_TRUNC;

			flags |= O_CREAT;
		}
		if (td->sync_io)
			flags |= O_SYNC;

		flags |= O_RDWR;

		td->fd = open(td->file_name, flags, 0600);
	}

	if (td->fd == -1) {
		td_verror(td, errno);
		return 1;
	}

	if (get_file_size(td))
		return 1;

	if (td->io_engine != FIO_MMAPIO)
		return setup_file_plain(td);
	else
		return setup_file_mmap(td);
}

static int check_dev_match(dev_t dev, char *path)
{
	unsigned int major, minor;
	char line[256], *p;
	FILE *f;

	f = fopen(path, "r");
	if (!f) {
		perror("open path");
		return 1;
	}

	p = fgets(line, sizeof(line), f);
	if (!p) {
		fclose(f);
		return 1;
	}

	if (sscanf(p, "%u:%u", &major, &minor) != 2) {
		fclose(f);
		return 1;
	}

	if (((major << 8) | minor) == dev) {
		fclose(f);
		return 0;
	}

	fclose(f);
	return 1;
}

static int find_block_dir(dev_t dev, char *path)
{
	struct dirent *dir;
	struct stat st;
	int found = 0;
	DIR *D;

	D = opendir(path);
	if (!D)
		return 0;

	while ((dir = readdir(D)) != NULL) {
		char full_path[256];

		if (!strcmp(dir->d_name, ".") || !strcmp(dir->d_name, ".."))
			continue;
		if (!strcmp(dir->d_name, "device"))
			continue;

		sprintf(full_path, "%s/%s", path, dir->d_name);

		if (!strcmp(dir->d_name, "dev")) {
			if (!check_dev_match(dev, full_path)) {
				found = 1;
				break;
			}
		}

		if (stat(full_path, &st) == -1) {
			perror("stat");
			break;
		}

		if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode))
			continue;

		found = find_block_dir(dev, full_path);
		if (found) {
			strcpy(path, full_path);
			break;
		}
	}

	closedir(D);
	return found;
}

static int get_io_ticks(struct disk_util *du, struct disk_util_stat *dus)
{
	unsigned in_flight;
	char line[256];
	FILE *f;
	char *p;

	f = fopen(du->path, "r");
	if (!f)
		return 1;

	p = fgets(line, sizeof(line), f);
	if (!p) {
		fclose(f);
		return 1;
	}

	if (sscanf(p, "%u %u %llu %u %u %u %llu %u %u %u %u\n", &dus->ios[0], &dus->merges[0], &dus->sectors[0], &dus->ticks[0], &dus->ios[1], &dus->merges[1], &dus->sectors[1], &dus->ticks[1], &in_flight, &dus->io_ticks, &dus->time_in_queue) != 11) {
		fclose(f);
		return 1;
	}

	fclose(f);
	return 0;
}

static void update_io_tick_disk(struct disk_util *du)
{
	struct disk_util_stat __dus, *dus, *ldus;
	struct timeval t;

	if (get_io_ticks(du, &__dus))
		return;

	dus = &du->dus;
	ldus = &du->last_dus;

	dus->sectors[0] += (__dus.sectors[0] - ldus->sectors[0]);
	dus->sectors[1] += (__dus.sectors[1] - ldus->sectors[1]);
	dus->ios[0] += (__dus.ios[0] - ldus->ios[0]);
	dus->ios[1] += (__dus.ios[1] - ldus->ios[1]);
	dus->merges[0] += (__dus.merges[0] - ldus->merges[0]);
	dus->merges[1] += (__dus.merges[1] - ldus->merges[1]);
	dus->ticks[0] += (__dus.ticks[0] - ldus->ticks[0]);
	dus->ticks[1] += (__dus.ticks[1] - ldus->ticks[1]);
	dus->io_ticks += (__dus.io_ticks - ldus->io_ticks);
	dus->time_in_queue += (__dus.time_in_queue - ldus->time_in_queue);

	gettimeofday(&t, NULL);
	du->msec += mtime_since(&du->time, &t);
	memcpy(&du->time, &t, sizeof(t));
	memcpy(ldus, &__dus, sizeof(__dus));
}

static void update_io_ticks(void)
{
	struct list_head *entry;
	struct disk_util *du;

	list_for_each(entry, &disk_list) {
		du = list_entry(entry, struct disk_util, list);
		update_io_tick_disk(du);
	}
}

static int disk_util_exists(dev_t dev)
{
	struct list_head *entry;
	struct disk_util *du;

	list_for_each(entry, &disk_list) {
		du = list_entry(entry, struct disk_util, list);

		if (du->dev == dev)
			return 1;
	}

	return 0;
}

static void disk_util_add(dev_t dev, char *path)
{
	struct disk_util *du = malloc(sizeof(*du));

	memset(du, 0, sizeof(*du));
	INIT_LIST_HEAD(&du->list);
	sprintf(du->path, "%s/stat", path);
	du->name = strdup(basename(path));
	du->dev = dev;

	gettimeofday(&du->time, NULL);
	get_io_ticks(du, &du->last_dus);

	list_add_tail(&du->list, &disk_list);
}

static void init_disk_util(struct thread_data *td)
{
	struct stat st;
	char foo[256], tmp[256];
	dev_t dev;
	char *p;

	if (!td->do_disk_util)
		return;

	if (!stat(td->file_name, &st)) {
		if (S_ISBLK(st.st_mode))
			dev = st.st_rdev;
		else
			dev = st.st_dev;
	} else {
		/*
		 * must be a file, open "." in that path
		 */
		strcpy(foo, td->file_name);
		p = dirname(foo);
		if (stat(p, &st)) {
			perror("disk util stat");
			return;
		}

		dev = st.st_dev;
	}

	if (disk_util_exists(dev))
		return;
		
	sprintf(foo, "/sys/block");
	if (!find_block_dir(dev, foo))
		return;

	/*
	 * if this is inside a partition dir, jump back to parent
	 */
	sprintf(tmp, "%s/queue", foo);
	if (stat(tmp, &st)) {
		p = dirname(foo);
		sprintf(tmp, "%s/queue", p);
		if (stat(tmp, &st)) {
			fprintf(stderr, "unknown sysfs layout\n");
			return;
		}
		sprintf(foo, "%s", p);
	}

	disk_util_add(dev, foo);
}

static void disk_util_timer_arm(void)
{
	itimer.it_value.tv_sec = 0;
	itimer.it_value.tv_usec = DISK_UTIL_MSEC * 1000;
	setitimer(ITIMER_REAL, &itimer, NULL);
}

static void clear_io_state(struct thread_data *td)
{
	if (td->io_engine == FIO_SYNCIO)
		lseek(td->fd, SEEK_SET, 0);

	td->last_pos = 0;
	td->stat_io_bytes[0] = td->stat_io_bytes[1] = 0;
	td->this_io_bytes[0] = td->this_io_bytes[1] = 0;
	td->zone_bytes = 0;

	if (td->file_map)
		memset(td->file_map, 0, td->num_maps * sizeof(long));
}

static void update_rusage_stat(struct thread_data *td)
{
	if (!(td->runtime[0] + td->runtime[1]))
		return;

	getrusage(RUSAGE_SELF, &td->ru_end);

	td->usr_time += mtime_since(&td->ru_start.ru_utime, &td->ru_end.ru_utime);
	td->sys_time += mtime_since(&td->ru_start.ru_stime, &td->ru_end.ru_stime);
	td->ctx += td->ru_end.ru_nvcsw + td->ru_end.ru_nivcsw - (td->ru_start.ru_nvcsw + td->ru_start.ru_nivcsw);

	
	memcpy(&td->ru_start, &td->ru_end, sizeof(td->ru_end));
}

static void *thread_main(void *data)
{
	struct thread_data *td = data;
	int ret = 1;

	if (!td->use_thread)
		setsid();

	td->pid = getpid();

	if (init_io_u(td))
		goto err;

	if (fio_setaffinity(td) == -1) {
		td_verror(td, errno);
		goto err;
	}

	if (init_io(td))
		goto err;

	if (td->ioprio) {
		if (ioprio_set(IOPRIO_WHO_PROCESS, 0, td->ioprio) == -1) {
			td_verror(td, errno);
			goto err;
		}
	}

	sem_post(&startup_sem);
	sem_wait(&td->mutex);

	if (!td->create_serialize && setup_file(td))
		goto err;

	if (init_random_state(td))
		goto err;

	gettimeofday(&td->epoch, NULL);

	while (td->loops--) {
		getrusage(RUSAGE_SELF, &td->ru_start);
		gettimeofday(&td->start, NULL);
		memcpy(&td->stat_sample_time, &td->start, sizeof(td->start));

		if (td->ratemin)
			memcpy(&td->lastrate, &td->stat_sample_time, sizeof(td->lastrate));

		clear_io_state(td);
		prune_io_piece_log(td);

		do_io(td);

		td->runtime[td->ddir] += mtime_since_now(&td->start);
		update_rusage_stat(td);

		if (td->error || td->terminate)
			break;

		if (td->verify == VERIFY_NONE)
			continue;

		clear_io_state(td);
		gettimeofday(&td->start, NULL);

		do_verify(td);

		td->runtime[DDIR_READ] += mtime_since_now(&td->start);

		if (td->error || td->terminate)
			break;
	}

	ret = 0;

	if (td->bw_log)
		finish_log(td, td->bw_log, "bw");
	if (td->slat_log)
		finish_log(td, td->slat_log, "slat");
	if (td->clat_log)
		finish_log(td, td->clat_log, "clat");

	if (exitall_on_terminate)
		terminate_threads(td->groupid);

err:
	if (td->fd != -1) {
		close(td->fd);
		td->fd = -1;
	}
	if (td->mmap)
		munmap(td->mmap, td->file_size);
	cleanup_io(td);
	cleanup_io_u(td);
	if (ret) {
		sem_post(&startup_sem);
		sem_wait(&td->mutex);
	}
	td_set_runstate(td, TD_EXITED);
	return NULL;

}

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

static int calc_lat(struct io_stat *is, unsigned long *min, unsigned long *max,
		    double *mean, double *dev)
{
	double n;

	if (is->samples == 0)
		return 0;

	*min = is->min_val;
	*max = is->max_val;

	n = (double) is->samples;
	*mean = (double) is->val / n;
	*dev = sqrt(((double) is->val_sq - (*mean * *mean) / n) / (n - 1));
	if (!(*min + *max) && !(*mean + *dev))
		return 0;

	return 1;
}

static void show_ddir_status(struct thread_data *td, struct group_run_stats *rs,
			     int ddir)
{
	char *ddir_str[] = { "read ", "write" };
	unsigned long min, max, bw;
	double mean, dev;

	if (!td->runtime[ddir])
		return;

	bw = td->io_bytes[ddir] / td->runtime[ddir];
	printf("  %s: io=%6luMiB, bw=%6luKiB/s, runt=%6lumsec\n", ddir_str[ddir], td->io_bytes[ddir] >> 20, bw, td->runtime[ddir]);

	if (calc_lat(&td->slat_stat[ddir], &min, &max, &mean, &dev))
		printf("    slat (msec): min=%5lu, max=%5lu, avg=%5.02f, dev=%5.02f\n", min, max, mean, dev);

	if (calc_lat(&td->clat_stat[ddir], &min, &max, &mean, &dev))
		printf("    clat (msec): min=%5lu, max=%5lu, avg=%5.02f, dev=%5.02f\n", min, max, mean, dev);

	if (calc_lat(&td->bw_stat[ddir], &min, &max, &mean, &dev)) {
		double p_of_agg;

		p_of_agg = mean * 100 / (double) rs->agg[ddir];
		printf("    bw (KiB/s) : min=%5lu, max=%5lu, per=%3.2f%%, avg=%5.02f, dev=%5.02f\n", min, max, p_of_agg, mean, dev);
	}
}

static void show_thread_status(struct thread_data *td,
			       struct group_run_stats *rs)
{
	double usr_cpu, sys_cpu;

	if (!(td->io_bytes[0] + td->io_bytes[1]) && !td->error)
		return;

	printf("Client%d (groupid=%d): err=%2d:\n", td->thread_number, td->groupid, td->error);

	show_ddir_status(td, rs, td->ddir);
	show_ddir_status(td, rs, td->ddir ^ 1);

	if (td->runtime[0] + td->runtime[1]) {
		double runt = td->runtime[0] + td->runtime[1];

		usr_cpu = (double) td->usr_time * 100 / runt;
		sys_cpu = (double) td->sys_time * 100 / runt;
	} else {
		usr_cpu = 0;
		sys_cpu = 0;
	}

	printf("  cpu          : usr=%3.2f%%, sys=%3.2f%%, ctx=%lu\n", usr_cpu, sys_cpu, td->ctx);
}

static void check_str_update(struct thread_data *td)
{
	char c = run_str[td->thread_number - 1];

	if (td->runstate == td->old_runstate)
		return;

	switch (td->runstate) {
		case TD_REAPED:
			c = '_';
			break;
		case TD_EXITED:
			c = 'E';
			break;
		case TD_RUNNING:
			if (td_read(td)) {
				if (td->sequential)
					c = 'R';
				else
					c = 'r';
			} else {
				if (td->sequential)
					c = 'W';
				else
					c = 'w';
			}
			break;
		case TD_VERIFYING:
			c = 'V';
			break;
		case TD_CREATED:
			c = 'C';
			break;
		case TD_NOT_CREATED:
			c = 'P';
			break;
		default:
			printf("state %d\n", td->runstate);
	}

	run_str[td->thread_number - 1] = c;
	td->old_runstate = td->runstate;
}

static void eta_to_str(char *str, int eta_sec)
{
	unsigned int d, h, m, s;
	static int always_d, always_h;

	d = h = m = s = 0;

	s = eta_sec % 60;
	eta_sec /= 60;
	m = eta_sec % 60;
	eta_sec /= 60;
	h = eta_sec % 24;
	eta_sec /= 24;
	d = eta_sec;

	if (d || always_d) {
		always_d = 1;
		str += sprintf(str, "%02dd:", d);
	}
	if (h || always_h) {
		always_h = 1;
		str += sprintf(str, "%02dh:", h);
	}

	str += sprintf(str, "%02dm:", m);
	str += sprintf(str, "%02ds", s);
}

static void print_thread_status(void)
{
	unsigned long long bytes_done, bytes_total;
	int i, nr_running, t_rate, m_rate, eta_sec;
	char eta_str[32];
	double perc;

	bytes_done = bytes_total = 0;
	nr_running = t_rate = m_rate = 0;
	for (i = 0; i < thread_number; i++) {
		struct thread_data *td = &threads[i];

		if (td->runstate == TD_RUNNING || td->runstate == TD_VERIFYING){
			nr_running++;
			t_rate += td->rate;
			m_rate += td->ratemin;
		}

		bytes_total += td->total_io_size;
		if (td->verify)
			bytes_total += td->total_io_size;

		if (td->zone_size)
			bytes_total /= (td->zone_skip / td->zone_size);
	
		bytes_done += td->io_bytes[DDIR_READ] +td->io_bytes[DDIR_WRITE];

		check_str_update(td);
	}

	perc = 0;
	eta_sec = 0;
	if (bytes_total && bytes_done) {
		unsigned long runtime;

		perc = (double) bytes_done / (double) bytes_total;
		if (perc > 1.0)
			perc = 1.0;

		runtime = time_since_now(&genesis);
		if (runtime >= 5) {
			memset(eta_str, 0, sizeof(eta_str));
			eta_sec = (runtime * (1.0 / perc)) - runtime;
			eta_to_str(eta_str, eta_sec);
		}

		perc *= 100.0;
	}

	printf("Threads now running (%d)", nr_running);
	if (m_rate || t_rate)
		printf(", commitrate %d/%dKiB/sec", t_rate, m_rate);
	printf(": [%s] [%3.2f%% done]", run_str, perc);
	if (eta_sec)
		printf(" [eta %s]", eta_str);
	printf("\r");
	fflush(stdout);
}

static void reap_threads(int *nr_running, int *t_rate, int *m_rate)
{
	int i;

	/*
	 * reap exited threads (TD_EXITED -> TD_REAPED)
	 */
	for (i = 0; i < thread_number; i++) {
		struct thread_data *td = &threads[i];

		if (td->runstate != TD_EXITED)
			continue;

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
}

static void run_threads(void)
{
	struct thread_data *td;
	unsigned long spent;
	int i, todo, nr_running, m_rate, t_rate, nr_started;

	printf("Starting %d thread%s\n", thread_number, thread_number > 1 ? "s" : "");
	fflush(stdout);

	signal(SIGINT, sig_handler);
	signal(SIGALRM, sig_handler);

	todo = thread_number;
	nr_running = 0;
	nr_started = 0;
	m_rate = t_rate = 0;

	for (i = 0; i < thread_number; i++) {
		td = &threads[i];

		run_str[td->thread_number - 1] = 'P';

		init_disk_util(td);

		if (!td->create_serialize)
			continue;

		/*
		 * do file setup here so it happens sequentially,
		 * we don't want X number of threads getting their
		 * client data interspersed on disk
		 */
		if (setup_file(td)) {
			td_set_runstate(td, TD_REAPED);
			todo--;
		}
	}

	gettimeofday(&genesis, NULL);

	while (todo) {
		/*
		 * create threads (TD_NOT_CREATED -> TD_CREATED)
		 */
		for (i = 0; i < thread_number; i++) {
			td = &threads[i];

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
				spent = mtime_since_now(&genesis);

				if (td->start_delay * 1000 > spent)
					continue;
			}

			if (td->stonewall && (nr_started || nr_running))
				break;

			td_set_runstate(td, TD_CREATED);
			sem_init(&startup_sem, 0, 1);
			todo--;
			nr_started++;

			if (td->use_thread) {
				if (pthread_create(&td->thread, NULL, thread_main, td)) {
					perror("thread_create");
					nr_started--;
				}
			} else {
				if (fork())
					sem_wait(&startup_sem);
				else {
					fork_main(shm_id, i);
					exit(0);
				}
			}
		}

		/*
		 * start created threads (TD_CREATED -> TD_RUNNING)
		 */
		for (i = 0; i < thread_number; i++) {
			td = &threads[i];

			if (td->runstate != TD_CREATED)
				continue;

			td_set_runstate(td, TD_RUNNING);
			nr_running++;
			nr_started--;
			m_rate += td->ratemin;
			t_rate += td->rate;
			sem_post(&td->mutex);
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
}

static void show_group_stats(struct group_run_stats *rs, int id)
{
	printf("\nRun status group %d (all jobs):\n", id);

	if (rs->max_run[DDIR_READ])
		printf("   READ: io=%luMiB, aggrb=%lu, minb=%lu, maxb=%lu, mint=%lumsec, maxt=%lumsec\n", rs->io_mb[0], rs->agg[0], rs->min_bw[0], rs->max_bw[0], rs->min_run[0], rs->max_run[0]);
	if (rs->max_run[DDIR_WRITE])
		printf("  WRITE: io=%luMiB, aggrb=%lu, minb=%lu, maxb=%lu, mint=%lumsec, maxt=%lumsec\n", rs->io_mb[1], rs->agg[1], rs->min_bw[1], rs->max_bw[1], rs->min_run[1], rs->max_run[1]);
}

static void show_disk_util(void)
{
	struct disk_util_stat *dus;
	struct list_head *entry;
	struct disk_util *du;
	double util;

	printf("\nDisk stats (read/write):\n");

	list_for_each(entry, &disk_list) {
		du = list_entry(entry, struct disk_util, list);
		dus = &du->dus;

		util = (double) 100 * du->dus.io_ticks / (double) du->msec;
		if (util > 100.0)
			util = 100.0;

		printf("  %s: ios=%u/%u, merge=%u/%u, ticks=%u/%u, in_queue=%u, util=%3.2f%%\n", du->name, dus->ios[0], dus->ios[1], dus->merges[0], dus->merges[1], dus->ticks[0], dus->ticks[1], dus->time_in_queue, util);
	}
}

static void show_run_stats(void)
{
	struct group_run_stats *runstats, *rs;
	struct thread_data *td;
	int i;

	runstats = malloc(sizeof(struct group_run_stats) * (groupid + 1));

	for (i = 0; i < groupid + 1; i++) {
		rs = &runstats[i];

		memset(rs, 0, sizeof(*rs));
		rs->min_bw[0] = rs->min_run[0] = ~0UL;
		rs->min_bw[1] = rs->min_run[1] = ~0UL;
	}

	for (i = 0; i < thread_number; i++) {
		unsigned long rbw, wbw;

		td = &threads[i];

		if (td->error) {
			printf("Client%d: %s\n", td->thread_number, td->verror);
			continue;
		}

		rs = &runstats[td->groupid];

		if (td->runtime[0] < rs->min_run[0] || !rs->min_run[0])
			rs->min_run[0] = td->runtime[0];
		if (td->runtime[0] > rs->max_run[0])
			rs->max_run[0] = td->runtime[0];
		if (td->runtime[1] < rs->min_run[1] || !rs->min_run[1])
			rs->min_run[1] = td->runtime[1];
		if (td->runtime[1] > rs->max_run[1])
			rs->max_run[1] = td->runtime[1];

		rbw = wbw = 0;
		if (td->runtime[0])
			rbw = td->io_bytes[0] / td->runtime[0];
		if (td->runtime[1])
			wbw = td->io_bytes[1] / td->runtime[1];

		if (rbw < rs->min_bw[0])
			rs->min_bw[0] = rbw;
		if (wbw < rs->min_bw[1])
			rs->min_bw[1] = wbw;
		if (rbw > rs->max_bw[0])
			rs->max_bw[0] = rbw;
		if (wbw > rs->max_bw[1])
			rs->max_bw[1] = wbw;

		rs->io_mb[0] += td->io_bytes[0] >> 20;
		rs->io_mb[1] += td->io_bytes[1] >> 20;
	}

	for (i = 0; i < groupid + 1; i++) {
		rs = &runstats[i];

		if (rs->max_run[0])
			rs->agg[0] = (rs->io_mb[0]*1024*1000) / rs->max_run[0];
		if (rs->max_run[1])
			rs->agg[1] = (rs->io_mb[1]*1024*1000) / rs->max_run[1];
	}

	/*
	 * don't overwrite last signal output
	 */
	printf("\n");

	for (i = 0; i < thread_number; i++) {
		td = &threads[i];
		rs = &runstats[td->groupid];

		show_thread_status(td, rs);
	}

	for (i = 0; i < groupid + 1; i++)
		show_group_stats(&runstats[i], i);

	show_disk_util();
}

int main(int argc, char *argv[])
{
	if (parse_options(argc, argv))
		return 1;

	if (!thread_number) {
		printf("Nothing to do\n");
		return 1;
	}

	disk_util_timer_arm();

	run_threads();
	show_run_stats();

	return 0;
}
