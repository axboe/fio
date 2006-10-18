/*
 * fio - the flexible io tester
 *
 * Copyright (C) 2005 Jens Axboe <axboe@suse.de>
 * Copyright (C) 2006 Jens Axboe <axboe@kernel.dk>
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
static char run_str[MAX_JOBS + 1];
int shm_id = 0;
static struct timeval genesis;
int temp_stall_ts;
char *fio_inst_prefix = _INST_PREFIX;

static void print_thread_status(void);

extern unsigned long long mlock_size;

/*
 * Thread life cycle. Once a thread has a runstate beyond TD_INITIALIZED, it
 * will never back again. It may cycle between running/verififying/fsyncing.
 * Once the thread reaches TD_EXITED, it is just waiting for the core to
 * reap it.
 */
enum {
	TD_NOT_CREATED = 0,
	TD_CREATED,
	TD_INITIALIZED,
	TD_RUNNING,
	TD_VERIFYING,
	TD_FSYNCING,
	TD_EXITED,
	TD_REAPED,
};

#define should_fsync(td)	((td_write(td) || td_rw(td)) && (!(td)->odirect || (td)->override_sync))

static volatile int startup_sem;

#define TERMINATE_ALL		(-1)
#define JOB_START_TIMEOUT	(5 * 1000)

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

/*
 * The ->file_map[] contains a map of blocks we have or have not done io
 * to yet. Used to make sure we cover the entire range in a fair fashion.
 */
static int random_map_free(struct thread_data *td, struct fio_file *f,
			   unsigned long long block)
{
	unsigned int idx = RAND_MAP_IDX(td, f, block);
	unsigned int bit = RAND_MAP_BIT(td, f, block);

	return (f->file_map[idx] & (1UL << bit)) == 0;
}

/*
 * Return the next free block in the map.
 */
static int get_next_free_block(struct thread_data *td, struct fio_file *f,
			       unsigned long long *b)
{
	int i;

	*b = 0;
	i = 0;
	while ((*b) * td->min_bs < f->file_size) {
		if (f->file_map[i] != -1UL) {
			*b += ffz(f->file_map[i]);
			return 0;
		}

		*b += BLOCKS_PER_MAP;
		i++;
	}

	return 1;
}

/*
 * Mark a given offset as used in the map.
 */
static void mark_random_map(struct thread_data *td, struct fio_file *f,
			    struct io_u *io_u)
{
	unsigned long long block = io_u->offset / (unsigned long long) td->min_bs;
	unsigned int blocks = 0;

	while (blocks < (io_u->buflen / td->min_bs)) {
		unsigned int idx, bit;

		if (!random_map_free(td, f, block))
			break;

		idx = RAND_MAP_IDX(td, f, block);
		bit = RAND_MAP_BIT(td, f, block);

		assert(idx < f->num_maps);

		f->file_map[idx] |= (1UL << bit);
		block++;
		blocks++;
	}

	if ((blocks * td->min_bs) < io_u->buflen)
		io_u->buflen = blocks * td->min_bs;
}

/*
 * For random io, generate a random new block and see if it's used. Repeat
 * until we find a free one. For sequential io, just return the end of
 * the last io issued.
 */
static int get_next_offset(struct thread_data *td, struct fio_file *f,
			   unsigned long long *offset)
{
	unsigned long long b, rb;
	long r;

	if (!td->sequential) {
		unsigned long long max_blocks = td->io_size / td->min_bs;
		int loops = 50;

		do {
			r = os_random_long(&td->random_state);
			b = ((max_blocks - 1) * r / (unsigned long long) (RAND_MAX+1.0));
			rb = b + (f->file_offset / td->min_bs);
			loops--;
		} while (!random_map_free(td, f, rb) && loops);

		if (!loops) {
			if (get_next_free_block(td, f, &b))
				return 1;
		}
	} else
		b = f->last_pos / td->min_bs;

	*offset = (b * td->min_bs) + f->file_offset;
	if (*offset > f->file_size)
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
		r = os_random_long(&td->bsrange_state);
		buflen = (1 + (double) (td->max_bs - 1) * r / (RAND_MAX + 1.0));
		buflen = (buflen + td->min_bs - 1) & ~(td->min_bs - 1);
	}

	if (buflen > td->io_size - td->this_io_bytes[td->ddir]) {
		/*
		 * if using direct/raw io, we may not be able to
		 * shrink the size. so just fail it.
		 */
		if (td->io_ops->flags & FIO_RAWIO)
			return 0;

		buflen = td->io_size - td->this_io_bytes[td->ddir];
	}

	return buflen;
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
			fprintf(f_out, "%s: min rate %d not met, got %ldKiB/sec\n", td->name, td->ratemin, rate);
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
		r = os_random_double(&td->verify_state);

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
		fprintf(f_out, "%02x", p[i]);
	fprintf(f_out, "\n");
}

static int verify_io_u_crc32(struct verify_header *hdr, struct io_u *io_u)
{
	unsigned char *p = (unsigned char *) io_u->buf;
	unsigned long c;

	p += sizeof(*hdr);
	c = crc32(p, hdr->len - sizeof(*hdr));

	if (c != hdr->crc32) {
		log_err("crc32: verify failed at %llu/%u\n", io_u->offset, io_u->buflen);
		log_err("crc32: wanted %lx, got %lx\n", hdr->crc32, c);
		return 1;
	}

	return 0;
}

static int verify_io_u_md5(struct verify_header *hdr, struct io_u *io_u)
{
	unsigned char *p = (unsigned char *) io_u->buf;
	struct md5_ctx md5_ctx;

	memset(&md5_ctx, 0, sizeof(md5_ctx));
	p += sizeof(*hdr);
	md5_update(&md5_ctx, p, hdr->len - sizeof(*hdr));

	if (memcmp(hdr->md5_digest, md5_ctx.hash, sizeof(md5_ctx.hash))) {
		log_err("md5: verify failed at %llu/%u\n", io_u->offset, io_u->buflen);
		hexdump(hdr->md5_digest, sizeof(hdr->md5_digest));
		hexdump(md5_ctx.hash, sizeof(md5_ctx.hash));
		return 1;
	}

	return 0;
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
		log_err("Bad verify type %d\n", hdr->verify_type);
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
 * Return the data direction for the next io_u. If the job is a
 * mixed read/write workload, check the rwmix cycle and switch if
 * necessary.
 */
static int get_rw_ddir(struct thread_data *td)
{
	if (td_rw(td)) {
		struct timeval now;
		unsigned long elapsed;

		gettimeofday(&now, NULL);
	 	elapsed = mtime_since_now(&td->rwmix_switch);

		/*
		 * Check if it's time to seed a new data direction.
		 */
		if (elapsed >= td->rwmixcycle) {
			int v;
			long r;

			r = os_random_long(&td->rwmix_state);
			v = 1 + (int) (100.0 * (r / (RAND_MAX + 1.0)));
			if (v < td->rwmixread)
				td->rwmix_ddir = DDIR_READ;
			else
				td->rwmix_ddir = DDIR_WRITE;
			memcpy(&td->rwmix_switch, &now, sizeof(now));
		}
		return td->rwmix_ddir;
	} else if (td_read(td))
		return DDIR_READ;
	else
		return DDIR_WRITE;
}

/*
 * fill body of io_u->buf with random data and add a header with the
 * crc32 or md5 sum of that data.
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

static int td_io_prep(struct thread_data *td, struct io_u *io_u)
{
	if (td->io_ops->prep && td->io_ops->prep(td, io_u))
		return 1;

	return 0;
}

void put_io_u(struct thread_data *td, struct io_u *io_u)
{
	io_u->file = NULL;
	list_del(&io_u->list);
	list_add(&io_u->list, &td->io_u_freelist);
	td->cur_depth--;
}

static int fill_io_u(struct thread_data *td, struct fio_file *f,
		     struct io_u *io_u)
{
	/*
	 * If using an iolog, grab next piece if any available.
	 */
	if (td->read_iolog)
		return read_iolog_get(td, io_u);

	/*
	 * No log, let the seq/rand engine retrieve the next position.
	 */
	if (!get_next_offset(td, f, &io_u->offset)) {
		io_u->buflen = get_next_buflen(td);

		if (io_u->buflen) {
			io_u->ddir = get_rw_ddir(td);

			/*
			 * If using a write iolog, store this entry.
			 */
			if (td->write_iolog)
				write_iolog_put(td, io_u);

			io_u->file = f;
			return 0;
		}
	}

	return 1;
}

#define queue_full(td)	list_empty(&(td)->io_u_freelist)

struct io_u *__get_io_u(struct thread_data *td)
{
	struct io_u *io_u = NULL;

	if (!queue_full(td)) {
		io_u = list_entry(td->io_u_freelist.next, struct io_u, list);

		io_u->error = 0;
		io_u->resid = 0;
		list_del(&io_u->list);
		list_add(&io_u->list, &td->io_u_busylist);
		td->cur_depth++;
	}

	return io_u;
}

/*
 * Return an io_u to be processed. Gets a buflen and offset, sets direction,
 * etc. The returned io_u is fully ready to be prepped and submitted.
 */
static struct io_u *get_io_u(struct thread_data *td, struct fio_file *f)
{
	struct io_u *io_u;

	io_u = __get_io_u(td);
	if (!io_u)
		return NULL;

	if (td->zone_bytes >= td->zone_size) {
		td->zone_bytes = 0;
		f->last_pos += td->zone_skip;
	}

	if (fill_io_u(td, f, io_u)) {
		put_io_u(td, io_u);
		return NULL;
	}

	if (io_u->buflen + io_u->offset > f->file_size) {
		if (td->io_ops->flags & FIO_RAWIO) {
			put_io_u(td, io_u);
			return NULL;
		}

		io_u->buflen = f->file_size - io_u->offset;
	}

	if (!io_u->buflen) {
		put_io_u(td, io_u);
		return NULL;
	}

	if (!td->read_iolog && !td->sequential)
		mark_random_map(td, f, io_u);

	f->last_pos += io_u->buflen;

	if (td->verify != VERIFY_NONE)
		populate_io_u(td, io_u);

	if (td_io_prep(td, io_u)) {
		put_io_u(td, io_u);
		return NULL;
	}

	gettimeofday(&io_u->start_time, NULL);
	return io_u;
}

static inline void td_set_runstate(struct thread_data *td, int runstate)
{
	td->runstate = runstate;
}

static int get_next_verify(struct thread_data *td, struct io_u *io_u)
{
	struct io_piece *ipo;

	if (!list_empty(&td->io_hist_list)) {
		ipo = list_entry(td->io_hist_list.next, struct io_piece, list);

		list_del(&ipo->list);

		io_u->offset = ipo->offset;
		io_u->buflen = ipo->len;
		io_u->ddir = DDIR_READ;
		free(ipo);
		return 0;
	}

	return 1;
}

static struct fio_file *get_next_file(struct thread_data *td)
{
	int old_next_file = td->next_file;
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

static int td_io_sync(struct thread_data *td, struct fio_file *f)
{
	if (td->io_ops->sync)
		return td->io_ops->sync(td, f);

	return 0;
}

static int io_u_getevents(struct thread_data *td, int min, int max,
			  struct timespec *t)
{
	return td->io_ops->getevents(td, min, max, t);
}

static int io_u_queue(struct thread_data *td, struct io_u *io_u)
{
	gettimeofday(&io_u->issue_time, NULL);

	return td->io_ops->queue(td, io_u);
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
		const int idx = io_u->ddir;

		td->io_blocks[idx]++;
		td->io_bytes[idx] += bytes;
		td->zone_bytes += bytes;
		td->this_io_bytes[idx] += bytes;

		msec = mtime_since(&io_u->issue_time, &e);

		add_clat_sample(td, idx, msec);
		add_bw_sample(td, idx);

		if ((td_rw(td) || td_write(td)) && idx == DDIR_WRITE)
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
		io_u = td->io_ops->event(td, i);

		io_completed(td, io_u, icd);
		put_io_u(td, io_u);
	}
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
	r = io_u_getevents(td, 0, td->cur_depth, &ts);
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

/*
 * The main verify engine. Runs over the writes we previusly submitted,
 * reads the blocks back in, and checks the crc/md5 of the data.
 */
static void do_verify(struct thread_data *td)
{
	struct timeval t;
	struct io_u *io_u, *v_io_u = NULL;
	struct io_completion_data icd;
	struct fio_file *f;
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

		v_io_u = td->io_ops->event(td, 0);
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
		gettimeofday(&e, NULL);

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
	struct timeval s, e;
	unsigned long usec;
	struct fio_file *f;
	int i;

	td_set_runstate(td, TD_RUNNING);

	while (td->this_io_bytes[td->ddir] < td->io_size) {
		struct timespec ts = { .tv_sec = 0, .tv_nsec = 0};
		struct timespec *timeout;
		int ret, min_evts = 0;
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
			td_io_sync(td, f);
	}

	if (td->cur_depth)
		cleanup_pending_aio(td);

	if (should_fsync(td) && td->end_fsync) {
		td_set_runstate(td, TD_FSYNCING);
		for_each_file(td, f, i)
			td_io_sync(td, f);
	}
}

static int init_io(struct thread_data *td)
{
	if (td->io_ops->init)
		return td->io_ops->init(td);

	return 0;
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
		log_err("Bad memory type %d\n", td->mem_type);

	td->orig_buffer = NULL;
}

static int init_io_u(struct thread_data *td)
{
	struct io_u *io_u;
	int i, max_units;
	char *p;

	if (td->io_ops->flags & FIO_CPUIO)
		return 0;

	if (td->io_ops->flags & FIO_SYNCIO)
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

	p = ALIGN(td->orig_buffer);
	for (i = 0; i < max_units; i++) {
		io_u = malloc(sizeof(*io_u));
		memset(io_u, 0, sizeof(*io_u));
		INIT_LIST_HEAD(&io_u->list);

		io_u->buf = p + td->max_bs * i;
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

	if (init_io(td))
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

	gettimeofday(&td->epoch, NULL);

	if (td->exec_prerun)
		system(td->exec_prerun);

	while (td->loops--) {
		getrusage(RUSAGE_SELF, &td->ru_start);
		gettimeofday(&td->start, NULL);
		memcpy(&td->stat_sample_time, &td->start, sizeof(td->start));

		if (td->ratemin)
			memcpy(&td->lastrate, &td->stat_sample_time, sizeof(td->lastrate));

		clear_io_state(td);
		prune_io_piece_log(td);

		if (td->io_ops->flags & FIO_CPUIO)
			do_cpuio(td);
		else
			do_io(td);

		td->runtime[td->ddir] += mtime_since_now(&td->start);
		if (td_rw(td) && td->io_bytes[td->ddir ^ 1])
			td->runtime[td->ddir ^ 1] = td->runtime[td->ddir];

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

	if (td->bw_log)
		finish_log(td, td->bw_log, "bw");
	if (td->slat_log)
		finish_log(td, td->slat_log, "slat");
	if (td->clat_log)
		finish_log(td, td->clat_log, "clat");
	if (td->write_iolog)
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
 * Sets the status of the 'td' in the printed status map.
 */
static void check_str_update(struct thread_data *td)
{
	char c = run_str[td->thread_number - 1];

	switch (td->runstate) {
		case TD_REAPED:
			c = '_';
			break;
		case TD_EXITED:
			c = 'E';
			break;
		case TD_RUNNING:
			if (td_rw(td)) {
				if (td->sequential)
					c = 'M';
				else
					c = 'm';
			} else if (td_read(td)) {
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
		case TD_FSYNCING:
			c = 'F';
			break;
		case TD_CREATED:
			c = 'C';
			break;
		case TD_INITIALIZED:
			c = 'I';
			break;
		case TD_NOT_CREATED:
			c = 'P';
			break;
		default:
			log_err("state %d\n", td->runstate);
	}

	run_str[td->thread_number - 1] = c;
}

/*
 * Convert seconds to a printable string.
 */
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

/*
 * Best effort calculation of the estimated pending runtime of a job.
 */
static int thread_eta(struct thread_data *td, unsigned long elapsed)
{
	unsigned long long bytes_total, bytes_done;
	unsigned int eta_sec = 0;

	bytes_total = td->total_io_size;

	/*
	 * if writing, bytes_total will be twice the size. If mixing,
	 * assume a 50/50 split and thus bytes_total will be 50% larger.
	 */
	if (td->verify) {
		if (td_rw(td))
			bytes_total = bytes_total * 3 / 2;
		else
			bytes_total <<= 1;
	}
	if (td->zone_size && td->zone_skip)
		bytes_total /= (td->zone_skip / td->zone_size);

	if (td->runstate == TD_RUNNING || td->runstate == TD_VERIFYING) {
		double perc;

		bytes_done = td->io_bytes[DDIR_READ] + td->io_bytes[DDIR_WRITE];
		perc = (double) bytes_done / (double) bytes_total;
		if (perc > 1.0)
			perc = 1.0;

		eta_sec = (elapsed * (1.0 / perc)) - elapsed;

		if (td->timeout && eta_sec > (td->timeout - elapsed))
			eta_sec = td->timeout - elapsed;
	} else if (td->runstate == TD_NOT_CREATED || td->runstate == TD_CREATED
			|| td->runstate == TD_INITIALIZED) {
		int t_eta = 0, r_eta = 0;

		/*
		 * We can only guess - assume it'll run the full timeout
		 * if given, otherwise assume it'll run at the specified rate.
		 */
		if (td->timeout)
			t_eta = td->timeout + td->start_delay - elapsed;
		if (td->rate) {
			r_eta = (bytes_total / 1024) / td->rate;
			r_eta += td->start_delay - elapsed;
		}

		if (r_eta && t_eta)
			eta_sec = min(r_eta, t_eta);
		else if (r_eta)
			eta_sec = r_eta;
		else if (t_eta)
			eta_sec = t_eta;
		else
			eta_sec = 0;
	} else {
		/*
		 * thread is already done or waiting for fsync
		 */
		eta_sec = 0;
	}

	return eta_sec;
}

/*
 * Print status of the jobs we know about. This includes rate estimates,
 * ETA, thread state, etc.
 */
static void print_thread_status(void)
{
	unsigned long elapsed = time_since_now(&genesis);
	int i, nr_running, nr_pending, t_rate, m_rate, *eta_secs, eta_sec;
	char eta_str[32];
	double perc = 0.0;

	if (temp_stall_ts || terse_output)
		return;

	eta_secs = malloc(thread_number * sizeof(int));
	memset(eta_secs, 0, thread_number * sizeof(int));

	nr_pending = nr_running = t_rate = m_rate = 0;
	for (i = 0; i < thread_number; i++) {
		struct thread_data *td = &threads[i];

		if (td->runstate == TD_RUNNING || td->runstate == TD_VERIFYING||
		    td->runstate == TD_FSYNCING) {
			nr_running++;
			t_rate += td->rate;
			m_rate += td->ratemin;
		} else if (td->runstate < TD_RUNNING)
			nr_pending++;

		if (elapsed >= 3)
			eta_secs[i] = thread_eta(td, elapsed);
		else
			eta_secs[i] = INT_MAX;

		check_str_update(td);
	}

	if (exitall_on_terminate)
		eta_sec = INT_MAX;
	else
		eta_sec = 0;

	for (i = 0; i < thread_number; i++) {
		if (exitall_on_terminate) {
			if (eta_secs[i] < eta_sec)
				eta_sec = eta_secs[i];
		} else {
			if (eta_secs[i] > eta_sec)
				eta_sec = eta_secs[i];
		}
	}

	if (eta_sec != INT_MAX && elapsed) {
		perc = (double) elapsed / (double) (elapsed + eta_sec);
		eta_to_str(eta_str, eta_sec);
	}

	if (!nr_running && !nr_pending)
		return;

	printf("Threads running: %d", nr_running);
	if (m_rate || t_rate)
		printf(", commitrate %d/%dKiB/sec", t_rate, m_rate);
	if (eta_sec != INT_MAX && nr_running) {
		perc *= 100.0;
		printf(": [%s] [%3.2f%% done] [eta %s]", run_str, perc,eta_str);
	}
	printf("\r");
	fflush(stdout);
	free(eta_secs);
}

/*
 * Run over the job map and reap the threads that have exited, if any.
 */
static void reap_threads(int *nr_running, int *t_rate, int *m_rate)
{
	int i, cputhreads;

	/*
	 * reap exited threads (TD_EXITED -> TD_REAPED)
	 */
	for (i = 0, cputhreads = 0; i < thread_number; i++) {
		struct thread_data *td = &threads[i];

		if (td->io_ops->flags & FIO_CPUIO)
			cputhreads++;

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

	if (*nr_running == cputhreads)
		terminate_threads(TERMINATE_ALL);
}

static void fio_unpin_memory(void *pinned)
{
	if (pinned) {
		if (munlock(pinned, mlock_size) < 0)
			perror("munlock");
		munmap(pinned, mlock_size);
	}
}

static void *fio_pin_memory(void)
{
	unsigned long long phys_mem;
	void *ptr;

	if (!mlock_size)
		return NULL;

	/*
	 * Don't allow mlock of more than real_mem-128MB
	 */
	phys_mem = os_phys_mem();
	if (phys_mem) {
		if ((mlock_size + 128 * 1024 * 1024) > phys_mem) {
			mlock_size = phys_mem - 128 * 1024 * 1024;
			fprintf(f_out, "fio: limiting mlocked memory to %lluMiB\n", mlock_size >> 20);
		}
	}

	ptr = mmap(NULL, mlock_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | OS_MAP_ANON, 0, 0);
	if (!ptr) {
		perror("malloc locked mem");
		return NULL;
	}
	if (mlock(ptr, mlock_size) < 0) {
		munmap(ptr, mlock_size);
		perror("mlock");
		return NULL;
	}

	return ptr;
}

/*
 * Main function for kicking off and reaping jobs, as needed.
 */
static void run_threads(void)
{
	struct thread_data *td;
	unsigned long spent;
	int i, todo, nr_running, m_rate, t_rate, nr_started;
	void *mlocked_mem;

	mlocked_mem = fio_pin_memory();

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
		if (setup_files(td)) {
			td_set_runstate(td, TD_REAPED);
			todo--;
		}
	}

	gettimeofday(&genesis, NULL);

	while (todo) {
		struct thread_data *map[MAX_JOBS];
		struct timeval this_start;
		int this_jobs = 0, left;

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
		gettimeofday(&this_start, NULL);
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
		for (i = 0; i < thread_number; i++) {
			td = &threads[i];

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
	fio_unpin_memory(mlocked_mem);
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
