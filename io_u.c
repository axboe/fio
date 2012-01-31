#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <assert.h>

#include "fio.h"
#include "hash.h"
#include "verify.h"
#include "trim.h"
#include "lib/rand.h"

struct io_completion_data {
	int nr;				/* input */
	int account;			/* input */

	int error;			/* output */
	unsigned long bytes_done[2];	/* output */
	struct timeval time;		/* output */
};

/*
 * The ->file_map[] contains a map of blocks we have or have not done io
 * to yet. Used to make sure we cover the entire range in a fair fashion.
 */
static int random_map_free(struct fio_file *f, const unsigned long long block)
{
	unsigned int idx = RAND_MAP_IDX(f, block);
	unsigned int bit = RAND_MAP_BIT(f, block);

	dprint(FD_RANDOM, "free: b=%llu, idx=%u, bit=%u\n", block, idx, bit);

	return (f->file_map[idx] & (1UL << bit)) == 0;
}

/*
 * Mark a given offset as used in the map.
 */
static void mark_random_map(struct thread_data *td, struct io_u *io_u)
{
	unsigned int min_bs = td->o.rw_min_bs;
	struct fio_file *f = io_u->file;
	unsigned long long block;
	unsigned int blocks, nr_blocks;
	int busy_check;

	block = (io_u->offset - f->file_offset) / (unsigned long long) min_bs;
	nr_blocks = (io_u->buflen + min_bs - 1) / min_bs;
	blocks = 0;
	busy_check = !(io_u->flags & IO_U_F_BUSY_OK);

	while (nr_blocks) {
		unsigned int idx, bit;
		unsigned long mask, this_blocks;

		/*
		 * If we have a mixed random workload, we may
		 * encounter blocks we already did IO to.
		 */
		if (!busy_check) {
			blocks = nr_blocks;
			break;
		}
		if ((td->o.ddir_seq_nr == 1) && !random_map_free(f, block))
			break;

		idx = RAND_MAP_IDX(f, block);
		bit = RAND_MAP_BIT(f, block);

		fio_assert(td, idx < f->num_maps);

		this_blocks = nr_blocks;
		if (this_blocks + bit > BLOCKS_PER_MAP)
			this_blocks = BLOCKS_PER_MAP - bit;

		do {
			if (this_blocks == BLOCKS_PER_MAP)
				mask = -1UL;
			else
				mask = ((1UL << this_blocks) - 1) << bit;
	
			if (!(f->file_map[idx] & mask))
				break;

			this_blocks--;
		} while (this_blocks);

		if (!this_blocks)
			break;

		f->file_map[idx] |= mask;
		nr_blocks -= this_blocks;
		blocks += this_blocks;
		block += this_blocks;
	}

	if ((blocks * min_bs) < io_u->buflen)
		io_u->buflen = blocks * min_bs;
}

static unsigned long long last_block(struct thread_data *td, struct fio_file *f,
				     enum fio_ddir ddir)
{
	unsigned long long max_blocks;
	unsigned long long max_size;

	assert(ddir_rw(ddir));

	/*
	 * Hmm, should we make sure that ->io_size <= ->real_file_size?
	 */
	max_size = f->io_size;
	if (max_size > f->real_file_size)
		max_size = f->real_file_size;

	if (td->o.zone_range)
		max_size = td->o.zone_range;

	max_blocks = max_size / (unsigned long long) td->o.ba[ddir];
	if (!max_blocks)
		return 0;

	return max_blocks;
}

/*
 * Return the next free block in the map.
 */
static int get_next_free_block(struct thread_data *td, struct fio_file *f,
			       enum fio_ddir ddir, unsigned long long *b)
{
	unsigned long long block, min_bs = td->o.rw_min_bs, lastb;
	int i;

	lastb = last_block(td, f, ddir);
	if (!lastb)
		return 1;

	i = f->last_free_lookup;
	block = i * BLOCKS_PER_MAP;
	while (block * min_bs < f->real_file_size &&
		block * min_bs < f->io_size) {
		if (f->file_map[i] != -1UL) {
			block += ffz(f->file_map[i]);
			if (block > lastb)
				break;
			f->last_free_lookup = i;
			*b = block;
			return 0;
		}

		block += BLOCKS_PER_MAP;
		i++;
	}

	dprint(FD_IO, "failed finding a free block\n");
	return 1;
}

static int get_next_rand_offset(struct thread_data *td, struct fio_file *f,
				enum fio_ddir ddir, unsigned long long *b)
{
	unsigned long long rmax, r, lastb;
	int loops = 5;

	lastb = last_block(td, f, ddir);
	if (!lastb)
		return 1;

	if (f->failed_rands >= 200)
		goto ffz;

	rmax = td->o.use_os_rand ? OS_RAND_MAX : FRAND_MAX;
	do {
		if (td->o.use_os_rand)
			r = os_random_long(&td->random_state);
		else
			r = __rand(&td->__random_state);

		*b = (lastb - 1) * (r / ((unsigned long long) rmax + 1.0));

		dprint(FD_RANDOM, "off rand %llu\n", r);


		/*
		 * if we are not maintaining a random map, we are done.
		 */
		if (!file_randommap(td, f))
			goto ret_good;

		/*
		 * calculate map offset and check if it's free
		 */
		if (random_map_free(f, *b))
			goto ret_good;

		dprint(FD_RANDOM, "get_next_rand_offset: offset %llu busy\n",
									*b);
	} while (--loops);

	if (!f->failed_rands++)
		f->last_free_lookup = 0;

	/*
	 * we get here, if we didn't suceed in looking up a block. generate
	 * a random start offset into the filemap, and find the first free
	 * block from there.
	 */
	loops = 10;
	do {
		f->last_free_lookup = (f->num_maps - 1) *
					(r / ((unsigned long long) rmax + 1.0));
		if (!get_next_free_block(td, f, ddir, b))
			goto ret;

		if (td->o.use_os_rand)
			r = os_random_long(&td->random_state);
		else
			r = __rand(&td->__random_state);
	} while (--loops);

	/*
	 * that didn't work either, try exhaustive search from the start
	 */
	f->last_free_lookup = 0;
ffz:
	if (!get_next_free_block(td, f, ddir, b))
		return 0;
	f->last_free_lookup = 0;
	return get_next_free_block(td, f, ddir, b);
ret_good:
	f->failed_rands = 0;
ret:
	return 0;
}

static int get_next_rand_block(struct thread_data *td, struct fio_file *f,
			       enum fio_ddir ddir, unsigned long long *b)
{
	if (get_next_rand_offset(td, f, ddir, b)) {
		dprint(FD_IO, "%s: rand offset failed, last=%llu, size=%llu\n",
				f->file_name, f->last_pos, f->real_file_size);
		return 1;
	}

	return 0;
}

static int get_next_seq_block(struct thread_data *td, struct fio_file *f,
			      enum fio_ddir ddir, unsigned long long *b)
{
	assert(ddir_rw(ddir));

	if (f->last_pos < f->real_file_size) {
		unsigned long long pos;

		if (f->last_pos == f->file_offset && td->o.ddir_seq_add < 0)
			f->last_pos = f->real_file_size;

		pos = f->last_pos - f->file_offset;
		if (pos)
			pos += td->o.ddir_seq_add;

		*b = pos / td->o.min_bs[ddir];
		return 0;
	}

	return 1;
}

static int get_next_block(struct thread_data *td, struct io_u *io_u,
			  enum fio_ddir ddir, int rw_seq, unsigned long long *b)
{
	struct fio_file *f = io_u->file;
	int ret;

	assert(ddir_rw(ddir));

	if (rw_seq) {
		if (td_random(td))
			ret = get_next_rand_block(td, f, ddir, b);
		else
			ret = get_next_seq_block(td, f, ddir, b);
	} else {
		io_u->flags |= IO_U_F_BUSY_OK;

		if (td->o.rw_seq == RW_SEQ_SEQ) {
			ret = get_next_seq_block(td, f, ddir, b);
			if (ret)
				ret = get_next_rand_block(td, f, ddir, b);
		} else if (td->o.rw_seq == RW_SEQ_IDENT) {
			if (f->last_start != -1ULL)
				*b = (f->last_start - f->file_offset)
					/ td->o.min_bs[ddir];
			else
				*b = 0;
			ret = 0;
		} else {
			log_err("fio: unknown rw_seq=%d\n", td->o.rw_seq);
			ret = 1;
		}
	}
	
	return ret;
}

/*
 * For random io, generate a random new block and see if it's used. Repeat
 * until we find a free one. For sequential io, just return the end of
 * the last io issued.
 */
static int __get_next_offset(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	unsigned long long b;
	enum fio_ddir ddir = io_u->ddir;
	int rw_seq_hit = 0;

	assert(ddir_rw(ddir));

	if (td->o.ddir_seq_nr && !--td->ddir_seq_nr) {
		rw_seq_hit = 1;
		td->ddir_seq_nr = td->o.ddir_seq_nr;
	}

	if (get_next_block(td, io_u, ddir, rw_seq_hit, &b))
		return 1;

	io_u->offset = b * td->o.ba[ddir];
	if (io_u->offset >= f->io_size) {
		dprint(FD_IO, "get_next_offset: offset %llu >= io_size %llu\n",
					io_u->offset, f->io_size);
		return 1;
	}

	io_u->offset += f->file_offset;
	if (io_u->offset >= f->real_file_size) {
		dprint(FD_IO, "get_next_offset: offset %llu >= size %llu\n",
					io_u->offset, f->real_file_size);
		return 1;
	}

	return 0;
}

static int get_next_offset(struct thread_data *td, struct io_u *io_u)
{
	struct prof_io_ops *ops = &td->prof_io_ops;

	if (ops->fill_io_u_off)
		return ops->fill_io_u_off(td, io_u);

	return __get_next_offset(td, io_u);
}

static inline int io_u_fits(struct thread_data *td, struct io_u *io_u,
			    unsigned int buflen)
{
	struct fio_file *f = io_u->file;

	return io_u->offset + buflen <= f->io_size + td->o.start_offset;
}

static unsigned int __get_next_buflen(struct thread_data *td, struct io_u *io_u)
{
	const int ddir = io_u->ddir;
	unsigned int uninitialized_var(buflen);
	unsigned int minbs, maxbs;
	unsigned long r, rand_max;

	assert(ddir_rw(ddir));

	minbs = td->o.min_bs[ddir];
	maxbs = td->o.max_bs[ddir];

	if (minbs == maxbs)
		return minbs;

	if (td->o.use_os_rand)
		rand_max = OS_RAND_MAX;
	else
		rand_max = FRAND_MAX;

	do {
		if (td->o.use_os_rand)
			r = os_random_long(&td->bsrange_state);
		else
			r = __rand(&td->__bsrange_state);

		if (!td->o.bssplit_nr[ddir]) {
			buflen = 1 + (unsigned int) ((double) maxbs *
					(r / (rand_max + 1.0)));
			if (buflen < minbs)
				buflen = minbs;
		} else {
			long perc = 0;
			unsigned int i;

			for (i = 0; i < td->o.bssplit_nr[ddir]; i++) {
				struct bssplit *bsp = &td->o.bssplit[ddir][i];

				buflen = bsp->bs;
				perc += bsp->perc;
				if ((r <= ((rand_max / 100L) * perc)) &&
				    io_u_fits(td, io_u, buflen))
					break;
			}
		}

		if (!td->o.bs_unaligned && is_power_of_2(minbs))
			buflen = (buflen + minbs - 1) & ~(minbs - 1);

	} while (!io_u_fits(td, io_u, buflen));

	return buflen;
}

static unsigned int get_next_buflen(struct thread_data *td, struct io_u *io_u)
{
	struct prof_io_ops *ops = &td->prof_io_ops;

	if (ops->fill_io_u_size)
		return ops->fill_io_u_size(td, io_u);

	return __get_next_buflen(td, io_u);
}

static void set_rwmix_bytes(struct thread_data *td)
{
	unsigned int diff;

	/*
	 * we do time or byte based switch. this is needed because
	 * buffered writes may issue a lot quicker than they complete,
	 * whereas reads do not.
	 */
	diff = td->o.rwmix[td->rwmix_ddir ^ 1];
	td->rwmix_issues = (td->io_issues[td->rwmix_ddir] * diff) / 100;
}

static inline enum fio_ddir get_rand_ddir(struct thread_data *td)
{
	unsigned int v;
	unsigned long r;

	if (td->o.use_os_rand) {
		r = os_random_long(&td->rwmix_state);
		v = 1 + (int) (100.0 * (r / (OS_RAND_MAX + 1.0)));
	} else {
		r = __rand(&td->__rwmix_state);
		v = 1 + (int) (100.0 * (r / (FRAND_MAX + 1.0)));
	}

	if (v <= td->o.rwmix[DDIR_READ])
		return DDIR_READ;

	return DDIR_WRITE;
}

static enum fio_ddir rate_ddir(struct thread_data *td, enum fio_ddir ddir)
{
	enum fio_ddir odir = ddir ^ 1;
	struct timeval t;
	long usec;

	assert(ddir_rw(ddir));

	if (td->rate_pending_usleep[ddir] <= 0)
		return ddir;

	/*
	 * We have too much pending sleep in this direction. See if we
	 * should switch.
	 */
	if (td_rw(td)) {
		/*
		 * Other direction does not have too much pending, switch
		 */
		if (td->rate_pending_usleep[odir] < 100000)
			return odir;

		/*
		 * Both directions have pending sleep. Sleep the minimum time
		 * and deduct from both.
		 */
		if (td->rate_pending_usleep[ddir] <=
			td->rate_pending_usleep[odir]) {
			usec = td->rate_pending_usleep[ddir];
		} else {
			usec = td->rate_pending_usleep[odir];
			ddir = odir;
		}
	} else
		usec = td->rate_pending_usleep[ddir];

	/*
	 * We are going to sleep, ensure that we flush anything pending as
	 * not to skew our latency numbers
	 */
	if (td->cur_depth) {
		int fio_unused ret;

		ret = io_u_queued_complete(td, td->cur_depth, NULL);
	}

	fio_gettime(&t, NULL);
	usec_sleep(td, usec);
	usec = utime_since_now(&t);

	td->rate_pending_usleep[ddir] -= usec;

	odir = ddir ^ 1;
	if (td_rw(td) && __should_check_rate(td, odir))
		td->rate_pending_usleep[odir] -= usec;

	return ddir;
}

/*
 * Return the data direction for the next io_u. If the job is a
 * mixed read/write workload, check the rwmix cycle and switch if
 * necessary.
 */
static enum fio_ddir get_rw_ddir(struct thread_data *td)
{
	enum fio_ddir ddir;

	/*
	 * see if it's time to fsync
	 */
	if (td->o.fsync_blocks &&
	   !(td->io_issues[DDIR_WRITE] % td->o.fsync_blocks) &&
	     td->io_issues[DDIR_WRITE] && should_fsync(td))
		return DDIR_SYNC;

	/*
	 * see if it's time to fdatasync
	 */
	if (td->o.fdatasync_blocks &&
	   !(td->io_issues[DDIR_WRITE] % td->o.fdatasync_blocks) &&
	     td->io_issues[DDIR_WRITE] && should_fsync(td))
		return DDIR_DATASYNC;

	/*
	 * see if it's time to sync_file_range
	 */
	if (td->sync_file_range_nr &&
	   !(td->io_issues[DDIR_WRITE] % td->sync_file_range_nr) &&
	     td->io_issues[DDIR_WRITE] && should_fsync(td))
		return DDIR_SYNC_FILE_RANGE;

	if (td_rw(td)) {
		/*
		 * Check if it's time to seed a new data direction.
		 */
		if (td->io_issues[td->rwmix_ddir] >= td->rwmix_issues) {
			/*
			 * Put a top limit on how many bytes we do for
			 * one data direction, to avoid overflowing the
			 * ranges too much
			 */
			ddir = get_rand_ddir(td);

			if (ddir != td->rwmix_ddir)
				set_rwmix_bytes(td);

			td->rwmix_ddir = ddir;
		}
		ddir = td->rwmix_ddir;
	} else if (td_read(td))
		ddir = DDIR_READ;
	else
		ddir = DDIR_WRITE;

	td->rwmix_ddir = rate_ddir(td, ddir);
	return td->rwmix_ddir;
}

static void set_rw_ddir(struct thread_data *td, struct io_u *io_u)
{
	io_u->ddir = get_rw_ddir(td);

	if (io_u->ddir == DDIR_WRITE && (td->io_ops->flags & FIO_BARRIER) &&
	    td->o.barrier_blocks &&
	   !(td->io_issues[DDIR_WRITE] % td->o.barrier_blocks) &&
	     td->io_issues[DDIR_WRITE])
		io_u->flags |= IO_U_F_BARRIER;
}

void put_file_log(struct thread_data *td, struct fio_file *f)
{
	int ret = put_file(td, f);

	if (ret)
		td_verror(td, ret, "file close");
}

void put_io_u(struct thread_data *td, struct io_u *io_u)
{
	td_io_u_lock(td);

	if (io_u->file && !(io_u->flags & IO_U_F_FREE_DEF))
		put_file_log(td, io_u->file);
	io_u->file = NULL;
	io_u->flags &= ~IO_U_F_FREE_DEF;
	io_u->flags |= IO_U_F_FREE;

	if (io_u->flags & IO_U_F_IN_CUR_DEPTH)
		td->cur_depth--;
	flist_del_init(&io_u->list);
	flist_add(&io_u->list, &td->io_u_freelist);
	td_io_u_unlock(td);
	td_io_u_free_notify(td);
}

void clear_io_u(struct thread_data *td, struct io_u *io_u)
{
	io_u->flags &= ~IO_U_F_FLIGHT;
	put_io_u(td, io_u);
}

void requeue_io_u(struct thread_data *td, struct io_u **io_u)
{
	struct io_u *__io_u = *io_u;

	dprint(FD_IO, "requeue %p\n", __io_u);

	td_io_u_lock(td);

	__io_u->flags |= IO_U_F_FREE;
	if ((__io_u->flags & IO_U_F_FLIGHT) && ddir_rw(__io_u->ddir))
		td->io_issues[__io_u->ddir]--;

	__io_u->flags &= ~IO_U_F_FLIGHT;
	if (__io_u->flags & IO_U_F_IN_CUR_DEPTH)
		td->cur_depth--;
	flist_del(&__io_u->list);
	flist_add_tail(&__io_u->list, &td->io_u_requeues);
	td_io_u_unlock(td);
	*io_u = NULL;
}

static int fill_io_u(struct thread_data *td, struct io_u *io_u)
{
	if (td->io_ops->flags & FIO_NOIO)
		goto out;

	set_rw_ddir(td, io_u);

	/*
	 * fsync() or fdatasync() or trim etc, we are done
	 */
	if (!ddir_rw(io_u->ddir))
		goto out;

	/*
	 * See if it's time to switch to a new zone
	 */
	if (td->zone_bytes >= td->o.zone_size) {
		td->zone_bytes = 0;
		io_u->file->file_offset += td->o.zone_range + td->o.zone_skip;
		io_u->file->last_pos = io_u->file->file_offset;
		td->io_skip_bytes += td->o.zone_skip;
	}

	/*
	 * No log, let the seq/rand engine retrieve the next buflen and
	 * position.
	 */
	if (get_next_offset(td, io_u)) {
		dprint(FD_IO, "io_u %p, failed getting offset\n", io_u);
		return 1;
	}

	io_u->buflen = get_next_buflen(td, io_u);
	if (!io_u->buflen) {
		dprint(FD_IO, "io_u %p, failed getting buflen\n", io_u);
		return 1;
	}

	if (io_u->offset + io_u->buflen > io_u->file->real_file_size) {
		dprint(FD_IO, "io_u %p, offset too large\n", io_u);
		dprint(FD_IO, "  off=%llu/%lu > %llu\n", io_u->offset,
				io_u->buflen, io_u->file->real_file_size);
		return 1;
	}

	/*
	 * mark entry before potentially trimming io_u
	 */
	if (td_random(td) && file_randommap(td, io_u->file))
		mark_random_map(td, io_u);

	/*
	 * If using a write iolog, store this entry.
	 */
out:
	dprint_io_u(io_u, "fill_io_u");
	td->zone_bytes += io_u->buflen;
	log_io_u(td, io_u);
	return 0;
}

static void __io_u_mark_map(unsigned int *map, unsigned int nr)
{
	int idx = 0;

	switch (nr) {
	default:
		idx = 6;
		break;
	case 33 ... 64:
		idx = 5;
		break;
	case 17 ... 32:
		idx = 4;
		break;
	case 9 ... 16:
		idx = 3;
		break;
	case 5 ... 8:
		idx = 2;
		break;
	case 1 ... 4:
		idx = 1;
	case 0:
		break;
	}

	map[idx]++;
}

void io_u_mark_submit(struct thread_data *td, unsigned int nr)
{
	__io_u_mark_map(td->ts.io_u_submit, nr);
	td->ts.total_submit++;
}

void io_u_mark_complete(struct thread_data *td, unsigned int nr)
{
	__io_u_mark_map(td->ts.io_u_complete, nr);
	td->ts.total_complete++;
}

void io_u_mark_depth(struct thread_data *td, unsigned int nr)
{
	int idx = 0;

	switch (td->cur_depth) {
	default:
		idx = 6;
		break;
	case 32 ... 63:
		idx = 5;
		break;
	case 16 ... 31:
		idx = 4;
		break;
	case 8 ... 15:
		idx = 3;
		break;
	case 4 ... 7:
		idx = 2;
		break;
	case 2 ... 3:
		idx = 1;
	case 1:
		break;
	}

	td->ts.io_u_map[idx] += nr;
}

static void io_u_mark_lat_usec(struct thread_data *td, unsigned long usec)
{
	int idx = 0;

	assert(usec < 1000);

	switch (usec) {
	case 750 ... 999:
		idx = 9;
		break;
	case 500 ... 749:
		idx = 8;
		break;
	case 250 ... 499:
		idx = 7;
		break;
	case 100 ... 249:
		idx = 6;
		break;
	case 50 ... 99:
		idx = 5;
		break;
	case 20 ... 49:
		idx = 4;
		break;
	case 10 ... 19:
		idx = 3;
		break;
	case 4 ... 9:
		idx = 2;
		break;
	case 2 ... 3:
		idx = 1;
	case 0 ... 1:
		break;
	}

	assert(idx < FIO_IO_U_LAT_U_NR);
	td->ts.io_u_lat_u[idx]++;
}

static void io_u_mark_lat_msec(struct thread_data *td, unsigned long msec)
{
	int idx = 0;

	switch (msec) {
	default:
		idx = 11;
		break;
	case 1000 ... 1999:
		idx = 10;
		break;
	case 750 ... 999:
		idx = 9;
		break;
	case 500 ... 749:
		idx = 8;
		break;
	case 250 ... 499:
		idx = 7;
		break;
	case 100 ... 249:
		idx = 6;
		break;
	case 50 ... 99:
		idx = 5;
		break;
	case 20 ... 49:
		idx = 4;
		break;
	case 10 ... 19:
		idx = 3;
		break;
	case 4 ... 9:
		idx = 2;
		break;
	case 2 ... 3:
		idx = 1;
	case 0 ... 1:
		break;
	}

	assert(idx < FIO_IO_U_LAT_M_NR);
	td->ts.io_u_lat_m[idx]++;
}

static void io_u_mark_latency(struct thread_data *td, unsigned long usec)
{
	if (usec < 1000)
		io_u_mark_lat_usec(td, usec);
	else
		io_u_mark_lat_msec(td, usec / 1000);
}

/*
 * Get next file to service by choosing one at random
 */
static struct fio_file *get_next_file_rand(struct thread_data *td,
					   enum fio_file_flags goodf,
					   enum fio_file_flags badf)
{
	struct fio_file *f;
	int fno;

	do {
		int opened = 0;
		unsigned long r;

		if (td->o.use_os_rand) {
			r = os_random_long(&td->next_file_state);
			fno = (unsigned int) ((double) td->o.nr_files
				* (r / (OS_RAND_MAX + 1.0)));
		} else {
			r = __rand(&td->__next_file_state);
			fno = (unsigned int) ((double) td->o.nr_files
				* (r / (FRAND_MAX + 1.0)));
		}

		f = td->files[fno];
		if (fio_file_done(f))
			continue;

		if (!fio_file_open(f)) {
			int err;

			err = td_io_open_file(td, f);
			if (err)
				continue;
			opened = 1;
		}

		if ((!goodf || (f->flags & goodf)) && !(f->flags & badf)) {
			dprint(FD_FILE, "get_next_file_rand: %p\n", f);
			return f;
		}
		if (opened)
			td_io_close_file(td, f);
	} while (1);
}

/*
 * Get next file to service by doing round robin between all available ones
 */
static struct fio_file *get_next_file_rr(struct thread_data *td, int goodf,
					 int badf)
{
	unsigned int old_next_file = td->next_file;
	struct fio_file *f;

	do {
		int opened = 0;

		f = td->files[td->next_file];

		td->next_file++;
		if (td->next_file >= td->o.nr_files)
			td->next_file = 0;

		dprint(FD_FILE, "trying file %s %x\n", f->file_name, f->flags);
		if (fio_file_done(f)) {
			f = NULL;
			continue;
		}

		if (!fio_file_open(f)) {
			int err;

			err = td_io_open_file(td, f);
			if (err) {
				dprint(FD_FILE, "error %d on open of %s\n",
					err, f->file_name);
				f = NULL;
				continue;
			}
			opened = 1;
		}

		dprint(FD_FILE, "goodf=%x, badf=%x, ff=%x\n", goodf, badf,
								f->flags);
		if ((!goodf || (f->flags & goodf)) && !(f->flags & badf))
			break;

		if (opened)
			td_io_close_file(td, f);

		f = NULL;
	} while (td->next_file != old_next_file);

	dprint(FD_FILE, "get_next_file_rr: %p\n", f);
	return f;
}

static struct fio_file *__get_next_file(struct thread_data *td)
{
	struct fio_file *f;

	assert(td->o.nr_files <= td->files_index);

	if (td->nr_done_files >= td->o.nr_files) {
		dprint(FD_FILE, "get_next_file: nr_open=%d, nr_done=%d,"
				" nr_files=%d\n", td->nr_open_files,
						  td->nr_done_files,
						  td->o.nr_files);
		return NULL;
	}

	f = td->file_service_file;
	if (f && fio_file_open(f) && !fio_file_closing(f)) {
		if (td->o.file_service_type == FIO_FSERVICE_SEQ)
			goto out;
		if (td->file_service_left--)
			goto out;
	}

	if (td->o.file_service_type == FIO_FSERVICE_RR ||
	    td->o.file_service_type == FIO_FSERVICE_SEQ)
		f = get_next_file_rr(td, FIO_FILE_open, FIO_FILE_closing);
	else
		f = get_next_file_rand(td, FIO_FILE_open, FIO_FILE_closing);

	td->file_service_file = f;
	td->file_service_left = td->file_service_nr - 1;
out:
	dprint(FD_FILE, "get_next_file: %p [%s]\n", f, f->file_name);
	return f;
}

static struct fio_file *get_next_file(struct thread_data *td)
{
	struct prof_io_ops *ops = &td->prof_io_ops;

	if (ops->get_next_file)
		return ops->get_next_file(td);

	return __get_next_file(td);
}

static int set_io_u_file(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f;

	do {
		f = get_next_file(td);
		if (!f)
			return 1;

		io_u->file = f;
		get_file(f);

		if (!fill_io_u(td, io_u))
			break;

		put_file_log(td, f);
		td_io_close_file(td, f);
		io_u->file = NULL;
		fio_file_set_done(f);
		td->nr_done_files++;
		dprint(FD_FILE, "%s: is done (%d of %d)\n", f->file_name,
					td->nr_done_files, td->o.nr_files);
	} while (1);

	return 0;
}


struct io_u *__get_io_u(struct thread_data *td)
{
	struct io_u *io_u = NULL;

	td_io_u_lock(td);

again:
	if (!flist_empty(&td->io_u_requeues))
		io_u = flist_entry(td->io_u_requeues.next, struct io_u, list);
	else if (!queue_full(td)) {
		io_u = flist_entry(td->io_u_freelist.next, struct io_u, list);

		io_u->buflen = 0;
		io_u->resid = 0;
		io_u->file = NULL;
		io_u->end_io = NULL;
	}

	if (io_u) {
		assert(io_u->flags & IO_U_F_FREE);
		io_u->flags &= ~(IO_U_F_FREE | IO_U_F_FREE_DEF);
		io_u->flags &= ~(IO_U_F_TRIMMED | IO_U_F_BARRIER);

		io_u->error = 0;
		flist_del(&io_u->list);
		flist_add(&io_u->list, &td->io_u_busylist);
		td->cur_depth++;
		io_u->flags |= IO_U_F_IN_CUR_DEPTH;
	} else if (td->o.verify_async) {
		/*
		 * We ran out, wait for async verify threads to finish and
		 * return one
		 */
		pthread_cond_wait(&td->free_cond, &td->io_u_lock);
		goto again;
	}

	td_io_u_unlock(td);
	return io_u;
}

static int check_get_trim(struct thread_data *td, struct io_u *io_u)
{
	if (td->o.trim_backlog && td->trim_entries) {
		int get_trim = 0;

		if (td->trim_batch) {
			td->trim_batch--;
			get_trim = 1;
		} else if (!(td->io_hist_len % td->o.trim_backlog) &&
			 td->last_ddir != DDIR_READ) {
			td->trim_batch = td->o.trim_batch;
			if (!td->trim_batch)
				td->trim_batch = td->o.trim_backlog;
			get_trim = 1;
		}

		if (get_trim && !get_next_trim(td, io_u))
			return 1;
	}

	return 0;
}

static int check_get_verify(struct thread_data *td, struct io_u *io_u)
{
	if (td->o.verify_backlog && td->io_hist_len) {
		int get_verify = 0;

		if (td->verify_batch) {
			td->verify_batch--;
			get_verify = 1;
		} else if (!(td->io_hist_len % td->o.verify_backlog) &&
			 td->last_ddir != DDIR_READ) {
			td->verify_batch = td->o.verify_batch;
			if (!td->verify_batch)
				td->verify_batch = td->o.verify_backlog;
			get_verify = 1;
		}

		if (get_verify && !get_next_verify(td, io_u))
			return 1;
	}

	return 0;
}

/*
 * Fill offset and start time into the buffer content, to prevent too
 * easy compressible data for simple de-dupe attempts. Do this for every
 * 512b block in the range, since that should be the smallest block size
 * we can expect from a device.
 */
static void small_content_scramble(struct io_u *io_u)
{
	unsigned int i, nr_blocks = io_u->buflen / 512;
	unsigned long long boffset;
	unsigned int offset;
	void *p, *end;

	if (!nr_blocks)
		return;

	p = io_u->xfer_buf;
	boffset = io_u->offset;

	for (i = 0; i < nr_blocks; i++) {
		/*
		 * Fill the byte offset into a "random" start offset of
		 * the buffer, given by the product of the usec time
		 * and the actual offset.
		 */
		offset = (io_u->start_time.tv_usec ^ boffset) & 511;
		offset &= ~(sizeof(unsigned long long) - 1);
		if (offset >= 512 - sizeof(unsigned long long))
			offset -= sizeof(unsigned long long);
		memcpy(p + offset, &boffset, sizeof(boffset));

		end = p + 512 - sizeof(io_u->start_time);
		memcpy(end, &io_u->start_time, sizeof(io_u->start_time));
		p += 512;
		boffset += 512;
	}
}

/*
 * Return an io_u to be processed. Gets a buflen and offset, sets direction,
 * etc. The returned io_u is fully ready to be prepped and submitted.
 */
struct io_u *get_io_u(struct thread_data *td)
{
	struct fio_file *f;
	struct io_u *io_u;
	int do_scramble = 0;

	io_u = __get_io_u(td);
	if (!io_u) {
		dprint(FD_IO, "__get_io_u failed\n");
		return NULL;
	}

	if (check_get_verify(td, io_u))
		goto out;
	if (check_get_trim(td, io_u))
		goto out;

	/*
	 * from a requeue, io_u already setup
	 */
	if (io_u->file)
		goto out;

	/*
	 * If using an iolog, grab next piece if any available.
	 */
	if (td->o.read_iolog_file) {
		if (read_iolog_get(td, io_u))
			goto err_put;
	} else if (set_io_u_file(td, io_u)) {
		dprint(FD_IO, "io_u %p, setting file failed\n", io_u);
		goto err_put;
	}

	f = io_u->file;
	assert(fio_file_open(f));

	if (ddir_rw(io_u->ddir)) {
		if (!io_u->buflen && !(td->io_ops->flags & FIO_NOIO)) {
			dprint(FD_IO, "get_io_u: zero buflen on %p\n", io_u);
			goto err_put;
		}

		f->last_start = io_u->offset;
		f->last_pos = io_u->offset + io_u->buflen;

		if (io_u->ddir == DDIR_WRITE) {
			if (td->o.verify != VERIFY_NONE)
				populate_verify_io_u(td, io_u);
			else if (td->o.refill_buffers)
				io_u_fill_buffer(td, io_u, io_u->xfer_buflen);
			else if (td->o.scramble_buffers)
				do_scramble = 1;
		} else if (io_u->ddir == DDIR_READ) {
			/*
			 * Reset the buf_filled parameters so next time if the
			 * buffer is used for writes it is refilled.
			 */
			io_u->buf_filled_len = 0;
		}
	}

	/*
	 * Set io data pointers.
	 */
	io_u->xfer_buf = io_u->buf;
	io_u->xfer_buflen = io_u->buflen;

out:
	assert(io_u->file);
	if (!td_io_prep(td, io_u)) {
		if (!td->o.disable_slat)
			fio_gettime(&io_u->start_time, NULL);
		if (do_scramble)
			small_content_scramble(io_u);
		return io_u;
	}
err_put:
	dprint(FD_IO, "get_io_u failed\n");
	put_io_u(td, io_u);
	return NULL;
}

void io_u_log_error(struct thread_data *td, struct io_u *io_u)
{
	const char *msg[] = { "read", "write", "sync", "datasync",
				"sync_file_range", "wait", "trim" };



	log_err("fio: io_u error");

	if (io_u->file)
		log_err(" on file %s", io_u->file->file_name);

	log_err(": %s\n", strerror(io_u->error));

	log_err("     %s offset=%llu, buflen=%lu\n", msg[io_u->ddir],
					io_u->offset, io_u->xfer_buflen);

	if (!td->error)
		td_verror(td, io_u->error, "io_u error");
}

static void account_io_completion(struct thread_data *td, struct io_u *io_u,
				  struct io_completion_data *icd,
				  const enum fio_ddir idx, unsigned int bytes)
{
	unsigned long uninitialized_var(lusec);

	if (!icd->account)
		return;

	if (!td->o.disable_clat || !td->o.disable_bw)
		lusec = utime_since(&io_u->issue_time, &icd->time);

	if (!td->o.disable_lat) {
		unsigned long tusec;

		tusec = utime_since(&io_u->start_time, &icd->time);
		add_lat_sample(td, idx, tusec, bytes);
	}

	if (!td->o.disable_clat) {
		add_clat_sample(td, idx, lusec, bytes);
		io_u_mark_latency(td, lusec);
	}

	if (!td->o.disable_bw)
		add_bw_sample(td, idx, bytes, &icd->time);

	add_iops_sample(td, idx, &icd->time);
}

static long long usec_for_io(struct thread_data *td, enum fio_ddir ddir)
{
	unsigned long long secs, remainder, bps, bytes;
	bytes = td->this_io_bytes[ddir];
	bps = td->rate_bps[ddir];
	secs = bytes / bps;
	remainder = bytes % bps;
	return remainder * 1000000 / bps + secs * 1000000;
}

static void io_completed(struct thread_data *td, struct io_u *io_u,
			 struct io_completion_data *icd)
{
	/*
	 * Older gcc's are too dumb to realize that usec is always used
	 * initialized, silence that warning.
	 */
	unsigned long uninitialized_var(usec);
	struct fio_file *f;

	dprint_io_u(io_u, "io complete");

	td_io_u_lock(td);
	assert(io_u->flags & IO_U_F_FLIGHT);
	io_u->flags &= ~(IO_U_F_FLIGHT | IO_U_F_BUSY_OK);
	td_io_u_unlock(td);

	if (ddir_sync(io_u->ddir)) {
		td->last_was_sync = 1;
		f = io_u->file;
		if (f) {
			f->first_write = -1ULL;
			f->last_write = -1ULL;
		}
		return;
	}

	td->last_was_sync = 0;
	td->last_ddir = io_u->ddir;

	if (!io_u->error && ddir_rw(io_u->ddir)) {
		unsigned int bytes = io_u->buflen - io_u->resid;
		const enum fio_ddir idx = io_u->ddir;
		const enum fio_ddir odx = io_u->ddir ^ 1;
		int ret;

		td->io_blocks[idx]++;
		td->this_io_blocks[idx]++;
		td->io_bytes[idx] += bytes;
		td->this_io_bytes[idx] += bytes;

		if (idx == DDIR_WRITE) {
			f = io_u->file;
			if (f) {
				if (f->first_write == -1ULL ||
				    io_u->offset < f->first_write)
					f->first_write = io_u->offset;
				if (f->last_write == -1ULL ||
				    ((io_u->offset + bytes) > f->last_write))
					f->last_write = io_u->offset + bytes;
			}
		}

		if (ramp_time_over(td) && td->runstate == TD_RUNNING) {
			account_io_completion(td, io_u, icd, idx, bytes);

			if (__should_check_rate(td, idx)) {
				td->rate_pending_usleep[idx] =
					(usec_for_io(td, idx) -
					 utime_since_now(&td->start));
			}
			if (__should_check_rate(td, odx))
				td->rate_pending_usleep[odx] =
					(usec_for_io(td, odx) -
					 utime_since_now(&td->start));
		}

		if (td_write(td) && idx == DDIR_WRITE &&
		    td->o.do_verify &&
		    td->o.verify != VERIFY_NONE)
			log_io_piece(td, io_u);

		icd->bytes_done[idx] += bytes;

		if (io_u->end_io) {
			ret = io_u->end_io(td, io_u);
			if (ret && !icd->error)
				icd->error = ret;
		}
	} else if (io_u->error) {
		icd->error = io_u->error;
		io_u_log_error(td, io_u);
	}
	if (icd->error && td_non_fatal_error(icd->error) &&
           (td->o.continue_on_error & td_error_type(io_u->ddir, icd->error))) {
		/*
		 * If there is a non_fatal error, then add to the error count
		 * and clear all the errors.
		 */
		update_error_count(td, icd->error);
		td_clear_error(td);
		icd->error = 0;
		io_u->error = 0;
	}
}

static void init_icd(struct thread_data *td, struct io_completion_data *icd,
		     int nr)
{
	if (!td->o.disable_clat || !td->o.disable_bw)
		fio_gettime(&icd->time, NULL);

	icd->nr = nr;
	icd->account = 1;

	icd->error = 0;
	icd->bytes_done[0] = icd->bytes_done[1] = 0;
}

static void ios_completed(struct thread_data *td,
			  struct io_completion_data *icd)
{
	struct io_u *io_u;
	int i;

	for (i = 0; i < icd->nr; i++) {
		io_u = td->io_ops->event(td, i);

		io_completed(td, io_u, icd);

		if (!(io_u->flags & IO_U_F_FREE_DEF))
			put_io_u(td, io_u);

		icd->account = 0;
	}
}

/*
 * Complete a single io_u for the sync engines.
 */
int io_u_sync_complete(struct thread_data *td, struct io_u *io_u,
		       unsigned long *bytes)
{
	struct io_completion_data icd;

	init_icd(td, &icd, 1);
	io_completed(td, io_u, &icd);

	if (!(io_u->flags & IO_U_F_FREE_DEF))
		put_io_u(td, io_u);

	if (icd.error) {
		td_verror(td, icd.error, "io_u_sync_complete");
		return -1;
	}

	if (bytes) {
		bytes[0] += icd.bytes_done[0];
		bytes[1] += icd.bytes_done[1];
	}

	return 0;
}

/*
 * Called to complete min_events number of io for the async engines.
 */
int io_u_queued_complete(struct thread_data *td, int min_evts,
			 unsigned long *bytes)
{
	struct io_completion_data icd;
	struct timespec *tvp = NULL;
	int ret;
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 0, };

	dprint(FD_IO, "io_u_queued_completed: min=%d\n", min_evts);

	if (!min_evts)
		tvp = &ts;

	ret = td_io_getevents(td, min_evts, td->o.iodepth_batch_complete, tvp);
	if (ret < 0) {
		td_verror(td, -ret, "td_io_getevents");
		return ret;
	} else if (!ret)
		return ret;

	init_icd(td, &icd, ret);
	ios_completed(td, &icd);
	if (icd.error) {
		td_verror(td, icd.error, "io_u_queued_complete");
		return -1;
	}

	if (bytes) {
		bytes[0] += icd.bytes_done[0];
		bytes[1] += icd.bytes_done[1];
	}

	return 0;
}

/*
 * Call when io_u is really queued, to update the submission latency.
 */
void io_u_queued(struct thread_data *td, struct io_u *io_u)
{
	if (!td->o.disable_slat) {
		unsigned long slat_time;

		slat_time = utime_since(&io_u->start_time, &io_u->issue_time);
		add_slat_sample(td, io_u->ddir, slat_time, io_u->xfer_buflen);
	}
}

/*
 * "randomly" fill the buffer contents
 */
void io_u_fill_buffer(struct thread_data *td, struct io_u *io_u,
		      unsigned int max_bs)
{
	io_u->buf_filled_len = 0;

	if (!td->o.zero_buffers)
		fill_random_buf(&td->buf_state, io_u->buf, max_bs);
	else
		memset(io_u->buf, 0, max_bs);
}
