#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <assert.h>

#include "fio.h"
#include "hash.h"

struct io_completion_data {
	int nr;				/* input */

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

	return (f->file_map[idx] & (1 << bit)) == 0;
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

	block = (io_u->offset - f->file_offset) / (unsigned long long) min_bs;
	nr_blocks = (io_u->buflen + min_bs - 1) / min_bs;
	blocks = 0;

	while (nr_blocks) {
		unsigned int this_blocks, mask;
		unsigned int idx, bit;

		/*
		 * If we have a mixed random workload, we may
		 * encounter blocks we already did IO to.
		 */
		if ((td->o.ddir_nr == 1) && !random_map_free(f, block)) {
			if (!blocks)
				blocks = 1;
			break;
		}

		idx = RAND_MAP_IDX(f, block);
		bit = RAND_MAP_BIT(f, block);

		fio_assert(td, idx < f->num_maps);

		this_blocks = nr_blocks;
		if (this_blocks + bit > BLOCKS_PER_MAP)
			this_blocks = BLOCKS_PER_MAP - bit;

		if (this_blocks == BLOCKS_PER_MAP)
			mask = -1U;
		else
			mask = ((1U << this_blocks) - 1) << bit;

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

	/*
	 * Hmm, should we make sure that ->io_size <= ->real_file_size?
	 */
	max_size = f->io_size;
	if (max_size > f->real_file_size)
		max_size = f->real_file_size;

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
	unsigned long long min_bs = td->o.rw_min_bs;
	int i;

	i = f->last_free_lookup;
	*b = (i * BLOCKS_PER_MAP);
	while ((*b) * min_bs < f->real_file_size &&
		(*b) * min_bs < f->io_size) {
		if (f->file_map[i] != (unsigned int) -1) {
			*b += ffz(f->file_map[i]);
			if (*b > last_block(td, f, ddir))
				break;
			f->last_free_lookup = i;
			return 0;
		}

		*b += BLOCKS_PER_MAP;
		i++;
	}

	dprint(FD_IO, "failed finding a free block\n");
	return 1;
}

static int get_next_rand_offset(struct thread_data *td, struct fio_file *f,
				enum fio_ddir ddir, unsigned long long *b)
{
	unsigned long long r;
	int loops = 5;

	do {
		r = os_random_long(&td->random_state);
		dprint(FD_RANDOM, "off rand %llu\n", r);
		*b = (last_block(td, f, ddir) - 1)
			* (r / ((unsigned long long) OS_RAND_MAX + 1.0));

		/*
		 * if we are not maintaining a random map, we are done.
		 */
		if (!file_randommap(td, f))
			return 0;

		/*
		 * calculate map offset and check if it's free
		 */
		if (random_map_free(f, *b))
			return 0;

		dprint(FD_RANDOM, "get_next_rand_offset: offset %llu busy\n",
									*b);
	} while (--loops);

	/*
	 * we get here, if we didn't suceed in looking up a block. generate
	 * a random start offset into the filemap, and find the first free
	 * block from there.
	 */
	loops = 10;
	do {
		f->last_free_lookup = (f->num_maps - 1) *
					(r / (OS_RAND_MAX + 1.0));
		if (!get_next_free_block(td, f, ddir, b))
			return 0;

		r = os_random_long(&td->random_state);
	} while (--loops);

	/*
	 * that didn't work either, try exhaustive search from the start
	 */
	f->last_free_lookup = 0;
	return get_next_free_block(td, f, ddir, b);
}

/*
 * For random io, generate a random new block and see if it's used. Repeat
 * until we find a free one. For sequential io, just return the end of
 * the last io issued.
 */
static int get_next_offset(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	unsigned long long b;
	enum fio_ddir ddir = io_u->ddir;

	if (td_random(td) && (td->o.ddir_nr && !--td->ddir_nr)) {
		td->ddir_nr = td->o.ddir_nr;

		if (get_next_rand_offset(td, f, ddir, &b)) {
			dprint(FD_IO, "%s: getting rand offset failed\n",
				f->file_name);
			return 1;
		}
	} else {
		if (f->last_pos >= f->real_file_size) {
			if (!td_random(td) ||
			     get_next_rand_offset(td, f, ddir, &b)) {
				dprint(FD_IO, "%s: pos %llu > size %llu\n",
						f->file_name, f->last_pos,
						f->real_file_size);
				return 1;
			}
		} else
			b = (f->last_pos - f->file_offset) / td->o.min_bs[ddir];
	}

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

static inline int is_power_of_2(unsigned int val)
{
	return (val != 0 && ((val & (val - 1)) == 0));
}

static unsigned int get_next_buflen(struct thread_data *td, struct io_u *io_u)
{
	const int ddir = io_u->ddir;
	unsigned int uninitialized_var(buflen);
	unsigned int minbs, maxbs;
	long r;

	minbs = td->o.min_bs[ddir];
	maxbs = td->o.max_bs[ddir];

	if (minbs == maxbs)
		buflen = minbs;
	else {
		r = os_random_long(&td->bsrange_state);
		if (!td->o.bssplit_nr[ddir]) {
			buflen = 1 + (unsigned int) ((double) maxbs *
					(r / (OS_RAND_MAX + 1.0)));
			if (buflen < minbs)
				buflen = minbs;
		} else {
			long perc = 0;
			unsigned int i;

			for (i = 0; i < td->o.bssplit_nr[ddir]; i++) {
				struct bssplit *bsp = &td->o.bssplit[ddir][i];

				buflen = bsp->bs;
				perc += bsp->perc;
				if (r <= ((OS_RAND_MAX / 100L) * perc))
					break;
			}
		}
		if (!td->o.bs_unaligned && is_power_of_2(minbs))
			buflen = (buflen + minbs - 1) & ~(minbs - 1);
	}

	if (io_u->offset + buflen > io_u->file->real_file_size) {
		dprint(FD_IO, "lower buflen %u -> %u (ddir=%d)\n", buflen,
						minbs, ddir);
		buflen = minbs;
	}

	return buflen;
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
	long r;

	r = os_random_long(&td->rwmix_state);
	v = 1 + (int) (100.0 * (r / (OS_RAND_MAX + 1.0)));
	if (v <= td->o.rwmix[DDIR_READ])
		return DDIR_READ;

	return DDIR_WRITE;
}

/*
 * Return the data direction for the next io_u. If the job is a
 * mixed read/write workload, check the rwmix cycle and switch if
 * necessary.
 */
static enum fio_ddir get_rw_ddir(struct thread_data *td)
{
	if (td_rw(td)) {
		/*
		 * Check if it's time to seed a new data direction.
		 */
		if (td->io_issues[td->rwmix_ddir] >= td->rwmix_issues) {
			unsigned long long max_bytes;
			enum fio_ddir ddir;

			/*
			 * Put a top limit on how many bytes we do for
			 * one data direction, to avoid overflowing the
			 * ranges too much
			 */
			ddir = get_rand_ddir(td);
			max_bytes = td->this_io_bytes[ddir];
			if (max_bytes >=
			    (td->o.size * td->o.rwmix[ddir] / 100)) {
				if (!td->rw_end_set[ddir]) {
					td->rw_end_set[ddir] = 1;
					fio_gettime(&td->rw_end[ddir], NULL);
				}

				ddir ^= 1;
			}

			if (ddir != td->rwmix_ddir)
				set_rwmix_bytes(td);

			td->rwmix_ddir = ddir;
		}
		return td->rwmix_ddir;
	} else if (td_read(td))
		return DDIR_READ;
	else
		return DDIR_WRITE;
}

static void put_file_log(struct thread_data *td, struct fio_file *f)
{
	int ret = put_file(td, f);

	if (ret)
		td_verror(td, ret, "file close");
}

void put_io_u(struct thread_data *td, struct io_u *io_u)
{
	assert((io_u->flags & IO_U_F_FREE) == 0);
	io_u->flags |= IO_U_F_FREE;

	if (io_u->file)
		put_file_log(td, io_u->file);

	io_u->file = NULL;
	flist_del(&io_u->list);
	flist_add(&io_u->list, &td->io_u_freelist);
	td->cur_depth--;
}

void requeue_io_u(struct thread_data *td, struct io_u **io_u)
{
	struct io_u *__io_u = *io_u;

	dprint(FD_IO, "requeue %p\n", __io_u);

	__io_u->flags |= IO_U_F_FREE;
	if ((__io_u->flags & IO_U_F_FLIGHT) && (__io_u->ddir != DDIR_SYNC))
		td->io_issues[__io_u->ddir]--;

	__io_u->flags &= ~IO_U_F_FLIGHT;

	flist_del(&__io_u->list);
	flist_add_tail(&__io_u->list, &td->io_u_requeues);
	td->cur_depth--;
	*io_u = NULL;
}

static int fill_io_u(struct thread_data *td, struct io_u *io_u)
{
	if (td->io_ops->flags & FIO_NOIO)
		goto out;

	/*
	 * see if it's time to sync
	 */
	if (td->o.fsync_blocks &&
	   !(td->io_issues[DDIR_WRITE] % td->o.fsync_blocks) &&
	     td->io_issues[DDIR_WRITE] && should_fsync(td)) {
		io_u->ddir = DDIR_SYNC;
		goto out;
	}

	io_u->ddir = get_rw_ddir(td);

	/*
	 * See if it's time to switch to a new zone
	 */
	if (td->zone_bytes >= td->o.zone_size) {
		td->zone_bytes = 0;
		io_u->file->last_pos += td->o.zone_skip;
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
	int index = 0;

	switch (nr) {
	default:
		index = 6;
		break;
	case 33 ... 64:
		index = 5;
		break;
	case 17 ... 32:
		index = 4;
		break;
	case 9 ... 16:
		index = 3;
		break;
	case 5 ... 8:
		index = 2;
		break;
	case 1 ... 4:
		index = 1;
	case 0:
		break;
	}

	map[index]++;
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
	int index = 0;

	switch (td->cur_depth) {
	default:
		index = 6;
		break;
	case 32 ... 63:
		index = 5;
		break;
	case 16 ... 31:
		index = 4;
		break;
	case 8 ... 15:
		index = 3;
		break;
	case 4 ... 7:
		index = 2;
		break;
	case 2 ... 3:
		index = 1;
	case 1:
		break;
	}

	td->ts.io_u_map[index] += nr;
}

static void io_u_mark_lat_usec(struct thread_data *td, unsigned long usec)
{
	int index = 0;

	assert(usec < 1000);

	switch (usec) {
	case 750 ... 999:
		index = 9;
		break;
	case 500 ... 749:
		index = 8;
		break;
	case 250 ... 499:
		index = 7;
		break;
	case 100 ... 249:
		index = 6;
		break;
	case 50 ... 99:
		index = 5;
		break;
	case 20 ... 49:
		index = 4;
		break;
	case 10 ... 19:
		index = 3;
		break;
	case 4 ... 9:
		index = 2;
		break;
	case 2 ... 3:
		index = 1;
	case 0 ... 1:
		break;
	}

	assert(index < FIO_IO_U_LAT_U_NR);
	td->ts.io_u_lat_u[index]++;
}

static void io_u_mark_lat_msec(struct thread_data *td, unsigned long msec)
{
	int index = 0;

	switch (msec) {
	default:
		index = 11;
		break;
	case 1000 ... 1999:
		index = 10;
		break;
	case 750 ... 999:
		index = 9;
		break;
	case 500 ... 749:
		index = 8;
		break;
	case 250 ... 499:
		index = 7;
		break;
	case 100 ... 249:
		index = 6;
		break;
	case 50 ... 99:
		index = 5;
		break;
	case 20 ... 49:
		index = 4;
		break;
	case 10 ... 19:
		index = 3;
		break;
	case 4 ... 9:
		index = 2;
		break;
	case 2 ... 3:
		index = 1;
	case 0 ... 1:
		break;
	}

	assert(index < FIO_IO_U_LAT_M_NR);
	td->ts.io_u_lat_m[index]++;
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
static struct fio_file *get_next_file_rand(struct thread_data *td, int goodf,
					   int badf)
{
	struct fio_file *f;
	int fno;

	do {
		long r = os_random_long(&td->next_file_state);
		int opened = 0;

		fno = (unsigned int) ((double) td->o.nr_files
			* (r / (OS_RAND_MAX + 1.0)));
		f = td->files[fno];
		if (f->flags & FIO_FILE_DONE)
			continue;

		if (!(f->flags & FIO_FILE_OPEN)) {
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
		if (f->flags & FIO_FILE_DONE) {
			f = NULL;
			continue;
		}

		if (!(f->flags & FIO_FILE_OPEN)) {
			int err;

			err = td_io_open_file(td, f);
			if (err) {
				dprint(FD_FILE, "error %d on open of %s\n",
					err, f->file_name);
				continue;
			}
			opened = 1;
		}

		dprint(FD_FILE, "goodf=%x, badf=%x, ff=%x\n", goodf, badf, f->flags);
		if ((!goodf || (f->flags & goodf)) && !(f->flags & badf))
			break;

		if (opened)
			td_io_close_file(td, f);

		f = NULL;
	} while (td->next_file != old_next_file);

	dprint(FD_FILE, "get_next_file_rr: %p\n", f);
	return f;
}

static struct fio_file *get_next_file(struct thread_data *td)
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
	if (f && (f->flags & FIO_FILE_OPEN) && !(f->flags & FIO_FILE_CLOSING)) {
		if (td->o.file_service_type == FIO_FSERVICE_SEQ)
			goto out;
		if (td->file_service_left--)
			goto out;
	}

	if (td->o.file_service_type == FIO_FSERVICE_RR ||
	    td->o.file_service_type == FIO_FSERVICE_SEQ)
		f = get_next_file_rr(td, FIO_FILE_OPEN, FIO_FILE_CLOSING);
	else
		f = get_next_file_rand(td, FIO_FILE_OPEN, FIO_FILE_CLOSING);

	td->file_service_file = f;
	td->file_service_left = td->file_service_nr - 1;
out:
	dprint(FD_FILE, "get_next_file: %p [%s]\n", f, f->file_name);
	return f;
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
		f->flags |= FIO_FILE_DONE;
		td->nr_done_files++;
		dprint(FD_FILE, "%s: is done (%d of %d)\n", f->file_name, td->nr_done_files, td->o.nr_files);
	} while (1);

	return 0;
}


struct io_u *__get_io_u(struct thread_data *td)
{
	struct io_u *io_u = NULL;

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
		io_u->flags &= ~IO_U_F_FREE;

		io_u->error = 0;
		flist_del(&io_u->list);
		flist_add(&io_u->list, &td->io_u_busylist);
		td->cur_depth++;
	}

	return io_u;
}

/*
 * Return an io_u to be processed. Gets a buflen and offset, sets direction,
 * etc. The returned io_u is fully ready to be prepped and submitted.
 */
struct io_u *get_io_u(struct thread_data *td)
{
	struct fio_file *f;
	struct io_u *io_u;

	io_u = __get_io_u(td);
	if (!io_u) {
		dprint(FD_IO, "__get_io_u failed\n");
		return NULL;
	}

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
	assert(f->flags & FIO_FILE_OPEN);

	if (io_u->ddir != DDIR_SYNC) {
		if (!io_u->buflen && !(td->io_ops->flags & FIO_NOIO)) {
			dprint(FD_IO, "get_io_u: zero buflen on %p\n", io_u);
			goto err_put;
		}

		f->last_pos = io_u->offset + io_u->buflen;

		if (td->o.verify != VERIFY_NONE && io_u->ddir == DDIR_WRITE)
			populate_verify_io_u(td, io_u);
		else if (td->o.refill_buffers && io_u->ddir == DDIR_WRITE)
			io_u_fill_buffer(td, io_u, io_u->xfer_buflen);
	}

	/*
	 * Set io data pointers.
	 */
	io_u->endpos = io_u->offset + io_u->buflen;
	io_u->xfer_buf = io_u->buf;
	io_u->xfer_buflen = io_u->buflen;

out:
	if (!td_io_prep(td, io_u)) {
		if (!td->o.disable_slat)
			fio_gettime(&io_u->start_time, NULL);
		return io_u;
	}
err_put:
	dprint(FD_IO, "get_io_u failed\n");
	put_io_u(td, io_u);
	return NULL;
}

void io_u_log_error(struct thread_data *td, struct io_u *io_u)
{
	const char *msg[] = { "read", "write", "sync" };

	log_err("fio: io_u error");

	if (io_u->file)
		log_err(" on file %s", io_u->file->file_name);

	log_err(": %s\n", strerror(io_u->error));

	log_err("     %s offset=%llu, buflen=%lu\n", msg[io_u->ddir],
					io_u->offset, io_u->xfer_buflen);

	if (!td->error)
		td_verror(td, io_u->error, "io_u error");
}

static void io_completed(struct thread_data *td, struct io_u *io_u,
			 struct io_completion_data *icd)
{
	/*
	 * Older gcc's are too dumb to realize that usec is always used
	 * initialized, silence that warning.
	 */
	unsigned long uninitialized_var(usec);

	dprint_io_u(io_u, "io complete");

	assert(io_u->flags & IO_U_F_FLIGHT);
	io_u->flags &= ~IO_U_F_FLIGHT;

	if (io_u->ddir == DDIR_SYNC) {
		td->last_was_sync = 1;
		return;
	}

	td->last_was_sync = 0;

	if (!io_u->error) {
		unsigned int bytes = io_u->buflen - io_u->resid;
		const enum fio_ddir idx = io_u->ddir;
		int ret;

		td->io_blocks[idx]++;
		td->io_bytes[idx] += bytes;
		td->this_io_bytes[idx] += bytes;

		if (ramp_time_over(td)) {
			if (!td->o.disable_clat || !td->o.disable_bw)
				usec = utime_since(&io_u->issue_time,
							&icd->time);

			if (!td->o.disable_clat) {
				add_clat_sample(td, idx, usec, bytes);
				io_u_mark_latency(td, usec);
			}
			if (!td->o.disable_bw)
				add_bw_sample(td, idx, bytes, &icd->time);
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
	} else {
		icd->error = io_u->error;
		io_u_log_error(td, io_u);
	}
}

static void init_icd(struct thread_data *td, struct io_completion_data *icd,
		     int nr)
{
	if (!td->o.disable_clat || !td->o.disable_bw)
		fio_gettime(&icd->time, NULL);

	icd->nr = nr;

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
		put_io_u(td, io_u);
	}
}

/*
 * Complete a single io_u for the sync engines.
 */
long io_u_sync_complete(struct thread_data *td, struct io_u *io_u)
{
	struct io_completion_data icd;

	init_icd(td, &icd, 1);
	io_completed(td, io_u, &icd);
	put_io_u(td, io_u);

	if (!icd.error)
		return icd.bytes_done[0] + icd.bytes_done[1];

	td_verror(td, icd.error, "io_u_sync_complete");
	return -1;
}

/*
 * Called to complete min_events number of io for the async engines.
 */
long io_u_queued_complete(struct thread_data *td, int min_evts)
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
	if (!icd.error)
		return icd.bytes_done[0] + icd.bytes_done[1];

	td_verror(td, icd.error, "io_u_queued_complete");
	return -1;
}

/*
 * Call when io_u is really queued, to update the submission latency.
 */
void io_u_queued(struct thread_data *td, struct io_u *io_u)
{
	if (!td->o.disable_slat) {
		unsigned long slat_time;

		slat_time = utime_since(&io_u->start_time, &io_u->issue_time);
		add_slat_sample(td, io_u->ddir, io_u->xfer_buflen, slat_time);
	}
}

/*
 * "randomly" fill the buffer contents
 */
void io_u_fill_buffer(struct thread_data *td, struct io_u *io_u,
		      unsigned int max_bs)
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
