#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <assert.h>

#include "fio.h"
#include "os.h"

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
 * Mark a given offset as used in the map.
 */
static void mark_random_map(struct thread_data *td, struct fio_file *f,
			    struct io_u *io_u)
{
	unsigned int min_bs = td->min_bs[io_u->ddir];
	unsigned long long block;
	unsigned int blocks;

	block = io_u->offset / (unsigned long long) min_bs;
	blocks = 0;
	while (blocks < (io_u->buflen / min_bs)) {
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

	if ((blocks * min_bs) < io_u->buflen)
		io_u->buflen = blocks * min_bs;
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
	while ((*b) * td->rw_min_bs < f->real_file_size) {
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
 * For random io, generate a random new block and see if it's used. Repeat
 * until we find a free one. For sequential io, just return the end of
 * the last io issued.
 */
static int get_next_offset(struct thread_data *td, struct fio_file *f,
			   unsigned long long *offset, int ddir)
{
	unsigned long long b, rb;
	long r;

	if (!td->sequential) {
		unsigned long long max_blocks = f->file_size / td->min_bs[ddir];
		int loops = 50;

		do {
			r = os_random_long(&td->random_state);
			b = ((max_blocks - 1) * r / (unsigned long long) (RAND_MAX+1.0));
			if (td->norandommap)
				break;
			rb = b + (f->file_offset / td->min_bs[ddir]);
			loops--;
		} while (!random_map_free(td, f, rb) && loops);

		if (!loops) {
			if (get_next_free_block(td, f, &b))
				return 1;
		}
	} else
		b = f->last_pos / td->min_bs[ddir];

	*offset = (b * td->min_bs[ddir]) + f->file_offset;
	if (*offset > f->real_file_size)
		return 1;

	return 0;
}

static unsigned int get_next_buflen(struct thread_data *td, int ddir)
{
	unsigned int buflen;
	long r;

	if (td->min_bs[ddir] == td->max_bs[ddir])
		buflen = td->min_bs[ddir];
	else {
		r = os_random_long(&td->bsrange_state);
		buflen = (unsigned int) (1 + (double) (td->max_bs[ddir] - 1) * r / (RAND_MAX + 1.0));
		if (!td->bs_unaligned)
			buflen = (buflen + td->min_bs[ddir] - 1) & ~(td->min_bs[ddir] - 1);
	}

	if (buflen > td->io_size - td->this_io_bytes[ddir]) {
		/*
		 * if using direct/raw io, we may not be able to
		 * shrink the size. so just fail it.
		 */
		if (td->io_ops->flags & FIO_RAWIO)
			return 0;

		buflen = td->io_size - td->this_io_bytes[ddir];
	}

	return buflen;
}

/*
 * Return the data direction for the next io_u. If the job is a
 * mixed read/write workload, check the rwmix cycle and switch if
 * necessary.
 */
static enum fio_ddir get_rw_ddir(struct thread_data *td)
{
	if (td_rw(td)) {
		struct timeval now;
		unsigned long elapsed;

		fio_gettime(&now, NULL);
	 	elapsed = mtime_since_now(&td->rwmix_switch);

		/*
		 * Check if it's time to seed a new data direction.
		 */
		if (elapsed >= td->rwmixcycle) {
			unsigned int v;
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
	 * see if it's time to sync
	 */
	if (td->fsync_blocks && !(td->io_blocks[DDIR_WRITE] % td->fsync_blocks)
	    && should_fsync(td)) {
		io_u->ddir = DDIR_SYNC;
		io_u->file = f;
		return 0;
	}

	io_u->ddir = get_rw_ddir(td);

	/*
	 * No log, let the seq/rand engine retrieve the next position.
	 */
	if (!get_next_offset(td, f, &io_u->offset, io_u->ddir)) {
		io_u->buflen = get_next_buflen(td, io_u->ddir);
		if (io_u->buflen) {
			/*
			 * If using a write iolog, store this entry.
			 */
			if (td->write_iolog_file)
				write_iolog_put(td, io_u);

			io_u->file = f;
			return 0;
		}
	}

	return 1;
}

struct io_u *__get_io_u(struct thread_data *td)
{
	struct io_u *io_u = NULL;

	if (!queue_full(td)) {
		io_u = list_entry(td->io_u_freelist.next, struct io_u, list);

		io_u->buflen = 0;
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
struct io_u *get_io_u(struct thread_data *td, struct fio_file *f)
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

	if (io_u->buflen + io_u->offset > f->real_file_size) {
		if (td->io_ops->flags & FIO_RAWIO) {
			put_io_u(td, io_u);
			return NULL;
		}

		io_u->buflen = f->real_file_size - io_u->offset;
	}

	if (io_u->ddir != DDIR_SYNC) {
		if (!io_u->buflen) {
			put_io_u(td, io_u);
			return NULL;
		}

		if (!td->read_iolog && !td->sequential && !td->norandommap)
			mark_random_map(td, f, io_u);

		f->last_pos += io_u->buflen;

		if (td->verify != VERIFY_NONE)
			populate_verify_io_u(td, io_u);
	}

	if (td_io_prep(td, io_u)) {
		put_io_u(td, io_u);
		return NULL;
	}

	fio_gettime(&io_u->start_time, NULL);
	return io_u;
}

void io_completed(struct thread_data *td, struct io_u *io_u,
		  struct io_completion_data *icd)
{
	unsigned long msec;

	if (io_u->ddir == DDIR_SYNC) {
		td->last_was_sync = 1;
		return;
	}

	td->last_was_sync = 0;

	if (!io_u->error) {
		unsigned int bytes = io_u->buflen - io_u->resid;
		const enum fio_ddir idx = io_u->ddir;

		td->io_blocks[idx]++;
		td->io_bytes[idx] += bytes;
		td->zone_bytes += bytes;
		td->this_io_bytes[idx] += bytes;

		io_u->file->last_completed_pos = io_u->offset + io_u->buflen;

		msec = mtime_since(&io_u->issue_time, &icd->time);

		add_clat_sample(td, idx, msec);
		add_bw_sample(td, idx, &icd->time);

		if ((td_rw(td) || td_write(td)) && idx == DDIR_WRITE)
			log_io_piece(td, io_u);

		icd->bytes_done[idx] += bytes;
	} else
		icd->error = io_u->error;
}

void ios_completed(struct thread_data *td, struct io_completion_data *icd)
{
	struct io_u *io_u;
	int i;

	fio_gettime(&icd->time, NULL);

	icd->error = 0;
	icd->bytes_done[0] = icd->bytes_done[1] = 0;

	for (i = 0; i < icd->nr; i++) {
		io_u = td->io_ops->event(td, i);

		io_completed(td, io_u, icd);
		put_io_u(td, io_u);
	}
}


