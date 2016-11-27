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
#include "lib/axmap.h"
#include "err.h"
#include "lib/pow2.h"
#include "minmax.h"

struct io_completion_data {
	int nr;				/* input */

	int error;			/* output */
	uint64_t bytes_done[DDIR_RWDIR_CNT];	/* output */
	struct timeval time;		/* output */
};

/*
 * The ->io_axmap contains a map of blocks we have or have not done io
 * to yet. Used to make sure we cover the entire range in a fair fashion.
 */
static bool random_map_free(struct fio_file *f, const uint64_t block)
{
	return !axmap_isset(f->io_axmap, block);
}

/*
 * Mark a given offset as used in the map.
 */
static void mark_random_map(struct thread_data *td, struct io_u *io_u)
{
	unsigned int min_bs = td->o.rw_min_bs;
	struct fio_file *f = io_u->file;
	unsigned int nr_blocks;
	uint64_t block;

	block = (io_u->offset - f->file_offset) / (uint64_t) min_bs;
	nr_blocks = (io_u->buflen + min_bs - 1) / min_bs;

	if (!(io_u->flags & IO_U_F_BUSY_OK))
		nr_blocks = axmap_set_nr(f->io_axmap, block, nr_blocks);

	if ((nr_blocks * min_bs) < io_u->buflen)
		io_u->buflen = nr_blocks * min_bs;
}

static uint64_t last_block(struct thread_data *td, struct fio_file *f,
			   enum fio_ddir ddir)
{
	uint64_t max_blocks;
	uint64_t max_size;

	assert(ddir_rw(ddir));

	/*
	 * Hmm, should we make sure that ->io_size <= ->real_file_size?
	 */
	max_size = f->io_size;
	if (max_size > f->real_file_size)
		max_size = f->real_file_size;

	if (td->o.zone_range)
		max_size = td->o.zone_range;

	if (td->o.min_bs[ddir] > td->o.ba[ddir])
		max_size -= td->o.min_bs[ddir] - td->o.ba[ddir];

	max_blocks = max_size / (uint64_t) td->o.ba[ddir];
	if (!max_blocks)
		return 0;

	return max_blocks;
}

struct rand_off {
	struct flist_head list;
	uint64_t off;
};

static int __get_next_rand_offset(struct thread_data *td, struct fio_file *f,
				  enum fio_ddir ddir, uint64_t *b,
				  uint64_t lastb)
{
	uint64_t r;

	if (td->o.random_generator == FIO_RAND_GEN_TAUSWORTHE ||
	    td->o.random_generator == FIO_RAND_GEN_TAUSWORTHE64) {

		r = __rand(&td->random_state);

		dprint(FD_RANDOM, "off rand %llu\n", (unsigned long long) r);

		*b = lastb * (r / (rand_max(&td->random_state) + 1.0));
	} else {
		uint64_t off = 0;

		assert(fio_file_lfsr(f));

		if (lfsr_next(&f->lfsr, &off))
			return 1;

		*b = off;
	}

	/*
	 * if we are not maintaining a random map, we are done.
	 */
	if (!file_randommap(td, f))
		goto ret;

	/*
	 * calculate map offset and check if it's free
	 */
	if (random_map_free(f, *b))
		goto ret;

	dprint(FD_RANDOM, "get_next_rand_offset: offset %llu busy\n",
						(unsigned long long) *b);

	*b = axmap_next_free(f->io_axmap, *b);
	if (*b == (uint64_t) -1ULL)
		return 1;
ret:
	return 0;
}

static int __get_next_rand_offset_zipf(struct thread_data *td,
				       struct fio_file *f, enum fio_ddir ddir,
				       uint64_t *b)
{
	*b = zipf_next(&f->zipf);
	return 0;
}

static int __get_next_rand_offset_pareto(struct thread_data *td,
					 struct fio_file *f, enum fio_ddir ddir,
					 uint64_t *b)
{
	*b = pareto_next(&f->zipf);
	return 0;
}

static int __get_next_rand_offset_gauss(struct thread_data *td,
					struct fio_file *f, enum fio_ddir ddir,
					uint64_t *b)
{
	*b = gauss_next(&f->gauss);
	return 0;
}

static int __get_next_rand_offset_zoned(struct thread_data *td,
					struct fio_file *f, enum fio_ddir ddir,
					uint64_t *b)
{
	unsigned int v, send, stotal;
	uint64_t offset, lastb;
	static int warned;
	struct zone_split_index *zsi;

	lastb = last_block(td, f, ddir);
	if (!lastb)
		return 1;

	if (!td->o.zone_split_nr[ddir]) {
bail:
		return __get_next_rand_offset(td, f, ddir, b, lastb);
	}

	/*
	 * Generate a value, v, between 1 and 100, both inclusive
	 */
	v = rand32_between(&td->zone_state, 1, 100);

	zsi = &td->zone_state_index[ddir][v - 1];
	stotal = zsi->size_perc_prev;
	send = zsi->size_perc;

	/*
	 * Should never happen
	 */
	if (send == -1U) {
		if (!warned) {
			log_err("fio: bug in zoned generation\n");
			warned = 1;
		}
		goto bail;
	}

	/*
	 * 'send' is some percentage below or equal to 100 that
	 * marks the end of the current IO range. 'stotal' marks
	 * the start, in percent.
	 */
	if (stotal)
		offset = stotal * lastb / 100ULL;
	else
		offset = 0;

	lastb = lastb * (send - stotal) / 100ULL;

	/*
	 * Generate index from 0..send-of-lastb
	 */
	if (__get_next_rand_offset(td, f, ddir, b, lastb) == 1)
		return 1;

	/*
	 * Add our start offset, if any
	 */
	if (offset)
		*b += offset;

	return 0;
}

static int flist_cmp(void *data, struct flist_head *a, struct flist_head *b)
{
	struct rand_off *r1 = flist_entry(a, struct rand_off, list);
	struct rand_off *r2 = flist_entry(b, struct rand_off, list);

	return r1->off - r2->off;
}

static int get_off_from_method(struct thread_data *td, struct fio_file *f,
			       enum fio_ddir ddir, uint64_t *b)
{
	if (td->o.random_distribution == FIO_RAND_DIST_RANDOM) {
		uint64_t lastb;

		lastb = last_block(td, f, ddir);
		if (!lastb)
			return 1;

		return __get_next_rand_offset(td, f, ddir, b, lastb);
	} else if (td->o.random_distribution == FIO_RAND_DIST_ZIPF)
		return __get_next_rand_offset_zipf(td, f, ddir, b);
	else if (td->o.random_distribution == FIO_RAND_DIST_PARETO)
		return __get_next_rand_offset_pareto(td, f, ddir, b);
	else if (td->o.random_distribution == FIO_RAND_DIST_GAUSS)
		return __get_next_rand_offset_gauss(td, f, ddir, b);
	else if (td->o.random_distribution == FIO_RAND_DIST_ZONED)
		return __get_next_rand_offset_zoned(td, f, ddir, b);

	log_err("fio: unknown random distribution: %d\n", td->o.random_distribution);
	return 1;
}

/*
 * Sort the reads for a verify phase in batches of verifysort_nr, if
 * specified.
 */
static inline bool should_sort_io(struct thread_data *td)
{
	if (!td->o.verifysort_nr || !td->o.do_verify)
		return false;
	if (!td_random(td))
		return false;
	if (td->runstate != TD_VERIFYING)
		return false;
	if (td->o.random_generator == FIO_RAND_GEN_TAUSWORTHE ||
	    td->o.random_generator == FIO_RAND_GEN_TAUSWORTHE64)
		return false;

	return true;
}

static bool should_do_random(struct thread_data *td, enum fio_ddir ddir)
{
	unsigned int v;

	if (td->o.perc_rand[ddir] == 100)
		return true;

	v = rand32_between(&td->seq_rand_state[ddir], 1, 100);

	return v <= td->o.perc_rand[ddir];
}

static int get_next_rand_offset(struct thread_data *td, struct fio_file *f,
				enum fio_ddir ddir, uint64_t *b)
{
	struct rand_off *r;
	int i, ret = 1;

	if (!should_sort_io(td))
		return get_off_from_method(td, f, ddir, b);

	if (!flist_empty(&td->next_rand_list)) {
fetch:
		r = flist_first_entry(&td->next_rand_list, struct rand_off, list);
		flist_del(&r->list);
		*b = r->off;
		free(r);
		return 0;
	}

	for (i = 0; i < td->o.verifysort_nr; i++) {
		r = malloc(sizeof(*r));

		ret = get_off_from_method(td, f, ddir, &r->off);
		if (ret) {
			free(r);
			break;
		}

		flist_add(&r->list, &td->next_rand_list);
	}

	if (ret && !i)
		return ret;

	assert(!flist_empty(&td->next_rand_list));
	flist_sort(NULL, &td->next_rand_list, flist_cmp);
	goto fetch;
}

static int get_next_rand_block(struct thread_data *td, struct fio_file *f,
			       enum fio_ddir ddir, uint64_t *b)
{
	if (!get_next_rand_offset(td, f, ddir, b))
		return 0;

	if (td->o.time_based ||
	    (td->o.file_service_type & __FIO_FSERVICE_NONUNIFORM)) {
		fio_file_reset(td, f);
		if (!get_next_rand_offset(td, f, ddir, b))
			return 0;
	}

	dprint(FD_IO, "%s: rand offset failed, last=%llu, size=%llu\n",
			f->file_name, (unsigned long long) f->last_pos[ddir],
			(unsigned long long) f->real_file_size);
	return 1;
}

static int get_next_seq_offset(struct thread_data *td, struct fio_file *f,
			       enum fio_ddir ddir, uint64_t *offset)
{
	struct thread_options *o = &td->o;

	assert(ddir_rw(ddir));

	if (f->last_pos[ddir] >= f->io_size + get_start_offset(td, f) &&
	    o->time_based) {
		struct thread_options *o = &td->o;
		uint64_t io_size = f->io_size + (f->io_size % o->min_bs[ddir]);

		if (io_size > f->last_pos[ddir])
			f->last_pos[ddir] = 0;
		else
			f->last_pos[ddir] = f->last_pos[ddir] - io_size;
	}

	if (f->last_pos[ddir] < f->real_file_size) {
		uint64_t pos;

		if (f->last_pos[ddir] == f->file_offset && o->ddir_seq_add < 0) {
			if (f->real_file_size > f->io_size)
				f->last_pos[ddir] = f->io_size;
			else
				f->last_pos[ddir] = f->real_file_size;
		}

		pos = f->last_pos[ddir] - f->file_offset;
		if (pos && o->ddir_seq_add) {
			pos += o->ddir_seq_add;

			/*
			 * If we reach beyond the end of the file
			 * with holed IO, wrap around to the
			 * beginning again. If we're doing backwards IO,
			 * wrap to the end.
			 */
			if (pos >= f->real_file_size) {
				if (o->ddir_seq_add > 0)
					pos = f->file_offset;
				else {
					if (f->real_file_size > f->io_size)
						pos = f->io_size;
					else
						pos = f->real_file_size;

					pos += o->ddir_seq_add;
				}
			}
		}

		*offset = pos;
		return 0;
	}

	return 1;
}

static int get_next_block(struct thread_data *td, struct io_u *io_u,
			  enum fio_ddir ddir, int rw_seq,
			  unsigned int *is_random)
{
	struct fio_file *f = io_u->file;
	uint64_t b, offset;
	int ret;

	assert(ddir_rw(ddir));

	b = offset = -1ULL;

	if (rw_seq) {
		if (td_random(td)) {
			if (should_do_random(td, ddir)) {
				ret = get_next_rand_block(td, f, ddir, &b);
				*is_random = 1;
			} else {
				*is_random = 0;
				io_u_set(td, io_u, IO_U_F_BUSY_OK);
				ret = get_next_seq_offset(td, f, ddir, &offset);
				if (ret)
					ret = get_next_rand_block(td, f, ddir, &b);
			}
		} else {
			*is_random = 0;
			ret = get_next_seq_offset(td, f, ddir, &offset);
		}
	} else {
		io_u_set(td, io_u, IO_U_F_BUSY_OK);
		*is_random = 0;

		if (td->o.rw_seq == RW_SEQ_SEQ) {
			ret = get_next_seq_offset(td, f, ddir, &offset);
			if (ret) {
				ret = get_next_rand_block(td, f, ddir, &b);
				*is_random = 0;
			}
		} else if (td->o.rw_seq == RW_SEQ_IDENT) {
			if (f->last_start[ddir] != -1ULL)
				offset = f->last_start[ddir] - f->file_offset;
			else
				offset = 0;
			ret = 0;
		} else {
			log_err("fio: unknown rw_seq=%d\n", td->o.rw_seq);
			ret = 1;
		}
	}

	if (!ret) {
		if (offset != -1ULL)
			io_u->offset = offset;
		else if (b != -1ULL)
			io_u->offset = b * td->o.ba[ddir];
		else {
			log_err("fio: bug in offset generation: offset=%llu, b=%llu\n", (unsigned long long) offset, (unsigned long long) b);
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
static int __get_next_offset(struct thread_data *td, struct io_u *io_u,
			     unsigned int *is_random)
{
	struct fio_file *f = io_u->file;
	enum fio_ddir ddir = io_u->ddir;
	int rw_seq_hit = 0;

	assert(ddir_rw(ddir));

	if (td->o.ddir_seq_nr && !--td->ddir_seq_nr) {
		rw_seq_hit = 1;
		td->ddir_seq_nr = td->o.ddir_seq_nr;
	}

	if (get_next_block(td, io_u, ddir, rw_seq_hit, is_random))
		return 1;

	if (io_u->offset >= f->io_size) {
		dprint(FD_IO, "get_next_offset: offset %llu >= io_size %llu\n",
					(unsigned long long) io_u->offset,
					(unsigned long long) f->io_size);
		return 1;
	}

	io_u->offset += f->file_offset;
	if (io_u->offset >= f->real_file_size) {
		dprint(FD_IO, "get_next_offset: offset %llu >= size %llu\n",
					(unsigned long long) io_u->offset,
					(unsigned long long) f->real_file_size);
		return 1;
	}

	return 0;
}

static int get_next_offset(struct thread_data *td, struct io_u *io_u,
			   unsigned int *is_random)
{
	if (td->flags & TD_F_PROFILE_OPS) {
		struct prof_io_ops *ops = &td->prof_io_ops;

		if (ops->fill_io_u_off)
			return ops->fill_io_u_off(td, io_u, is_random);
	}

	return __get_next_offset(td, io_u, is_random);
}

static inline bool io_u_fits(struct thread_data *td, struct io_u *io_u,
			     unsigned int buflen)
{
	struct fio_file *f = io_u->file;

	return io_u->offset + buflen <= f->io_size + get_start_offset(td, f);
}

static unsigned int __get_next_buflen(struct thread_data *td, struct io_u *io_u,
				      unsigned int is_random)
{
	int ddir = io_u->ddir;
	unsigned int buflen = 0;
	unsigned int minbs, maxbs;
	uint64_t frand_max, r;

	assert(ddir_rw(ddir));

	if (td->o.bs_is_seq_rand)
		ddir = is_random ? DDIR_WRITE: DDIR_READ;

	minbs = td->o.min_bs[ddir];
	maxbs = td->o.max_bs[ddir];

	if (minbs == maxbs)
		return minbs;

	/*
	 * If we can't satisfy the min block size from here, then fail
	 */
	if (!io_u_fits(td, io_u, minbs))
		return 0;

	frand_max = rand_max(&td->bsrange_state);
	do {
		r = __rand(&td->bsrange_state);

		if (!td->o.bssplit_nr[ddir]) {
			buflen = 1 + (unsigned int) ((double) maxbs *
					(r / (frand_max + 1.0)));
			if (buflen < minbs)
				buflen = minbs;
		} else {
			long long perc = 0;
			unsigned int i;

			for (i = 0; i < td->o.bssplit_nr[ddir]; i++) {
				struct bssplit *bsp = &td->o.bssplit[ddir][i];

				buflen = bsp->bs;
				perc += bsp->perc;
				if (!perc)
					break;
				if ((r / perc <= frand_max / 100ULL) &&
				    io_u_fits(td, io_u, buflen))
					break;
			}
		}

		if (td->o.verify != VERIFY_NONE)
			buflen = (buflen + td->o.verify_interval - 1) &
				~(td->o.verify_interval - 1);

		if (!td->o.bs_unaligned && is_power_of_2(minbs))
			buflen &= ~(minbs - 1);

	} while (!io_u_fits(td, io_u, buflen));

	return buflen;
}

static unsigned int get_next_buflen(struct thread_data *td, struct io_u *io_u,
				    unsigned int is_random)
{
	if (td->flags & TD_F_PROFILE_OPS) {
		struct prof_io_ops *ops = &td->prof_io_ops;

		if (ops->fill_io_u_size)
			return ops->fill_io_u_size(td, io_u, is_random);
	}

	return __get_next_buflen(td, io_u, is_random);
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

	v = rand32_between(&td->rwmix_state, 1, 100);

	if (v <= td->o.rwmix[DDIR_READ])
		return DDIR_READ;

	return DDIR_WRITE;
}

int io_u_quiesce(struct thread_data *td)
{
	int completed = 0;

	/*
	 * We are going to sleep, ensure that we flush anything pending as
	 * not to skew our latency numbers.
	 *
	 * Changed to only monitor 'in flight' requests here instead of the
	 * td->cur_depth, b/c td->cur_depth does not accurately represent
	 * io's that have been actually submitted to an async engine,
	 * and cur_depth is meaningless for sync engines.
	 */
	if (td->io_u_queued || td->cur_depth) {
		int fio_unused ret;

		ret = td_io_commit(td);
	}

	while (td->io_u_in_flight) {
		int fio_unused ret;

		ret = io_u_queued_complete(td, 1);
		if (ret > 0)
			completed += ret;
	}

	return completed;
}

static enum fio_ddir rate_ddir(struct thread_data *td, enum fio_ddir ddir)
{
	enum fio_ddir odir = ddir ^ 1;
	long usec;
	uint64_t now;

	assert(ddir_rw(ddir));
	now = utime_since_now(&td->start);

	/*
	 * if rate_next_io_time is in the past, need to catch up to rate
	 */
	if (td->rate_next_io_time[ddir] <= now)
		return ddir;

	/*
	 * We are ahead of rate in this direction. See if we
	 * should switch.
	 */
	if (td_rw(td) && td->o.rwmix[odir]) {
		/*
		 * Other direction is behind rate, switch
		 */
		if (td->rate_next_io_time[odir] <= now)
			return odir;

		/*
		 * Both directions are ahead of rate. sleep the min
		 * switch if necissary
		 */
		if (td->rate_next_io_time[ddir] <=
			td->rate_next_io_time[odir]) {
			usec = td->rate_next_io_time[ddir] - now;
		} else {
			usec = td->rate_next_io_time[odir] - now;
			ddir = odir;
		}
	} else
		usec = td->rate_next_io_time[ddir] - now;

	if (td->o.io_submit_mode == IO_MODE_INLINE)
		io_u_quiesce(td);

	usec = usec_sleep(td, usec);

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
	else if (td_write(td))
		ddir = DDIR_WRITE;
	else
		ddir = DDIR_TRIM;

	td->rwmix_ddir = rate_ddir(td, ddir);
	return td->rwmix_ddir;
}

static void set_rw_ddir(struct thread_data *td, struct io_u *io_u)
{
	enum fio_ddir ddir = get_rw_ddir(td);

	if (td_trimwrite(td)) {
		struct fio_file *f = io_u->file;
		if (f->last_pos[DDIR_WRITE] == f->last_pos[DDIR_TRIM])
			ddir = DDIR_TRIM;
		else
			ddir = DDIR_WRITE;
	}

	io_u->ddir = io_u->acct_ddir = ddir;

	if (io_u->ddir == DDIR_WRITE && td_ioengine_flagged(td, FIO_BARRIER) &&
	    td->o.barrier_blocks &&
	   !(td->io_issues[DDIR_WRITE] % td->o.barrier_blocks) &&
	     td->io_issues[DDIR_WRITE])
		io_u_set(td, io_u, IO_U_F_BARRIER);
}

void put_file_log(struct thread_data *td, struct fio_file *f)
{
	unsigned int ret = put_file(td, f);

	if (ret)
		td_verror(td, ret, "file close");
}

void put_io_u(struct thread_data *td, struct io_u *io_u)
{
	if (td->parent)
		td = td->parent;

	td_io_u_lock(td);

	if (io_u->file && !(io_u->flags & IO_U_F_NO_FILE_PUT))
		put_file_log(td, io_u->file);

	io_u->file = NULL;
	io_u_set(td, io_u, IO_U_F_FREE);

	if (io_u->flags & IO_U_F_IN_CUR_DEPTH) {
		td->cur_depth--;
		assert(!(td->flags & TD_F_CHILD));
	}
	io_u_qpush(&td->io_u_freelist, io_u);
	td_io_u_unlock(td);
	td_io_u_free_notify(td);
}

void clear_io_u(struct thread_data *td, struct io_u *io_u)
{
	io_u_clear(td, io_u, IO_U_F_FLIGHT);
	put_io_u(td, io_u);
}

void requeue_io_u(struct thread_data *td, struct io_u **io_u)
{
	struct io_u *__io_u = *io_u;
	enum fio_ddir ddir = acct_ddir(__io_u);

	dprint(FD_IO, "requeue %p\n", __io_u);

	if (td->parent)
		td = td->parent;

	td_io_u_lock(td);

	io_u_set(td, __io_u, IO_U_F_FREE);
	if ((__io_u->flags & IO_U_F_FLIGHT) && ddir_rw(ddir))
		td->io_issues[ddir]--;

	io_u_clear(td, __io_u, IO_U_F_FLIGHT);
	if (__io_u->flags & IO_U_F_IN_CUR_DEPTH) {
		td->cur_depth--;
		assert(!(td->flags & TD_F_CHILD));
	}

	io_u_rpush(&td->io_u_requeues, __io_u);
	td_io_u_unlock(td);
	td_io_u_free_notify(td);
	*io_u = NULL;
}

static int fill_io_u(struct thread_data *td, struct io_u *io_u)
{
	unsigned int is_random;

	if (td_ioengine_flagged(td, FIO_NOIO))
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
	if (td->zone_bytes >= td->o.zone_size && td->o.zone_skip) {
		struct fio_file *f = io_u->file;

		td->zone_bytes = 0;
		f->file_offset += td->o.zone_range + td->o.zone_skip;

		/*
		 * Wrap from the beginning, if we exceed the file size
		 */
		if (f->file_offset >= f->real_file_size)
			f->file_offset = f->real_file_size - f->file_offset;
		f->last_pos[io_u->ddir] = f->file_offset;
		td->io_skip_bytes += td->o.zone_skip;
	}

	/*
	 * No log, let the seq/rand engine retrieve the next buflen and
	 * position.
	 */
	if (get_next_offset(td, io_u, &is_random)) {
		dprint(FD_IO, "io_u %p, failed getting offset\n", io_u);
		return 1;
	}

	io_u->buflen = get_next_buflen(td, io_u, is_random);
	if (!io_u->buflen) {
		dprint(FD_IO, "io_u %p, failed getting buflen\n", io_u);
		return 1;
	}

	if (io_u->offset + io_u->buflen > io_u->file->real_file_size) {
		dprint(FD_IO, "io_u %p, offset too large\n", io_u);
		dprint(FD_IO, "  off=%llu/%lu > %llu\n",
			(unsigned long long) io_u->offset, io_u->buflen,
			(unsigned long long) io_u->file->real_file_size);
		return 1;
	}

	/*
	 * mark entry before potentially trimming io_u
	 */
	if (td_random(td) && file_randommap(td, io_u->file))
		mark_random_map(td, io_u);

out:
	dprint_io_u(io_u, "fill_io_u");
	td->zone_bytes += io_u->buflen;
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

static unsigned int __get_next_fileno_rand(struct thread_data *td)
{
	unsigned long fileno;

	if (td->o.file_service_type == FIO_FSERVICE_RANDOM) {
		uint64_t frand_max = rand_max(&td->next_file_state);
		unsigned long r;

		r = __rand(&td->next_file_state);
		return (unsigned int) ((double) td->o.nr_files
				* (r / (frand_max + 1.0)));
	}

	if (td->o.file_service_type == FIO_FSERVICE_ZIPF)
		fileno = zipf_next(&td->next_file_zipf);
	else if (td->o.file_service_type == FIO_FSERVICE_PARETO)
		fileno = pareto_next(&td->next_file_zipf);
	else if (td->o.file_service_type == FIO_FSERVICE_GAUSS)
		fileno = gauss_next(&td->next_file_gauss);
	else {
		log_err("fio: bad file service type: %d\n", td->o.file_service_type);
		assert(0);
		return 0;
	}

	return fileno >> FIO_FSERVICE_SHIFT;
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

		fno = __get_next_fileno_rand(td);

		f = td->files[fno];
		if (fio_file_done(f))
			continue;

		if (!fio_file_open(f)) {
			int err;

			if (td->nr_open_files >= td->o.open_files)
				return ERR_PTR(-EBUSY);

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

			if (td->nr_open_files >= td->o.open_files)
				return ERR_PTR(-EBUSY);

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

	if (IS_ERR(f))
		return f;

	td->file_service_file = f;
	td->file_service_left = td->file_service_nr - 1;
out:
	if (f)
		dprint(FD_FILE, "get_next_file: %p [%s]\n", f, f->file_name);
	else
		dprint(FD_FILE, "get_next_file: NULL\n");
	return f;
}

static struct fio_file *get_next_file(struct thread_data *td)
{
	if (td->flags & TD_F_PROFILE_OPS) {
		struct prof_io_ops *ops = &td->prof_io_ops;

		if (ops->get_next_file)
			return ops->get_next_file(td);
	}

	return __get_next_file(td);
}

static long set_io_u_file(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f;

	do {
		f = get_next_file(td);
		if (IS_ERR_OR_NULL(f))
			return PTR_ERR(f);

		io_u->file = f;
		get_file(f);

		if (!fill_io_u(td, io_u))
			break;

		put_file_log(td, f);
		td_io_close_file(td, f);
		io_u->file = NULL;
		if (td->o.file_service_type & __FIO_FSERVICE_NONUNIFORM)
			fio_file_reset(td, f);
		else {
			fio_file_set_done(f);
			td->nr_done_files++;
			dprint(FD_FILE, "%s: is done (%d of %d)\n", f->file_name,
					td->nr_done_files, td->o.nr_files);
		}
	} while (1);

	return 0;
}

static void lat_fatal(struct thread_data *td, struct io_completion_data *icd,
		      unsigned long tusec, unsigned long max_usec)
{
	if (!td->error)
		log_err("fio: latency of %lu usec exceeds specified max (%lu usec)\n", tusec, max_usec);
	td_verror(td, ETIMEDOUT, "max latency exceeded");
	icd->error = ETIMEDOUT;
}

static void lat_new_cycle(struct thread_data *td)
{
	fio_gettime(&td->latency_ts, NULL);
	td->latency_ios = ddir_rw_sum(td->io_blocks);
	td->latency_failed = 0;
}

/*
 * We had an IO outside the latency target. Reduce the queue depth. If we
 * are at QD=1, then it's time to give up.
 */
static bool __lat_target_failed(struct thread_data *td)
{
	if (td->latency_qd == 1)
		return true;

	td->latency_qd_high = td->latency_qd;

	if (td->latency_qd == td->latency_qd_low)
		td->latency_qd_low--;

	td->latency_qd = (td->latency_qd + td->latency_qd_low) / 2;

	dprint(FD_RATE, "Ramped down: %d %d %d\n", td->latency_qd_low, td->latency_qd, td->latency_qd_high);

	/*
	 * When we ramp QD down, quiesce existing IO to prevent
	 * a storm of ramp downs due to pending higher depth.
	 */
	io_u_quiesce(td);
	lat_new_cycle(td);
	return false;
}

static bool lat_target_failed(struct thread_data *td)
{
	if (td->o.latency_percentile.u.f == 100.0)
		return __lat_target_failed(td);

	td->latency_failed++;
	return false;
}

void lat_target_init(struct thread_data *td)
{
	td->latency_end_run = 0;

	if (td->o.latency_target) {
		dprint(FD_RATE, "Latency target=%llu\n", td->o.latency_target);
		fio_gettime(&td->latency_ts, NULL);
		td->latency_qd = 1;
		td->latency_qd_high = td->o.iodepth;
		td->latency_qd_low = 1;
		td->latency_ios = ddir_rw_sum(td->io_blocks);
	} else
		td->latency_qd = td->o.iodepth;
}

void lat_target_reset(struct thread_data *td)
{
	if (!td->latency_end_run)
		lat_target_init(td);
}

static void lat_target_success(struct thread_data *td)
{
	const unsigned int qd = td->latency_qd;
	struct thread_options *o = &td->o;

	td->latency_qd_low = td->latency_qd;

	/*
	 * If we haven't failed yet, we double up to a failing value instead
	 * of bisecting from highest possible queue depth. If we have set
	 * a limit other than td->o.iodepth, bisect between that.
	 */
	if (td->latency_qd_high != o->iodepth)
		td->latency_qd = (td->latency_qd + td->latency_qd_high) / 2;
	else
		td->latency_qd *= 2;

	if (td->latency_qd > o->iodepth)
		td->latency_qd = o->iodepth;

	dprint(FD_RATE, "Ramped up: %d %d %d\n", td->latency_qd_low, td->latency_qd, td->latency_qd_high);

	/*
	 * Same as last one, we are done. Let it run a latency cycle, so
	 * we get only the results from the targeted depth.
	 */
	if (td->latency_qd == qd) {
		if (td->latency_end_run) {
			dprint(FD_RATE, "We are done\n");
			td->done = 1;
		} else {
			dprint(FD_RATE, "Quiesce and final run\n");
			io_u_quiesce(td);
			td->latency_end_run = 1;
			reset_all_stats(td);
			reset_io_stats(td);
		}
	}

	lat_new_cycle(td);
}

/*
 * Check if we can bump the queue depth
 */
void lat_target_check(struct thread_data *td)
{
	uint64_t usec_window;
	uint64_t ios;
	double success_ios;

	usec_window = utime_since_now(&td->latency_ts);
	if (usec_window < td->o.latency_window)
		return;

	ios = ddir_rw_sum(td->io_blocks) - td->latency_ios;
	success_ios = (double) (ios - td->latency_failed) / (double) ios;
	success_ios *= 100.0;

	dprint(FD_RATE, "Success rate: %.2f%% (target %.2f%%)\n", success_ios, td->o.latency_percentile.u.f);

	if (success_ios >= td->o.latency_percentile.u.f)
		lat_target_success(td);
	else
		__lat_target_failed(td);
}

/*
 * If latency target is enabled, we might be ramping up or down and not
 * using the full queue depth available.
 */
bool queue_full(const struct thread_data *td)
{
	const int qempty = io_u_qempty(&td->io_u_freelist);

	if (qempty)
		return true;
	if (!td->o.latency_target)
		return false;

	return td->cur_depth >= td->latency_qd;
}

struct io_u *__get_io_u(struct thread_data *td)
{
	struct io_u *io_u = NULL;

	if (td->stop_io)
		return NULL;

	td_io_u_lock(td);

again:
	if (!io_u_rempty(&td->io_u_requeues))
		io_u = io_u_rpop(&td->io_u_requeues);
	else if (!queue_full(td)) {
		io_u = io_u_qpop(&td->io_u_freelist);

		io_u->file = NULL;
		io_u->buflen = 0;
		io_u->resid = 0;
		io_u->end_io = NULL;
	}

	if (io_u) {
		assert(io_u->flags & IO_U_F_FREE);
		io_u_clear(td, io_u, IO_U_F_FREE | IO_U_F_NO_FILE_PUT |
				 IO_U_F_TRIMMED | IO_U_F_BARRIER |
				 IO_U_F_VER_LIST);

		io_u->error = 0;
		io_u->acct_ddir = -1;
		td->cur_depth++;
		assert(!(td->flags & TD_F_CHILD));
		io_u_set(td, io_u, IO_U_F_IN_CUR_DEPTH);
		io_u->ipo = NULL;
	} else if (td_async_processing(td)) {
		/*
		 * We ran out, wait for async verify threads to finish and
		 * return one
		 */
		assert(!(td->flags & TD_F_CHILD));
		assert(!pthread_cond_wait(&td->free_cond, &td->io_u_lock));
		goto again;
	}

	td_io_u_unlock(td);
	return io_u;
}

static bool check_get_trim(struct thread_data *td, struct io_u *io_u)
{
	if (!(td->flags & TD_F_TRIM_BACKLOG))
		return false;

	if (td->trim_entries) {
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

		if (get_trim && get_next_trim(td, io_u))
			return true;
	}

	return false;
}

static bool check_get_verify(struct thread_data *td, struct io_u *io_u)
{
	if (!(td->flags & TD_F_VER_BACKLOG))
		return false;

	if (td->io_hist_len) {
		int get_verify = 0;

		if (td->verify_batch)
			get_verify = 1;
		else if (!(td->io_hist_len % td->o.verify_backlog) &&
			 td->last_ddir != DDIR_READ) {
			td->verify_batch = td->o.verify_batch;
			if (!td->verify_batch)
				td->verify_batch = td->o.verify_backlog;
			get_verify = 1;
		}

		if (get_verify && !get_next_verify(td, io_u)) {
			td->verify_batch--;
			return true;
		}
	}

	return false;
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
	uint64_t boffset;
	unsigned int offset;
	void *p, *end;

	if (!nr_blocks)
		return;

	p = io_u->xfer_buf;
	boffset = io_u->offset;
	io_u->buf_filled_len = 0;

	for (i = 0; i < nr_blocks; i++) {
		/*
		 * Fill the byte offset into a "random" start offset of
		 * the buffer, given by the product of the usec time
		 * and the actual offset.
		 */
		offset = (io_u->start_time.tv_usec ^ boffset) & 511;
		offset &= ~(sizeof(uint64_t) - 1);
		if (offset >= 512 - sizeof(uint64_t))
			offset -= sizeof(uint64_t);
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
	long ret = 0;

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
	if (td->flags & TD_F_READ_IOLOG) {
		if (read_iolog_get(td, io_u))
			goto err_put;
	} else if (set_io_u_file(td, io_u)) {
		ret = -EBUSY;
		dprint(FD_IO, "io_u %p, setting file failed\n", io_u);
		goto err_put;
	}

	f = io_u->file;
	if (!f) {
		dprint(FD_IO, "io_u %p, setting file failed\n", io_u);
		goto err_put;
	}

	assert(fio_file_open(f));

	if (ddir_rw(io_u->ddir)) {
		if (!io_u->buflen && !td_ioengine_flagged(td, FIO_NOIO)) {
			dprint(FD_IO, "get_io_u: zero buflen on %p\n", io_u);
			goto err_put;
		}

		f->last_start[io_u->ddir] = io_u->offset;
		f->last_pos[io_u->ddir] = io_u->offset + io_u->buflen;

		if (io_u->ddir == DDIR_WRITE) {
			if (td->flags & TD_F_REFILL_BUFFERS) {
				io_u_fill_buffer(td, io_u,
					td->o.min_bs[DDIR_WRITE],
					io_u->buflen);
			} else if ((td->flags & TD_F_SCRAMBLE_BUFFERS) &&
				   !(td->flags & TD_F_COMPRESS))
				do_scramble = 1;
			if (td->flags & TD_F_VER_NONE) {
				populate_verify_io_u(td, io_u);
				do_scramble = 0;
			}
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
		if (!td->o.disable_lat)
			fio_gettime(&io_u->start_time, NULL);
		if (do_scramble)
			small_content_scramble(io_u);
		return io_u;
	}
err_put:
	dprint(FD_IO, "get_io_u failed\n");
	put_io_u(td, io_u);
	return ERR_PTR(ret);
}

static void __io_u_log_error(struct thread_data *td, struct io_u *io_u)
{
	enum error_type_bit eb = td_error_type(io_u->ddir, io_u->error);

	if (td_non_fatal_error(td, eb, io_u->error) && !td->o.error_dump)
		return;

	log_err("fio: io_u error%s%s: %s: %s offset=%llu, buflen=%lu\n",
		io_u->file ? " on file " : "",
		io_u->file ? io_u->file->file_name : "",
		strerror(io_u->error),
		io_ddir_name(io_u->ddir),
		io_u->offset, io_u->xfer_buflen);

	if (td->io_ops->errdetails) {
		char *err = td->io_ops->errdetails(io_u);

		log_err("fio: %s\n", err);
		free(err);
	}

	if (!td->error)
		td_verror(td, io_u->error, "io_u error");
}

void io_u_log_error(struct thread_data *td, struct io_u *io_u)
{
	__io_u_log_error(td, io_u);
	if (td->parent)
		__io_u_log_error(td->parent, io_u);
}

static inline bool gtod_reduce(struct thread_data *td)
{
	return (td->o.disable_clat && td->o.disable_slat && td->o.disable_bw)
			|| td->o.gtod_reduce;
}

static void account_io_completion(struct thread_data *td, struct io_u *io_u,
				  struct io_completion_data *icd,
				  const enum fio_ddir idx, unsigned int bytes)
{
	const int no_reduce = !gtod_reduce(td);
	unsigned long lusec = 0;

	if (td->parent)
		td = td->parent;

	if (no_reduce)
		lusec = utime_since(&io_u->issue_time, &icd->time);

	if (!td->o.disable_lat) {
		unsigned long tusec;

		tusec = utime_since(&io_u->start_time, &icd->time);
		add_lat_sample(td, idx, tusec, bytes, io_u->offset);

		if (td->flags & TD_F_PROFILE_OPS) {
			struct prof_io_ops *ops = &td->prof_io_ops;

			if (ops->io_u_lat)
				icd->error = ops->io_u_lat(td, tusec);
		}

		if (td->o.max_latency && tusec > td->o.max_latency)
			lat_fatal(td, icd, tusec, td->o.max_latency);
		if (td->o.latency_target && tusec > td->o.latency_target) {
			if (lat_target_failed(td))
				lat_fatal(td, icd, tusec, td->o.latency_target);
		}
	}

	if (ddir_rw(idx)) {
		if (!td->o.disable_clat) {
			add_clat_sample(td, idx, lusec, bytes, io_u->offset);
			io_u_mark_latency(td, lusec);
		}

		if (!td->o.disable_bw && per_unit_log(td->bw_log))
			add_bw_sample(td, io_u, bytes, lusec);

		if (no_reduce && per_unit_log(td->iops_log))
			add_iops_sample(td, io_u, bytes);
	}

	if (td->ts.nr_block_infos && io_u->ddir == DDIR_TRIM) {
		uint32_t *info = io_u_block_info(td, io_u);
		if (BLOCK_INFO_STATE(*info) < BLOCK_STATE_TRIM_FAILURE) {
			if (io_u->ddir == DDIR_TRIM) {
				*info = BLOCK_INFO(BLOCK_STATE_TRIMMED,
						BLOCK_INFO_TRIMS(*info) + 1);
			} else if (io_u->ddir == DDIR_WRITE) {
				*info = BLOCK_INFO_SET_STATE(BLOCK_STATE_WRITTEN,
								*info);
			}
		}
	}
}

static void file_log_write_comp(const struct thread_data *td, struct fio_file *f,
				uint64_t offset, unsigned int bytes)
{
	int idx;

	if (!f)
		return;

	if (f->first_write == -1ULL || offset < f->first_write)
		f->first_write = offset;
	if (f->last_write == -1ULL || ((offset + bytes) > f->last_write))
		f->last_write = offset + bytes;

	if (!f->last_write_comp)
		return;

	idx = f->last_write_idx++;
	f->last_write_comp[idx] = offset;
	if (f->last_write_idx == td->o.iodepth)
		f->last_write_idx = 0;
}

static void io_completed(struct thread_data *td, struct io_u **io_u_ptr,
			 struct io_completion_data *icd)
{
	struct io_u *io_u = *io_u_ptr;
	enum fio_ddir ddir = io_u->ddir;
	struct fio_file *f = io_u->file;

	dprint_io_u(io_u, "io complete");

	assert(io_u->flags & IO_U_F_FLIGHT);
	io_u_clear(td, io_u, IO_U_F_FLIGHT | IO_U_F_BUSY_OK);

	/*
	 * Mark IO ok to verify
	 */
	if (io_u->ipo) {
		/*
		 * Remove errored entry from the verification list
		 */
		if (io_u->error)
			unlog_io_piece(td, io_u);
		else {
			io_u->ipo->flags &= ~IP_F_IN_FLIGHT;
			write_barrier();
		}
	}

	if (ddir_sync(ddir)) {
		td->last_was_sync = 1;
		if (f) {
			f->first_write = -1ULL;
			f->last_write = -1ULL;
		}
		return;
	}

	td->last_was_sync = 0;
	td->last_ddir = ddir;

	if (!io_u->error && ddir_rw(ddir)) {
		unsigned int bytes = io_u->buflen - io_u->resid;
		int ret;

		td->io_blocks[ddir]++;
		td->this_io_blocks[ddir]++;
		td->io_bytes[ddir] += bytes;

		if (!(io_u->flags & IO_U_F_VER_LIST))
			td->this_io_bytes[ddir] += bytes;

		if (ddir == DDIR_WRITE)
			file_log_write_comp(td, f, io_u->offset, bytes);

		if (ramp_time_over(td) && (td->runstate == TD_RUNNING ||
					   td->runstate == TD_VERIFYING))
			account_io_completion(td, io_u, icd, ddir, bytes);

		icd->bytes_done[ddir] += bytes;

		if (io_u->end_io) {
			ret = io_u->end_io(td, io_u_ptr);
			io_u = *io_u_ptr;
			if (ret && !icd->error)
				icd->error = ret;
		}
	} else if (io_u->error) {
		icd->error = io_u->error;
		io_u_log_error(td, io_u);
	}
	if (icd->error) {
		enum error_type_bit eb = td_error_type(ddir, icd->error);

		if (!td_non_fatal_error(td, eb, icd->error))
			return;

		/*
		 * If there is a non_fatal error, then add to the error count
		 * and clear all the errors.
		 */
		update_error_count(td, icd->error);
		td_clear_error(td);
		icd->error = 0;
		if (io_u)
			io_u->error = 0;
	}
}

static void init_icd(struct thread_data *td, struct io_completion_data *icd,
		     int nr)
{
	int ddir;

	if (!gtod_reduce(td))
		fio_gettime(&icd->time, NULL);

	icd->nr = nr;

	icd->error = 0;
	for (ddir = DDIR_READ; ddir < DDIR_RWDIR_CNT; ddir++)
		icd->bytes_done[ddir] = 0;
}

static void ios_completed(struct thread_data *td,
			  struct io_completion_data *icd)
{
	struct io_u *io_u;
	int i;

	for (i = 0; i < icd->nr; i++) {
		io_u = td->io_ops->event(td, i);

		io_completed(td, &io_u, icd);

		if (io_u)
			put_io_u(td, io_u);
	}
}

/*
 * Complete a single io_u for the sync engines.
 */
int io_u_sync_complete(struct thread_data *td, struct io_u *io_u)
{
	struct io_completion_data icd;
	int ddir;

	init_icd(td, &icd, 1);
	io_completed(td, &io_u, &icd);

	if (io_u)
		put_io_u(td, io_u);

	if (icd.error) {
		td_verror(td, icd.error, "io_u_sync_complete");
		return -1;
	}

	for (ddir = DDIR_READ; ddir < DDIR_RWDIR_CNT; ddir++)
		td->bytes_done[ddir] += icd.bytes_done[ddir];

	return 0;
}

/*
 * Called to complete min_events number of io for the async engines.
 */
int io_u_queued_complete(struct thread_data *td, int min_evts)
{
	struct io_completion_data icd;
	struct timespec *tvp = NULL;
	int ret, ddir;
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 0, };

	dprint(FD_IO, "io_u_queued_completed: min=%d\n", min_evts);

	if (!min_evts)
		tvp = &ts;
	else if (min_evts > td->cur_depth)
		min_evts = td->cur_depth;

	/* No worries, td_io_getevents fixes min and max if they are
	 * set incorrectly */
	ret = td_io_getevents(td, min_evts, td->o.iodepth_batch_complete_max, tvp);
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

	for (ddir = DDIR_READ; ddir < DDIR_RWDIR_CNT; ddir++)
		td->bytes_done[ddir] += icd.bytes_done[ddir];

	return ret;
}

/*
 * Call when io_u is really queued, to update the submission latency.
 */
void io_u_queued(struct thread_data *td, struct io_u *io_u)
{
	if (!td->o.disable_slat) {
		unsigned long slat_time;

		slat_time = utime_since(&io_u->start_time, &io_u->issue_time);

		if (td->parent)
			td = td->parent;

		add_slat_sample(td, io_u->ddir, slat_time, io_u->xfer_buflen,
				io_u->offset);
	}
}

/*
 * See if we should reuse the last seed, if dedupe is enabled
 */
static struct frand_state *get_buf_state(struct thread_data *td)
{
	unsigned int v;

	if (!td->o.dedupe_percentage)
		return &td->buf_state;
	else if (td->o.dedupe_percentage == 100) {
		frand_copy(&td->buf_state_prev, &td->buf_state);
		return &td->buf_state;
	}

	v = rand32_between(&td->dedupe_state, 1, 100);

	if (v <= td->o.dedupe_percentage)
		return &td->buf_state_prev;

	return &td->buf_state;
}

static void save_buf_state(struct thread_data *td, struct frand_state *rs)
{
	if (td->o.dedupe_percentage == 100)
		frand_copy(rs, &td->buf_state_prev);
	else if (rs == &td->buf_state)
		frand_copy(&td->buf_state_prev, rs);
}

void fill_io_buffer(struct thread_data *td, void *buf, unsigned int min_write,
		    unsigned int max_bs)
{
	struct thread_options *o = &td->o;

	if (o->compress_percentage || o->dedupe_percentage) {
		unsigned int perc = td->o.compress_percentage;
		struct frand_state *rs;
		unsigned int left = max_bs;
		unsigned int this_write;

		do {
			rs = get_buf_state(td);

			min_write = min(min_write, left);

			if (perc) {
				this_write = min_not_zero(min_write,
							td->o.compress_chunk);

				fill_random_buf_percentage(rs, buf, perc,
					this_write, this_write,
					o->buffer_pattern,
					o->buffer_pattern_bytes);
			} else {
				fill_random_buf(rs, buf, min_write);
				this_write = min_write;
			}

			buf += this_write;
			left -= this_write;
			save_buf_state(td, rs);
		} while (left);
	} else if (o->buffer_pattern_bytes)
		fill_buffer_pattern(td, buf, max_bs);
	else if (o->zero_buffers)
		memset(buf, 0, max_bs);
	else
		fill_random_buf(get_buf_state(td), buf, max_bs);
}

/*
 * "randomly" fill the buffer contents
 */
void io_u_fill_buffer(struct thread_data *td, struct io_u *io_u,
		      unsigned int min_write, unsigned int max_bs)
{
	io_u->buf_filled_len = 0;
	fill_io_buffer(td, io_u->buf, min_write, max_bs);
}
