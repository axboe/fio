/*
 * blktrace support code for fio
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "flist.h"
#include "fio.h"
#include "blktrace.h"
#include "blktrace_api.h"
#include "oslib/linux-dev-lookup.h"

/*
 * Just discard the pdu by seeking past it.
 */
static int discard_pdu(FILE* f, struct blk_io_trace *t)
{
	if (t->pdu_len == 0)
		return 0;
	if (fseek(f, t->pdu_len, SEEK_CUR) == 0)
		return t->pdu_len;
	else
		return -1;
}

/*
 * Check if this is a blktrace binary data file. We read a single trace
 * into memory and check for the magic signature.
 */
bool is_blktrace(const char *filename, int *need_swap)
{
	struct blk_io_trace t;
	int fd, ret;

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return false;

	ret = read(fd, &t, sizeof(t));
	close(fd);

	if (ret < 0) {
		perror("read blktrace");
		return false;
	} else if (ret != sizeof(t)) {
		log_err("fio: short read on blktrace file\n");
		return false;
	}

	if ((t.magic & 0xffffff00) == BLK_IO_TRACE_MAGIC) {
		*need_swap = 0;
		return true;
	}

	/*
	 * Maybe it needs to be endian swapped...
	 */
	t.magic = fio_swap32(t.magic);
	if ((t.magic & 0xffffff00) == BLK_IO_TRACE_MAGIC) {
		*need_swap = 1;
		return true;
	}

	return false;
}

#define FMINORBITS	20
#define FMINORMASK	((1U << FMINORBITS) - 1)
#define FMAJOR(dev)	((unsigned int) ((dev) >> FMINORBITS))
#define FMINOR(dev)	((unsigned int) ((dev) & FMINORMASK))

static void trace_add_open_close_event(struct thread_data *td, int fileno, enum file_log_act action)
{
	struct io_piece *ipo;

	ipo = calloc(1, sizeof(*ipo));
	init_ipo(ipo);

	ipo->ddir = DDIR_INVAL;
	ipo->fileno = fileno;
	ipo->file_action = action;
	flist_add_tail(&ipo->list, &td->io_log_list);
}

static int trace_add_file(struct thread_data *td, __u32 device)
{
	static unsigned int last_maj, last_min, last_fileno;
	unsigned int maj = FMAJOR(device);
	unsigned int min = FMINOR(device);
	struct fio_file *f;
	char dev[256];
	unsigned int i;

	if (last_maj == maj && last_min == min)
		return last_fileno;

	last_maj = maj;
	last_min = min;

	/*
	 * check for this file in our list
	 */
	for_each_file(td, f, i)
		if (f->major == maj && f->minor == min) {
			last_fileno = f->fileno;
			return last_fileno;
		}

	strcpy(dev, "/dev");
	if (blktrace_lookup_device(td->o.replay_redirect, dev, maj, min)) {
		int fileno;

		if (td->o.replay_redirect)
			dprint(FD_BLKTRACE, "device lookup: %d/%d\n overridden"
					" with: %s\n", maj, min,
					td->o.replay_redirect);
		else
			dprint(FD_BLKTRACE, "device lookup: %d/%d\n", maj, min);

		dprint(FD_BLKTRACE, "add devices %s\n", dev);
		fileno = add_file_exclusive(td, dev);
		td->o.open_files++;
		td->files[fileno]->major = maj;
		td->files[fileno]->minor = min;
		trace_add_open_close_event(td, fileno, FIO_LOG_OPEN_FILE);
		last_fileno = fileno;
	}

	return last_fileno;
}

static void t_bytes_align(struct thread_options *o, struct blk_io_trace *t)
{
	if (!o->replay_align)
		return;

	t->bytes = (t->bytes + o->replay_align - 1) & ~(o->replay_align - 1);
}

/*
 * Store blk_io_trace data in an ipo for later retrieval.
 */
static bool store_ipo(struct thread_data *td, unsigned long long offset,
		      unsigned int bytes, int rw, unsigned long long ttime,
		      int fileno)
{
	struct io_piece *ipo;

	ipo = calloc(1, sizeof(*ipo));
	init_ipo(ipo);

	ipo->offset = offset * 512;
	if (td->o.replay_scale)
		ipo->offset = ipo->offset / td->o.replay_scale;
	ipo_bytes_align(td->o.replay_align, ipo);
	ipo->len = bytes;
	ipo->delay = ttime / 1000;
	if (rw)
		ipo->ddir = DDIR_WRITE;
	else
		ipo->ddir = DDIR_READ;
	ipo->fileno = fileno;

	dprint(FD_BLKTRACE, "store ddir=%d, off=%llu, len=%lu, delay=%lu\n",
							ipo->ddir, ipo->offset,
							ipo->len, ipo->delay);
	queue_io_piece(td, ipo);
	return true;
}

static bool handle_trace_notify(struct blk_io_trace *t)
{
	switch (t->action) {
	case BLK_TN_PROCESS:
		dprint(FD_BLKTRACE, "got process notify: %x, %d\n",
				t->action, t->pid);
		break;
	case BLK_TN_TIMESTAMP:
		dprint(FD_BLKTRACE, "got timestamp notify: %x, %d\n",
				t->action, t->pid);
		break;
	case BLK_TN_MESSAGE:
		break;
	default:
		dprint(FD_BLKTRACE, "unknown trace act %x\n", t->action);
		break;
	}
	return false;
}

static bool handle_trace_discard(struct thread_data *td,
				 struct blk_io_trace *t,
				 unsigned long long ttime,
				 unsigned long *ios, unsigned int *bs)
{
	struct io_piece *ipo;
	int fileno;

	if (td->o.replay_skip & (1u << DDIR_TRIM))
		return false;

	ipo = calloc(1, sizeof(*ipo));
	init_ipo(ipo);
	fileno = trace_add_file(td, t->device);

	ios[DDIR_TRIM]++;
	if (t->bytes > bs[DDIR_TRIM])
		bs[DDIR_TRIM] = t->bytes;

	td->o.size += t->bytes;

	INIT_FLIST_HEAD(&ipo->list);

	ipo->offset = t->sector * 512;
	if (td->o.replay_scale)
		ipo->offset = ipo->offset / td->o.replay_scale;
	ipo_bytes_align(td->o.replay_align, ipo);
	ipo->len = t->bytes;
	ipo->delay = ttime / 1000;
	ipo->ddir = DDIR_TRIM;
	ipo->fileno = fileno;

	dprint(FD_BLKTRACE, "store discard, off=%llu, len=%lu, delay=%lu\n",
							ipo->offset, ipo->len,
							ipo->delay);
	queue_io_piece(td, ipo);
	return true;
}

static void dump_trace(struct blk_io_trace *t)
{
	log_err("blktrace: ignoring zero byte trace: action=%x\n", t->action);
}

static bool handle_trace_fs(struct thread_data *td, struct blk_io_trace *t,
			    unsigned long long ttime, unsigned long *ios,
			    unsigned int *bs)
{
	int rw;
	int fileno;

	fileno = trace_add_file(td, t->device);

	rw = (t->action & BLK_TC_ACT(BLK_TC_WRITE)) != 0;

	if (rw) {
		if (td->o.replay_skip & (1u << DDIR_WRITE))
			return false;
	} else {
		if (td->o.replay_skip & (1u << DDIR_READ))
			return false;
	}

	if (!t->bytes) {
		if (!fio_did_warn(FIO_WARN_BTRACE_ZERO))
			dump_trace(t);
		return false;
	}

	if (t->bytes > bs[rw])
		bs[rw] = t->bytes;

	ios[rw]++;
	td->o.size += t->bytes;
	return store_ipo(td, t->sector, t->bytes, rw, ttime, fileno);
}

static bool handle_trace_flush(struct thread_data *td, struct blk_io_trace *t,
			       unsigned long long ttime, unsigned long *ios)
{
	struct io_piece *ipo;
	int fileno;

	if (td->o.replay_skip & (1u << DDIR_SYNC))
		return false;

	ipo = calloc(1, sizeof(*ipo));
	init_ipo(ipo);
	fileno = trace_add_file(td, t->device);

	ipo->delay = ttime / 1000;
	ipo->ddir = DDIR_SYNC;
	ipo->fileno = fileno;

	ios[DDIR_SYNC]++;
	dprint(FD_BLKTRACE, "store flush delay=%lu\n", ipo->delay);
	queue_io_piece(td, ipo);
	return true;
}

/*
 * We only care for queue traces, most of the others are side effects
 * due to internal workings of the block layer.
 */
static bool queue_trace(struct thread_data *td, struct blk_io_trace *t,
			 unsigned long *ios, unsigned int *bs)
{
	static unsigned long long last_ttime;
	unsigned long long delay = 0;

	if ((t->action & 0xffff) != __BLK_TA_QUEUE)
		return false;

	if (!(t->action & BLK_TC_ACT(BLK_TC_NOTIFY))) {
		if (!last_ttime || td->o.no_stall)
			delay = 0;
		else if (td->o.replay_time_scale == 100)
			delay = t->time - last_ttime;
		else {
			double tmp = t->time - last_ttime;
			double scale;

			scale = (double) 100.0 / (double) td->o.replay_time_scale;
			tmp *= scale;
			delay = tmp;
		}
		last_ttime = t->time;
	}

	t_bytes_align(&td->o, t);

	if (t->action & BLK_TC_ACT(BLK_TC_NOTIFY))
		return handle_trace_notify(t);
	else if (t->action & BLK_TC_ACT(BLK_TC_DISCARD))
		return handle_trace_discard(td, t, delay, ios, bs);
	else if (t->action & BLK_TC_ACT(BLK_TC_FLUSH))
		return handle_trace_flush(td, t, delay, ios);
	else
		return handle_trace_fs(td, t, delay, ios, bs);
}

static void byteswap_trace(struct blk_io_trace *t)
{
	t->magic = fio_swap32(t->magic);
	t->sequence = fio_swap32(t->sequence);
	t->time = fio_swap64(t->time);
	t->sector = fio_swap64(t->sector);
	t->bytes = fio_swap32(t->bytes);
	t->action = fio_swap32(t->action);
	t->pid = fio_swap32(t->pid);
	t->device = fio_swap32(t->device);
	t->cpu = fio_swap32(t->cpu);
	t->error = fio_swap16(t->error);
	t->pdu_len = fio_swap16(t->pdu_len);
}

static bool t_is_write(struct blk_io_trace *t)
{
	return (t->action & BLK_TC_ACT(BLK_TC_WRITE | BLK_TC_DISCARD)) != 0;
}

static enum fio_ddir t_get_ddir(struct blk_io_trace *t)
{
	if (t->action & BLK_TC_ACT(BLK_TC_READ))
		return DDIR_READ;
	else if (t->action & BLK_TC_ACT(BLK_TC_WRITE))
		return DDIR_WRITE;
	else if (t->action & BLK_TC_ACT(BLK_TC_DISCARD))
		return DDIR_TRIM;

	return DDIR_INVAL;
}

static void depth_inc(struct blk_io_trace *t, int *depth)
{
	enum fio_ddir ddir;

	ddir = t_get_ddir(t);
	if (ddir != DDIR_INVAL)
		depth[ddir]++;
}

static void depth_dec(struct blk_io_trace *t, int *depth)
{
	enum fio_ddir ddir;

	ddir = t_get_ddir(t);
	if (ddir != DDIR_INVAL)
		depth[ddir]--;
}

static void depth_end(struct blk_io_trace *t, int *this_depth, int *depth)
{
	enum fio_ddir ddir = DDIR_INVAL;

	ddir = t_get_ddir(t);
	if (ddir != DDIR_INVAL) {
		depth[ddir] = max(depth[ddir], this_depth[ddir]);
		this_depth[ddir] = 0;
	}
}

static void depth_set(struct thread_data *td, int *depth, unsigned long *ios)
{
	/*
	 * For stacked devices, we don't always get a COMPLETE event so
	 * the depth grows to insane values. Limit it to something sane(r).
	 */
	int max_depth = 0, i = 0;
	for ( ; i < DDIR_RWDIR_CNT; i++) {
		if (depth[i] > 1024)
			depth[i] = 1024;
		else if (!depth[i] && ios[i])
			depth[i] = 1;
		max_depth = max(depth[i], max_depth);
	}

	td->o.iodepth = td->o.iodepth_low = max_depth;
	dprint(FD_BLKTRACE, "set max_depth = %d\n", max_depth);
}

/*
 * Load a blktrace file by reading all the blk_io_trace entries, and storing
 * them as io_pieces like the fio text version would do.
 */
bool init_blktrace_read(struct thread_data *td, const char *filename, int need_swap)
{
	int old_state;

	td->io_log_rfile = fopen(filename, "rb");
	if (td->io_log_rfile == NULL) {
		td_verror(td, errno, "open blktrace file");
		goto err;
	}
	td->io_log_blktrace_swap = need_swap;
	td->o.size = 0;

	old_state = td_bump_runstate(td, TD_SETTING_UP);

	if (!read_blktrace(td)) {
		goto err;
	}

	td_restore_runstate(td, old_state);

	if (!td->files_index) {
		log_err("fio: did not find replay device(s)\n");
		return false;
	}

	return true;

err:
	if (td->io_log_rfile) {
		fclose(td->io_log_rfile);
		td->io_log_rfile = NULL;
	}
	return false;
}

bool read_blktrace(struct thread_data* td)
{
	int i;
	struct blk_io_trace t;
	unsigned long ios[DDIR_RWDIR_SYNC_CNT] = { };
	unsigned int rw_bs[DDIR_RWDIR_CNT] = { };
	FILE *f = td->io_log_rfile;
	int need_swap = td->io_log_blktrace_swap;
	struct fio_file* fiof;
	int this_depth[DDIR_RWDIR_CNT] = { };
	int depth[DDIR_RWDIR_CNT] = { };
	bool chunked = td->o.read_iolog_chunked;
	bool queued;
	bool realloc = false;

	// If depth wasn't manually set, use probed depth at first read
	bool probe_depth = (ftell(f) == 0 && !fio_option_is_set(&td->o, iodepth));

	// most devices don't have 512k IOPS, should be enough for seconds
	// optimally there should be an option for this
	uint32_t chunked_items = probe_depth ? 4 * 1024 * 1024 : 512 * 1024;
	unsigned long chunked_begin = td->io_log_current;

	td->io_log_checkmark  = chunked_items / 2;

	if (td->io_log_done)
		return true;

	do {
		int ret = fread(&t, 1, sizeof(t), f);

		if (ferror(f)) {
			td_verror(td, errno, "read blktrace file");
			goto err;
		}
		if (ret == 0)
			break;
		if (ret != (int) sizeof(t)) {
			log_err("fio: fread short trace data %d\n", ret);
			break;
		}

		if (need_swap)
			byteswap_trace(&t);

		if ((t.magic & 0xffffff00) != BLK_IO_TRACE_MAGIC) {
			log_err("fio: bad magic in blktrace data: %x\n", t.magic);
			goto err;
		}
		if ((t.magic & 0xff) != BLK_IO_TRACE_VERSION) {
			log_err("fio: bad blktrace version %d\n", t.magic & 0xff);
			goto err;
		}

		ret = discard_pdu(f, &t);
		if (ret < 0) {
			td_verror(td, ret, "blktrace lseek");
			goto err;
		}
		if ((t.action & BLK_TC_ACT(BLK_TC_NOTIFY)) == 0) {

			if (fio_unlikely(probe_depth)) {
				if ((t.action & 0xffff) == __BLK_TA_QUEUE)
					depth_inc(&t, this_depth);
				else if (((t.action & 0xffff) == __BLK_TA_BACKMERGE) ||
						((t.action & 0xffff) == __BLK_TA_FRONTMERGE))
					depth_dec(&t, this_depth);
				else if ((t.action & 0xffff) == __BLK_TA_COMPLETE)
					depth_end(&t, this_depth, depth);
			}

			if (t_is_write(&t) && read_only) {
				td->io_log_skipped_writes++;
				continue;
			}
		}

		queued = queue_trace(td, &t, ios, rw_bs);
		if (chunked && queued) {
			td->io_log_current++;
			chunked_items--;
			if (chunked_items == 0)
				break;
		}
	} while (1);

	/* add close files io_piece to the end */
	if (!chunked || chunked_items) {
		for_each_file(td, fiof, i) {
			trace_add_open_close_event(td, fiof->fileno, FIO_LOG_CLOSE_FILE);
			if (chunked)
				td->io_log_current++;
		}

		if (td->io_log_skipped_writes) {
			log_err("fio: <%s> skips replay of %llu writes due to"
					" read-only\n", td->o.name, td->io_log_skipped_writes);
		}

		td->io_log_done = 1;
	}

	if (chunked) {
		dprint(FD_BLKTRACE, "blktrace chunk %lu items\n",
				td->io_log_current - chunked_begin);

		if (td->io_log_done)
			dprint(FD_BLKTRACE, "chunked blktrace read done\n");

		td->o.td_ddir = TD_DDIR_RW;

		// DDIR_READ, DDIR_WRITE, DDIR_TRIM
		for (i = DDIR_READ; i < DDIR_SYNC; ++i) {
			if (td->o.max_bs[i] >= rw_bs[i])
				continue;
			realloc = true;
			td->o.max_bs[i] = rw_bs[i];
		}
		if (realloc && td->orig_buffer) {
			io_u_quiesce(td);
			free_io_mem(td);
			init_io_u_buffers(td);

			dprint(FD_BLKTRACE, "blktrace realloc for max_bs\n");
		}

		if (probe_depth) {
			depth_set(td, depth, ios);
		}
		return true;
	}

	if (!ios[DDIR_READ] && !ios[DDIR_WRITE] && !ios[DDIR_TRIM] &&
	    !ios[DDIR_SYNC]) {
		log_err("fio: found no ios in blktrace data\n");
		return false;
	} else if (ios[DDIR_READ] && !ios[DDIR_WRITE]) {
		td->o.td_ddir = TD_DDIR_READ;
		td->o.max_bs[DDIR_READ] = rw_bs[DDIR_READ];
	} else if (!ios[DDIR_READ] && ios[DDIR_WRITE]) {
		td->o.td_ddir = TD_DDIR_WRITE;
		td->o.max_bs[DDIR_WRITE] = rw_bs[DDIR_WRITE];
	} else {
		td->o.td_ddir = TD_DDIR_RW;
		td->o.max_bs[DDIR_READ] = rw_bs[DDIR_READ];
		td->o.max_bs[DDIR_WRITE] = rw_bs[DDIR_WRITE];
		td->o.max_bs[DDIR_TRIM] = rw_bs[DDIR_TRIM];
	}

	if (probe_depth) {
		depth_set(td, depth, ios);
	}

	return true;
err:
	return false;
}

static int init_merge_param_list(fio_fp64_t *vals, struct blktrace_cursor *bcs,
				 int nr_logs, int def, size_t off)
{
	int i = 0, len = 0;

	while (len < FIO_IO_U_LIST_MAX_LEN && vals[len].u.f != 0.0)
		len++;

	if (len && len != nr_logs)
		return len;

	for (i = 0; i < nr_logs; i++) {
		int *val = (int *)((char *)&bcs[i] + off);
		*val = def;
		if (len)
			*val = (int)vals[i].u.f;
	}

	return 0;

}

static int find_earliest_io(struct blktrace_cursor *bcs, int nr_logs)
{
	__u64 time = ~(__u64)0;
	int idx = 0, i;

	for (i = 0; i < nr_logs; i++) {
		if (bcs[i].t.time < time) {
			time = bcs[i].t.time;
			idx = i;
		}
	}

	return idx;
}

static void merge_finish_file(struct blktrace_cursor *bcs, int i, int *nr_logs)
{
	bcs[i].iter++;
	if (bcs[i].iter < bcs[i].nr_iter) {
		fseek(bcs[i].f, 0, SEEK_SET);
		return;
	}

	*nr_logs -= 1;

	fclose(bcs[i].f);

	/* keep active files contiguous */
	memmove(&bcs[i], &bcs[*nr_logs], sizeof(bcs[i]));
}

static int read_trace(struct thread_data *td, struct blktrace_cursor *bc)
{
	int ret = 0;
	struct blk_io_trace *t = &bc->t;

read_skip:
	ret = fread(&t, 1, sizeof(t), bc->f);

	if (ferror(bc->f)) {
		return -1;
	} else if (!ret) {
		if (!bc->length)
			bc->length = bc->t.time;
		return ret;
	} else if (ret != (int) sizeof(*t)) {
		log_err("fio: fread short trace data %d\n", ret);
		return -1;
	}

	if (fio_unlikely(bc->swap))
		byteswap_trace(t);

	/* skip over actions that fio does not care about */
	if ((t->action & 0xffff) != __BLK_TA_QUEUE ||
	    t_get_ddir(t) == DDIR_INVAL) {
		ret = discard_pdu(bc->f, t);
		if (ret < 0) {
			td_verror(td, ret, "blktrace lseek");
			return ret;
		}
		goto read_skip;
	}

	t->time = (t->time + bc->iter * bc->length) * bc->scalar / 100;

	return ret;
}

static int write_trace(FILE *fp, struct blk_io_trace *t)
{
	/* pdu is not used so just write out only the io trace */
	t->pdu_len = 0;
	return fwrite((void *)t, sizeof(*t), 1, fp);
}

int merge_blktrace_iologs(struct thread_data *td)
{
	int nr_logs = get_max_str_idx(td->o.read_iolog_file);
	struct blktrace_cursor *bcs = malloc(sizeof(struct blktrace_cursor) *
					     nr_logs);
	struct blktrace_cursor *bc;
	FILE *merge_fp;
	char *str, *ptr, *name, *merge_buf;
	int i, ret;

	ret = init_merge_param_list(td->o.merge_blktrace_scalars, bcs, nr_logs,
				    100, offsetof(struct blktrace_cursor,
						  scalar));
	if (ret) {
		log_err("fio: merge_blktrace_scalars(%d) != nr_logs(%d)\n",
			ret, nr_logs);
		goto err_param;
	}

	ret = init_merge_param_list(td->o.merge_blktrace_iters, bcs, nr_logs,
				    1, offsetof(struct blktrace_cursor,
						nr_iter));
	if (ret) {
		log_err("fio: merge_blktrace_iters(%d) != nr_logs(%d)\n",
			ret, nr_logs);
		goto err_param;
	}

	/* setup output file */
	merge_fp = fopen(td->o.merge_blktrace_file, "w");
	merge_buf = malloc(128 * 1024);
	ret = setvbuf(merge_fp, merge_buf, _IOFBF, 128 * 1024);
	if (ret)
		goto err_out_file;

	/* setup input files */
	str = ptr = strdup(td->o.read_iolog_file);
	nr_logs = 0;
	for (i = 0; (name = get_next_str(&ptr)) != NULL; i++) {
		bcs[i].f = fopen(name, "rb");
		if (bcs[i].f == NULL) {
			log_err("fio: could not open file: %s\n", name);
			ret = -1;
			goto err_file;
		}
		nr_logs++;

		if (!is_blktrace(name, &bcs[i].swap)) {
			log_err("fio: file is not a blktrace: %s\n", name);
			goto err_file;
		}

		ret = read_trace(td, &bcs[i]);
		if (ret < 0) {
			goto err_file;
		} else if (!ret) {
			merge_finish_file(bcs, i, &nr_logs);
			i--;
		}
	}
	free(str);

	/* merge files */
	while (nr_logs) {
		i = find_earliest_io(bcs, nr_logs);
		bc = &bcs[i];

		/* skip over the pdu */
		ret = discard_pdu(bc->f, &bc->t);
		if (ret < 0) {
			td_verror(td, ret, "blktrace lseek");
			goto err_file;
		}

		ret = write_trace(merge_fp, &bc->t);
		ret = read_trace(td, bc);
		if (ret < 0)
			goto err_file;
		else if (!ret)
			merge_finish_file(bcs, i, &nr_logs);
	}

	/* set iolog file to read from the newly merged file */
	td->o.read_iolog_file = td->o.merge_blktrace_file;
	ret = 0;

err_file:
	/* cleanup */
	for (i = 0; i < nr_logs; i++) {
		fclose(bcs[i].f);
	}
err_out_file:
	fflush(merge_fp);
	fclose(merge_fp);
	free(merge_buf);
err_param:
	free(bcs);

	return ret;
}
