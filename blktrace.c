/*
 * blktrace support code for fio
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <dirent.h>

#include "flist.h"
#include "fio.h"
#include "blktrace_api.h"
#include "oslib/linux-dev-lookup.h"

#define TRACE_FIFO_SIZE	8192

/*
 * fifo refill frontend, to avoid reading data in trace sized bites
 */
static int refill_fifo(struct thread_data *td, struct fifo *fifo, int fd)
{
	char buf[TRACE_FIFO_SIZE];
	unsigned int total;
	int ret;

	total = sizeof(buf);
	if (total > fifo_room(fifo))
		total = fifo_room(fifo);

	ret = read(fd, buf, total);
	if (ret < 0) {
		td_verror(td, errno, "read blktrace file");
		return -1;
	}

	if (ret > 0)
		ret = fifo_put(fifo, buf, ret);

	dprint(FD_BLKTRACE, "refill: filled %d bytes\n", ret);
	return ret;
}

/*
 * Retrieve 'len' bytes from the fifo, refilling if necessary.
 */
static int trace_fifo_get(struct thread_data *td, struct fifo *fifo, int fd,
			  void *buf, unsigned int len)
{
	if (fifo_len(fifo) < len) {
		int ret = refill_fifo(td, fifo, fd);

		if (ret < 0)
			return ret;
	}

	return fifo_get(fifo, buf, len);
}

/*
 * Just discard the pdu by seeking past it.
 */
static int discard_pdu(struct thread_data *td, struct fifo *fifo, int fd,
		       struct blk_io_trace *t)
{
	if (t->pdu_len == 0)
		return 0;

	dprint(FD_BLKTRACE, "discard pdu len %u\n", t->pdu_len);
	return trace_fifo_get(td, fifo, fd, NULL, t->pdu_len);
}

/*
 * Check if this is a blktrace binary data file. We read a single trace
 * into memory and check for the magic signature.
 */
int is_blktrace(const char *filename, int *need_swap)
{
	struct blk_io_trace t;
	int fd, ret;

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return 0;

	ret = read(fd, &t, sizeof(t));
	close(fd);

	if (ret < 0) {
		perror("read blktrace");
		return 0;
	} else if (ret != sizeof(t)) {
		log_err("fio: short read on blktrace file\n");
		return 0;
	}

	if ((t.magic & 0xffffff00) == BLK_IO_TRACE_MAGIC) {
		*need_swap = 0;
		return 1;
	}

	/*
	 * Maybe it needs to be endian swapped...
	 */
	t.magic = fio_swap32(t.magic);
	if ((t.magic & 0xffffff00) == BLK_IO_TRACE_MAGIC) {
		*need_swap = 1;
		return 1;
	}

	return 0;
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

static int get_dev_blocksize(const char *dev, unsigned int *bs)
{
	int fd;

	fd = open(dev, O_RDONLY);
	if (fd < 0)
		return 1;

	if (ioctl(fd, BLKSSZGET, bs) < 0) {
		close(fd);
		return 1;
	}

	close(fd);
	return 0;
}

static int trace_add_file(struct thread_data *td, __u32 device,
			  unsigned int *bs)
{
	static unsigned int last_maj, last_min, last_fileno, last_bs;
	unsigned int maj = FMAJOR(device);
	unsigned int min = FMINOR(device);
	struct fio_file *f;
	unsigned int i;
	char dev[256];

	if (last_maj == maj && last_min == min) {
		*bs = last_bs;
		return last_fileno;
	}

	last_maj = maj;
	last_min = min;

	/*
	 * check for this file in our list
	 */
	for_each_file(td, f, i) {
		if (f->major == maj && f->minor == min) {
			last_fileno = f->fileno;
			last_bs = f->bs;
			goto out;
		}
	}

	strcpy(dev, "/dev");
	if (blktrace_lookup_device(td->o.replay_redirect, dev, maj, min)) {
		unsigned int this_bs;
		int fileno;

		if (td->o.replay_redirect)
			dprint(FD_BLKTRACE, "device lookup: %d/%d\n overridden"
					" with: %s\n", maj, min,
					td->o.replay_redirect);
		else
			dprint(FD_BLKTRACE, "device lookup: %d/%d\n", maj, min);

		dprint(FD_BLKTRACE, "add devices %s\n", dev);
		fileno = add_file_exclusive(td, dev);

		if (get_dev_blocksize(dev, &this_bs))
			this_bs = 512;

		td->o.open_files++;
		td->files[fileno]->major = maj;
		td->files[fileno]->minor = min;
		td->files[fileno]->bs = this_bs;
		trace_add_open_close_event(td, fileno, FIO_LOG_OPEN_FILE);

		last_fileno = fileno;
		last_bs = this_bs;
	}

out:
	*bs = last_bs;
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
static void store_ipo(struct thread_data *td, unsigned long long offset,
		      unsigned int bytes, int rw, unsigned long long ttime,
		      int fileno, unsigned int bs)
{
	struct io_piece *ipo = malloc(sizeof(*ipo));

	init_ipo(ipo);

	ipo->offset = offset * bs;
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
}

static void handle_trace_notify(struct blk_io_trace *t)
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
}

static void handle_trace_discard(struct thread_data *td,
				 struct blk_io_trace *t,
				 unsigned long long ttime,
				 unsigned long *ios, unsigned int *rw_bs)
{
	struct io_piece *ipo = malloc(sizeof(*ipo));
	unsigned int bs;
	int fileno;

	init_ipo(ipo);
	fileno = trace_add_file(td, t->device, &bs);

	ios[DDIR_TRIM]++;
	if (t->bytes > rw_bs[DDIR_TRIM])
		rw_bs[DDIR_TRIM] = t->bytes;

	td->o.size += t->bytes;

	memset(ipo, 0, sizeof(*ipo));
	INIT_FLIST_HEAD(&ipo->list);

	ipo->offset = t->sector * bs;
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
}

static void handle_trace_fs(struct thread_data *td, struct blk_io_trace *t,
			    unsigned long long ttime, unsigned long *ios,
			    unsigned int *rw_bs)
{
	unsigned int bs;
	int rw;
	int fileno;

	fileno = trace_add_file(td, t->device, &bs);

	rw = (t->action & BLK_TC_ACT(BLK_TC_WRITE)) != 0;

	if (t->bytes > rw_bs[rw])
		rw_bs[rw] = t->bytes;

	ios[rw]++;
	td->o.size += t->bytes;
	store_ipo(td, t->sector, t->bytes, rw, ttime, fileno, bs);
}

/*
 * We only care for queue traces, most of the others are side effects
 * due to internal workings of the block layer.
 */
static void handle_trace(struct thread_data *td, struct blk_io_trace *t,
			 unsigned long *ios, unsigned int *bs)
{
	static unsigned long long last_ttime;
	unsigned long long delay = 0;

	if ((t->action & 0xffff) != __BLK_TA_QUEUE)
		return;

	if (!(t->action & BLK_TC_ACT(BLK_TC_NOTIFY))) {
		if (!last_ttime || td->o.no_stall) {
			last_ttime = t->time;
			delay = 0;
		} else {
			delay = t->time - last_ttime;
			last_ttime = t->time;
		}
	}

	t_bytes_align(&td->o, t);

	if (t->action & BLK_TC_ACT(BLK_TC_NOTIFY))
		handle_trace_notify(t);
	else if (t->action & BLK_TC_ACT(BLK_TC_DISCARD))
		handle_trace_discard(td, t, delay, ios, bs);
	else
		handle_trace_fs(td, t, delay, ios, bs);
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

static int t_is_write(struct blk_io_trace *t)
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

/*
 * Load a blktrace file by reading all the blk_io_trace entries, and storing
 * them as io_pieces like the fio text version would do.
 */
int load_blktrace(struct thread_data *td, const char *filename, int need_swap)
{
	struct blk_io_trace t;
	unsigned long ios[DDIR_RWDIR_CNT], skipped_writes;
	unsigned int rw_bs[DDIR_RWDIR_CNT];
	struct fifo *fifo;
	int fd, i, old_state;
	struct fio_file *f;
	int this_depth[DDIR_RWDIR_CNT], depth[DDIR_RWDIR_CNT], max_depth;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		td_verror(td, errno, "open blktrace file");
		return 1;
	}

	fifo = fifo_alloc(TRACE_FIFO_SIZE);

	old_state = td_bump_runstate(td, TD_SETTING_UP);

	td->o.size = 0;

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		ios[i] = 0;
		rw_bs[i] = 0;
		this_depth[i] = 0;
		depth[i] = 0;
	}

	skipped_writes = 0;
	do {
		int ret = trace_fifo_get(td, fifo, fd, &t, sizeof(t));

		if (ret < 0)
			goto err;
		else if (!ret)
			break;
		else if (ret < (int) sizeof(t)) {
			log_err("fio: short fifo get\n");
			break;
		}

		if (need_swap)
			byteswap_trace(&t);

		if ((t.magic & 0xffffff00) != BLK_IO_TRACE_MAGIC) {
			log_err("fio: bad magic in blktrace data: %x\n",
								t.magic);
			goto err;
		}
		if ((t.magic & 0xff) != BLK_IO_TRACE_VERSION) {
			log_err("fio: bad blktrace version %d\n",
								t.magic & 0xff);
			goto err;
		}
		ret = discard_pdu(td, fifo, fd, &t);
		if (ret < 0) {
			td_verror(td, ret, "blktrace lseek");
			goto err;
		} else if (t.pdu_len != ret) {
			log_err("fio: discarded %d of %d\n", ret, t.pdu_len);
			goto err;
		}
		if ((t.action & BLK_TC_ACT(BLK_TC_NOTIFY)) == 0) {
			if ((t.action & 0xffff) == __BLK_TA_QUEUE)
				depth_inc(&t, this_depth);
			else if (((t.action & 0xffff) == __BLK_TA_BACKMERGE) ||
				((t.action & 0xffff) == __BLK_TA_FRONTMERGE))
				depth_dec(&t, this_depth);
			else if ((t.action & 0xffff) == __BLK_TA_COMPLETE)
				depth_end(&t, this_depth, depth);

			if (t_is_write(&t) && read_only) {
				skipped_writes++;
				continue;
			}
		}

		handle_trace(td, &t, ios, rw_bs);
	} while (1);

	for (i = 0; i < td->files_index; i++) {
		f = td->files[i];
		trace_add_open_close_event(td, f->fileno, FIO_LOG_CLOSE_FILE);
	}

	fifo_free(fifo);
	close(fd);

	td_restore_runstate(td, old_state);

	if (!td->files_index) {
		log_err("fio: did not find replay device(s)\n");
		return 1;
	}

	/*
	 * For stacked devices, we don't always get a COMPLETE event so
	 * the depth grows to insane values. Limit it to something sane(r).
	 */
	max_depth = 0;
	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		if (depth[i] > 1024)
			depth[i] = 1024;
		else if (!depth[i] && ios[i])
			depth[i] = 1;
		max_depth = max(depth[i], max_depth);
	}

	if (skipped_writes)
		log_err("fio: %s skips replay of %lu writes due to read-only\n",
						td->o.name, skipped_writes);

	if (!ios[DDIR_READ] && !ios[DDIR_WRITE]) {
		log_err("fio: found no ios in blktrace data\n");
		return 1;
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

	/*
	 * We need to do direct/raw ios to the device, to avoid getting
	 * read-ahead in our way. But only do so if the minimum block size
	 * is a multiple of 4k, otherwise we don't know if it's safe to do so.
	 */
	if (!fio_option_is_set(&td->o, odirect) && !(td_min_bs(td) & 4095))
		td->o.odirect = 1;

	/*
	 * If depth wasn't manually set, use probed depth
	 */
	if (!fio_option_is_set(&td->o, iodepth))
		td->o.iodepth = td->o.iodepth_low = max_depth;

	return 0;
err:
	close(fd);
	fifo_free(fifo);
	return 1;
}
