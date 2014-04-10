/*
 * blktrace support code for fio
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <dirent.h>

#include "flist.h"
#include "fio.h"
#include "blktrace_api.h"

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

static int lookup_device(struct thread_data *td, char *path, unsigned int maj,
			 unsigned int min)
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

		sprintf(full_path, "%s%s%s", path, FIO_OS_PATH_SEPARATOR, dir->d_name);
		if (lstat(full_path, &st) == -1) {
			perror("lstat");
			break;
		}

		if (S_ISDIR(st.st_mode)) {
			found = lookup_device(td, full_path, maj, min);
			if (found) {
				strcpy(path, full_path);
				break;
			}
		}

		if (!S_ISBLK(st.st_mode))
			continue;

		/*
		 * If replay_redirect is set then always return this device
		 * upon lookup which overrides the device lookup based on
		 * major minor in the actual blktrace
		 */
		if (td->o.replay_redirect) {
			dprint(FD_BLKTRACE, "device lookup: %d/%d\n overridden"
					" with: %s\n", maj, min,
					td->o.replay_redirect);
			strcpy(path, td->o.replay_redirect);
			found = 1;
			break;
		}

		if (maj == major(st.st_rdev) && min == minor(st.st_rdev)) {
			dprint(FD_BLKTRACE, "device lookup: %d/%d\n", maj, min);
			strcpy(path, full_path);
			found = 1;
			break;
		}
	}

	closedir(D);
	return found;
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
	if (lookup_device(td, dev, maj, min)) {
		int fileno;

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

/*
 * Store blk_io_trace data in an ipo for later retrieval.
 */
static void store_ipo(struct thread_data *td, unsigned long long offset,
		      unsigned int bytes, int rw, unsigned long long ttime,
		      int fileno)
{
	struct io_piece *ipo = malloc(sizeof(*ipo));

	init_ipo(ipo);

	/*
	 * the 512 is wrong here, it should be the hardware sector size...
	 */
	ipo->offset = offset * 512;
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
		log_info("blktrace: got process notify: %x, %d\n",
				t->action, t->pid);
		break;
	case BLK_TN_TIMESTAMP:
		log_info("blktrace: got timestamp notify: %x, %d\n",
				t->action, t->pid);
		break;
	case BLK_TN_MESSAGE:
		break;
	default:
		dprint(FD_BLKTRACE, "unknown trace act %x\n", t->action);
		break;
	}
}

static void handle_trace_discard(struct thread_data *td, struct blk_io_trace *t,
				 unsigned long long ttime, unsigned long *ios)
{
	struct io_piece *ipo = malloc(sizeof(*ipo));
	int fileno;

	init_ipo(ipo);
	fileno = trace_add_file(td, t->device);

	ios[DDIR_WRITE]++;
	td->o.size += t->bytes;

	memset(ipo, 0, sizeof(*ipo));
	INIT_FLIST_HEAD(&ipo->list);

	/*
	 * the 512 is wrong here, it should be the hardware sector size...
	 */
	ipo->offset = t->sector * 512;
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
			    unsigned int *bs)
{
	int rw;
	int fileno;

	fileno = trace_add_file(td, t->device);

	rw = (t->action & BLK_TC_ACT(BLK_TC_WRITE)) != 0;

	if (t->bytes > bs[rw])
		bs[rw] = t->bytes;

	ios[rw]++;
	td->o.size += t->bytes;
	store_ipo(td, t->sector, t->bytes, rw, ttime, fileno);
}

/*
 * We only care for queue traces, most of the others are side effects
 * due to internal workings of the block layer.
 */
static void handle_trace(struct thread_data *td, struct blk_io_trace *t,
			 unsigned long long ttime, unsigned long *ios,
			 unsigned int *bs)
{
	if ((t->action & 0xffff) != __BLK_TA_QUEUE)
		return;
	if (t->action & BLK_TC_ACT(BLK_TC_PC))
		return;

	if (t->action & BLK_TC_ACT(BLK_TC_NOTIFY))
		handle_trace_notify(t);
	else if (t->action & BLK_TC_ACT(BLK_TC_DISCARD))
		handle_trace_discard(td, t, ttime, ios);
	else
		handle_trace_fs(td, t, ttime, ios, bs);
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

/*
 * Load a blktrace file by reading all the blk_io_trace entries, and storing
 * them as io_pieces like the fio text version would do.
 */
int load_blktrace(struct thread_data *td, const char *filename, int need_swap)
{
	unsigned long long ttime, delay;
	struct blk_io_trace t;
	unsigned long ios[2], skipped_writes;
	unsigned int cpu;
	unsigned int rw_bs[2];
	struct fifo *fifo;
	int fd, i, old_state;
	struct fio_file *f;
	int this_depth, depth;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		td_verror(td, errno, "open blktrace file");
		return 1;
	}

	fifo = fifo_alloc(TRACE_FIFO_SIZE);

	old_state = td_bump_runstate(td, TD_SETTING_UP);

	td->o.size = 0;

	cpu = 0;
	ttime = 0;
	ios[0] = ios[1] = 0;
	rw_bs[0] = rw_bs[1] = 0;
	skipped_writes = 0;
	this_depth = depth = 0;
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
				this_depth++;
			else if ((t.action & 0xffff) == __BLK_TA_COMPLETE) {
				depth = max(depth, this_depth);
				this_depth = 0;
			}
			if (!ttime) {
				ttime = t.time;
				cpu = t.cpu;
			}

			delay = 0;
			if (cpu == t.cpu)
				delay = t.time - ttime;
			if ((t.action & BLK_TC_ACT(BLK_TC_WRITE)) && read_only)
				skipped_writes++;
			else {
				/*
				 * set delay to zero if no_stall enabled for
				 * fast replay
				 */
				if (td->o.no_stall)
					delay = 0;

				handle_trace(td, &t, delay, ios, rw_bs);
			}

			ttime = t.time;
			cpu = t.cpu;
		} else {
			delay = 0;
			handle_trace(td, &t, delay, ios, rw_bs);
		}
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
	if (!depth || depth > 1024)
		depth = 1024;

	if (skipped_writes)
		log_err("fio: %s skips replay of %lu writes due to read-only\n",
						td->o.name, skipped_writes);

	if (!ios[DDIR_READ] && !ios[DDIR_WRITE]) {
		log_err("fio: found no ios in blktrace data\n");
		return 1;
	} else if (ios[DDIR_READ] && !ios[DDIR_READ]) {
		td->o.td_ddir = TD_DDIR_READ;
		td->o.max_bs[DDIR_READ] = rw_bs[DDIR_READ];
	} else if (!ios[DDIR_READ] && ios[DDIR_WRITE]) {
		td->o.td_ddir = TD_DDIR_WRITE;
		td->o.max_bs[DDIR_WRITE] = rw_bs[DDIR_WRITE];
	} else {
		td->o.td_ddir = TD_DDIR_RW;
		td->o.max_bs[DDIR_READ] = rw_bs[DDIR_READ];
		td->o.max_bs[DDIR_WRITE] = rw_bs[DDIR_WRITE];
	}

	/*
	 * We need to do direct/raw ios to the device, to avoid getting
	 * read-ahead in our way.
	 */
	td->o.odirect = 1;

	/*
	 * we don't know if this option was set or not. it defaults to 1,
	 * so we'll just guess that we should override it if it's still 1
	 */
	if (td->o.iodepth != 1)
		td->o.iodepth = depth;

	return 0;
err:
	close(fd);
	fifo_free(fifo);
	return 1;
}
