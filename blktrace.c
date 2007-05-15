/*
 * blktrace support code for fio
 */
#include <stdio.h>
#include <stdlib.h>

#include "list.h"
#include "fio.h"
#include "blktrace_api.h"

/*
 * Just discard the pdu by seeking past it.
 */
static int discard_pdu(int fd, struct blk_io_trace *t)
{
	if (t->pdu_len == 0)
		return 0;

	if (lseek(fd, t->pdu_len, SEEK_CUR) < 0)
		return errno;
		
	return 0;
}

/*
 * Check if this is a blktrace binary data file. We read a single trace
 * into memory and check for the magic signature.
 */
int is_blktrace(const char *filename)
{
	struct blk_io_trace t;
	int fd, ret;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open blktrace");
		return 0;
	}

	ret = read(fd, &t, sizeof(t));
	close(fd);

	if (ret < 0) {
		perror("read blktrace");
		return 0;
	} else if (ret != sizeof(t)) {
		log_err("fio: short read on blktrace file\n");
		return 0;
	}

	if ((t.magic & 0xffffff00) == BLK_IO_TRACE_MAGIC)
		return 1;

	return 0;
}

/*
 * Store blk_io_trace data in an ipo for later retrieval.
 */
static void store_ipo(struct thread_data *td, unsigned long long offset,
		      unsigned int bytes, int rw, unsigned long long ttime)
{
	struct io_piece *ipo = malloc(sizeof(*ipo));

	memset(ipo, 0, sizeof(*ipo));
	INIT_LIST_HEAD(&ipo->list);
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

	list_add_tail(&ipo->list, &td->io_log_list);
}

/*
 * We only care for queue traces, most of the others are side effects
 * due to internal workings of the block layer.
 */
static void handle_trace(struct thread_data *td, struct blk_io_trace *t,
			 unsigned long long ttime, unsigned long *ios)
{
	int rw;

	if ((t->action & 0xffff) != __BLK_TA_QUEUE)
		return;
	if (t->action & BLK_TC_ACT(BLK_TC_PC))
		return;

	/*
	 * should not happen, need to look into that...
	 */
	if (!t->bytes)
		return;

	rw = (t->action & BLK_TC_ACT(BLK_TC_WRITE)) != 0;
	ios[rw]++;
	td->o.size += t->bytes;
	store_ipo(td, t->sector, t->bytes, rw, ttime);
}

/*
 * Load a blktrace file by reading all the blk_io_trace entries, and storing
 * them as io_pieces like the fio text version would do.
 */
int load_blktrace(struct thread_data *td, const char *filename)
{
	unsigned long long ttime;
	struct blk_io_trace t;
	unsigned long ios[2];
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		td_verror(td, errno, "open blktrace file");
		return 1;
	}

	td->o.size = 0;

	ios[0] = ios[1] = 0;
	ttime = 0;
	do {
		/*
		 * Once this is working fully, I'll add a layer between
		 * here and read to cache trace data. Then we can avoid
		 * doing itsy bitsy reads, but instead pull in a larger
		 * chunk of data at the time.
		 */
		int ret = read(fd, &t, sizeof(t));

		if (ret < 0) {
			td_verror(td, errno, "read blktrace file");
			goto err;
		} else if (!ret) {
			break;
		} else if (ret != sizeof(t)) {
			log_err("fio: short read on blktrace file\n");
			goto err;
		}

		if ((t.magic & 0xffffff00) != BLK_IO_TRACE_MAGIC) {
			log_err("fio: bad magic in blktrace data\n");
			goto err;
		}
		if ((t.magic & 0xff) != BLK_IO_TRACE_VERSION) {
			log_err("fio: bad blktrace version %d\n", t.magic & 0xff);
			goto err;
		}
		ret = discard_pdu(fd, &t);
		if (ret) {
			td_verror(td, ret, "blktrace lseek");
			goto err;
		}
		if (!ttime)
			ttime = t.time;
		handle_trace(td, &t, t.time - ttime, ios);
		ttime = t.time;
	} while (1);

	close(fd);

	if (!ios[DDIR_READ] && !ios[DDIR_WRITE]) {
		log_err("fio: found no ios in blktrace data\n");
		return 1;
	} else if (ios[DDIR_READ] && !ios[DDIR_READ])
		td->o.td_ddir = TD_DDIR_READ;
	else if (!ios[DDIR_READ] && ios[DDIR_WRITE])
		td->o.td_ddir = TD_DDIR_WRITE;
	else
		td->o.td_ddir = TD_DDIR_RW;

	/*
	 * We need to do direct/raw ios to the device, to avoid getting
	 * read-ahead in our way.
	 */
	td->o.odirect = 1;

	return 0;
err:
	close(fd);
	return 1;
}
