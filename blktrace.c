/*
 * blktrace support code for fio
 */
#include <stdio.h>
#include <stdlib.h>
#include "list.h"
#include "fio.h"
#include "blktrace_api.h"

static int discard_pdu(int fd, struct blk_io_trace *t)
{
	if (t->pdu_len == 0)
		return 0;

	if (lseek(fd, t->pdu_len, SEEK_CUR) < 0)
		return errno;
		
	return 0;
}

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

static void store_ipo(struct thread_data *td, unsigned long long offset,
		      unsigned int bytes, int rw)
{
	struct io_piece *ipo = malloc(sizeof(*ipo));

	memset(ipo, 0, sizeof(*ipo));
	INIT_LIST_HEAD(&ipo->list);
	ipo->offset = offset;
	ipo->len = bytes;
	if (rw)
		ipo->ddir = DDIR_WRITE;
	else
		ipo->ddir = DDIR_READ;

	list_add_tail(&ipo->list, &td->io_log_list);
}

static void handle_trace(struct thread_data *td, struct blk_io_trace *t)
{
	int rw;

	if ((t->action & 0xffff) != __BLK_TA_QUEUE)
		return;

	rw = (t->action & BLK_TC_ACT(BLK_TC_WRITE)) != 0;
	store_ipo(td, t->sector, t->bytes, rw);
}

int load_blktrace(struct thread_data *td, const char *filename)
{
	struct blk_io_trace t;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		td_verror(td, errno, "open blktrace file");
		return 1;
	}

	do {
		int ret = read(fd, &t, sizeof(t));

		if (ret < 0) {
			td_verror(td, errno, "read blktrace file");
			return 1;
		} else if (!ret) {
			break;
		} else if (ret != sizeof(t)) {
			log_err("fio: short read on blktrace file\n");
			return 1;
		}

		if ((t.magic & 0xffffff00) != BLK_IO_TRACE_MAGIC) {
			log_err("fio: bad magic in blktrace data\n");
			return 1;
		}
		if ((t.magic & 0xff) != BLK_IO_TRACE_VERSION) {
			log_err("fio: bad blktrace version %d\n", t.magic & 0xff);
			return 1;
		}
		ret = discard_pdu(fd, &t);
		if (ret) {
			td_verror(td, ret, "blktrace lseek");
			return 1;
		}
		handle_trace(td, &t);
	} while (1);

	close(fd);
	return 0;
}
