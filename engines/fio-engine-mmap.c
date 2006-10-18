/*
 * regular read/write sync io engine
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/mman.h>
#include "fio.h"
#include "os.h"

struct mmapio_data {
	struct io_u *last_io_u;
};

static int fio_mmapio_getevents(struct thread_data *td, int fio_unused min,
				int max, struct timespec fio_unused *t)
{
	assert(max <= 1);

	/*
	 * we can only have one finished io_u for sync io, since the depth
	 * is always 1
	 */
	if (list_empty(&td->io_u_busylist))
		return 0;

	return 1;
}

static struct io_u *fio_mmapio_event(struct thread_data *td, int event)
{
	struct mmapio_data *sd = td->io_ops->data;

	assert(event == 0);

	return sd->last_io_u;
}


static int fio_mmapio_queue(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	unsigned long long real_off = io_u->offset - f->file_offset;
	struct mmapio_data *sd = td->io_ops->data;

	if (io_u->ddir == DDIR_READ)
		memcpy(io_u->buf, f->mmap + real_off, io_u->buflen);
	else
		memcpy(f->mmap + real_off, io_u->buf, io_u->buflen);

	/*
	 * not really direct, but should drop the pages from the cache
	 */
	if (td->odirect) {
		if (msync(f->mmap + real_off, io_u->buflen, MS_SYNC) < 0)
			io_u->error = errno;
		if (madvise(f->mmap + real_off, io_u->buflen,  MADV_DONTNEED) < 0)
			io_u->error = errno;
	}

	if (!io_u->error)
		sd->last_io_u = io_u;

	return io_u->error;
}

static int fio_mmapio_sync(struct thread_data *td, struct fio_file *f)
{
	return msync(f->mmap, f->file_size, MS_SYNC);
}

static void fio_mmapio_cleanup(struct thread_data *td)
{
	if (td->io_ops->data) {
		free(td->io_ops->data);
		td->io_ops->data = NULL;
	}
}

static int fio_mmapio_init(struct thread_data *td)
{
	struct mmapio_data *sd = malloc(sizeof(*sd));

	sd->last_io_u = NULL;
	td->io_ops->data = sd;
	return 0;
}

struct ioengine_ops ioengine = {
	.name		= "mmap",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_mmapio_init,
	.queue		= fio_mmapio_queue,
	.getevents	= fio_mmapio_getevents,
	.event		= fio_mmapio_event,
	.cleanup	= fio_mmapio_cleanup,
	.sync		= fio_mmapio_sync,
	.flags		= FIO_SYNCIO,
};
