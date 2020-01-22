/*
 * filecreate engine
 *
 * IO engine that doesn't do any IO, just creates files and tracks the latency
 * of the file creation.
 */
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

#include "../fio.h"

struct fc_data {
	enum fio_ddir stat_ddir;
};

static int open_file(struct thread_data *td, struct fio_file *f)
{
	struct timespec start;
	int do_lat = !td->o.disable_lat;

	dprint(FD_FILE, "fd open %s\n", f->file_name);

	if (f->filetype != FIO_TYPE_FILE) {
		log_err("fio: only files are supported fallocate \n");
		return 1;
	}
	if (!strcmp(f->file_name, "-")) {
		log_err("fio: can't read/write to stdin/out\n");
		return 1;
	}

	if (do_lat)
		fio_gettime(&start, NULL);

	f->fd = open(f->file_name, O_CREAT|O_RDWR, 0600);

	if (f->fd == -1) {
		char buf[FIO_VERROR_SIZE];
		int e = errno;

		snprintf(buf, sizeof(buf), "open(%s)", f->file_name);
		td_verror(td, e, buf);
		return 1;
	}

	if (do_lat) {
		struct fc_data *data = td->io_ops_data;
		uint64_t nsec;

		nsec = ntime_since_now(&start);
		add_clat_sample(td, data->stat_ddir, nsec, 0, 0, 0);
	}

	return 0;
}

static enum fio_q_status queue_io(struct thread_data *td,
				  struct io_u fio_unused *io_u)
{
	return FIO_Q_COMPLETED;
}

/*
 * Ensure that we at least have a block size worth of IO to do for each
 * file. If the job file has td->o.size < nr_files * block_size, then
 * fio won't do anything.
 */
static int get_file_size(struct thread_data *td, struct fio_file *f)
{
	f->real_file_size = td_min_bs(td);
	return 0;
}

static int init(struct thread_data *td)
{
	struct fc_data *data;

	data = calloc(1, sizeof(*data));

	if (td_read(td))
		data->stat_ddir = DDIR_READ;
	else if (td_write(td))
		data->stat_ddir = DDIR_WRITE;

	td->io_ops_data = data;
	return 0;
}

static void cleanup(struct thread_data *td)
{
	struct fc_data *data = td->io_ops_data;

	free(data);
}

static struct ioengine_ops ioengine = {
	.name		= "filecreate",
	.version	= FIO_IOOPS_VERSION,
	.init		= init,
	.cleanup	= cleanup,
	.queue		= queue_io,
	.get_file_size	= get_file_size,
	.open_file	= open_file,
	.close_file	= generic_close_file,
	.flags		= FIO_DISKLESSIO | FIO_SYNCIO | FIO_FAKEIO |
				FIO_NOSTATS | FIO_NOFILEHASH,
};

static void fio_init fio_filecreate_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_filecreate_unregister(void)
{
	unregister_ioengine(&ioengine);
}
