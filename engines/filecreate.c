/*
 * filecreate engine
 *
 * IO engine that doesn't do any IO, just creates files and tracks the latency
 * of the file creation.
 */
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "../fio.h"
#include "../filehash.h"

static int open_file(struct thread_data *td, struct fio_file *f)
{
	struct timespec start, end;
	int from_hash = 0;
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

open_again:
	if (do_lat)
		fio_gettime(&start, NULL);
	from_hash = file_lookup_open(f, O_CREAT|O_RDWR);
	if (do_lat) {
		unsigned long long nsec;

		fio_gettime(&end, NULL);
		nsec = ntime_since(&start, &end);
		add_lat_sample(td, DDIR_WRITE, nsec, 0, 0);
	}

	if (f->fd == -1) {
		char buf[FIO_VERROR_SIZE];
		int e = errno;

		snprintf(buf, sizeof(buf), "open(%s)", f->file_name);
		td_verror(td, e, buf);
	}

	if (!from_hash && f->fd != -1) {
		if (add_file_hash(f)) {
			int fio_unused ret;

			/*
			 * OK to ignore, we haven't done anything with it
			 */
			ret = generic_close_file(td, f);
			goto open_again;
		}
	}

	return 0;
}

static int queue_io(struct thread_data *td, struct io_u fio_unused *io_u)
{
	return FIO_Q_COMPLETED;
}

static struct ioengine_ops ioengine = {
	.name		= "filecreate",
	.version	= FIO_IOOPS_VERSION,
	.open_file	= open_file,
	.queue		= queue_io,
	.close_file	= generic_close_file,
	.flags		= FIO_DISKLESSIO | FIO_SYNCIO | FIO_FAKEIO,
};

static void fio_init fio_filecreate_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_filecreate_unregister(void)
{
	unregister_ioengine(&ioengine);
}
