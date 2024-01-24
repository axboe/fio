/*
 * directory operations engine
 *
 * IO engine that doesn't do any IO, just operates directories
 * and tracks the latency of the directory operation.
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../fio.h"
#include "../optgroup.h"
#include "../oslib/statx.h"


struct fc_data {
	enum fio_ddir stat_ddir;
};

struct filestat_options {
	void *pad;
	unsigned int stat_type;
};

enum {
	FIO_FILESTAT_STAT	= 1,
	FIO_FILESTAT_LSTAT	= 2,
	FIO_FILESTAT_STATX	= 3,
};

static struct fio_option options[] = {
	{
		.name	= "stat_type",
		.lname	= "stat_type",
		.type	= FIO_OPT_STR,
		.off1	= offsetof(struct filestat_options, stat_type),
		.help	= "Specify stat system call type to measure lookup/getattr performance",
		.def	= "stat",
		.posval = {
			  { .ival = "stat",
			    .oval = FIO_FILESTAT_STAT,
			    .help = "Use stat(2)",
			  },
			  { .ival = "lstat",
			    .oval = FIO_FILESTAT_LSTAT,
			    .help = "Use lstat(2)",
			  },
			  { .ival = "statx",
			    .oval = FIO_FILESTAT_STATX,
			    .help = "Use statx(2) if exists",
			  },
		},
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_FILESTAT,
	},
	{
		.name	= NULL,
	},
};

static int setup_dirs(struct thread_data *td)
{
	int ret = 0;
	int i;
	struct fio_file *f;

	for_each_file(td, f, i) {
		dprint(FD_FILE, "setup directory %s\n", f->file_name);
		ret = fio_mkdir(f->file_name, 0700);
		if ((ret && errno != EEXIST)) {
			log_err("create directory %s failed with %d\n",
				f->file_name, errno);
			break;
		}
		ret = 0;
	}
	return ret;
}

static int create_dir(struct thread_data *td, struct fio_file *f)
{
	struct timespec start;
	int do_lat = !td->o.disable_lat;

	dprint(FD_FILE, "create directory: %s\n", f->file_name);

	if (f->filetype != FIO_TYPE_FILE) {
		log_err("fio: only files are supported\n");
		return 1;
	}
	if (!strcmp(f->file_name, "-")) {
		log_err("fio: can't read/write to stdin/out\n");
		return 1;
	}

	if (do_lat)
		fio_gettime(&start, NULL);

	f->fd = fio_mkdir(f->file_name, 0700);

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
		add_clat_sample(td, data->stat_ddir, nsec, 0, 0, 0, 0);
	}

	return 0;
}

static int stat_dir(struct thread_data *td, struct fio_file *f)
{
	struct filestat_options *o = td->eo;
	struct timespec start;
	int do_lat = !td->o.disable_lat;
	struct stat statbuf;
#ifndef WIN32
	struct statx statxbuf;
	char *abspath;
#endif
	int ret;

	dprint(FD_FILE, "dir stat %s\n", f->file_name);

	if (f->filetype != FIO_TYPE_FILE) {
		log_err("fio: only files are supported\n");
		return 1;
	}
	if (!strcmp(f->file_name, "-")) {
		log_err("fio: can't read/write to stdin/out\n");
		return 1;
	}

	if (do_lat)
		fio_gettime(&start, NULL);

	switch (o->stat_type) {
	case FIO_FILESTAT_STAT:
		ret = stat(f->file_name, &statbuf);
		break;
	case FIO_FILESTAT_LSTAT:
		ret = lstat(f->file_name, &statbuf);
		break;
	case FIO_FILESTAT_STATX:
#ifndef WIN32
		abspath = realpath(f->file_name, NULL);
		if (abspath) {
			ret = statx(-1, abspath, 0, STATX_ALL, &statxbuf);
			free(abspath);
		} else
			ret = -1;
#else
		ret = -1;
#endif
		break;
	default:
		ret = -1;
		break;
	}

	if (ret == -1) {
		char buf[FIO_VERROR_SIZE];
		int e = errno;

		snprintf(buf, sizeof(buf), "stat(%s) type=%u", f->file_name,
			o->stat_type);
		td_verror(td, e, buf);
		return 1;
	}

	if (do_lat) {
		struct fc_data *data = td->io_ops_data;
		uint64_t nsec;

		nsec = ntime_since_now(&start);
		add_clat_sample(td, data->stat_ddir, nsec, 0, 0, 0, 0);
	}

	return 0;
}


static int delete_dir(struct thread_data *td, struct fio_file *f)
{
	struct timespec start;
	int do_lat = !td->o.disable_lat;
	int ret;

	dprint(FD_FILE, "dir delete %s\n", f->file_name);

	if (f->filetype != FIO_TYPE_FILE) {
		log_err("fio: only files are supported\n");
		return 1;
	}
	if (!strcmp(f->file_name, "-")) {
		log_err("fio: can't read/write to stdin/out\n");
		return 1;
	}

	if (do_lat)
		fio_gettime(&start, NULL);

	ret = rmdir(f->file_name);

	if (ret == -1) {
		char buf[FIO_VERROR_SIZE];
		int e = errno;

		snprintf(buf, sizeof(buf), "delete(%s)", f->file_name);
		td_verror(td, e, buf);
		return 1;
	}

	if (do_lat) {
		struct fc_data *data = td->io_ops_data;
		uint64_t nsec;

		nsec = ntime_since_now(&start);
		add_clat_sample(td, data->stat_ddir, nsec, 0, 0, 0, 0);
	}

	return 0;
}

static int invalidate_do_nothing(struct thread_data *td, struct fio_file *f)
{
	/* do nothing because file not opened */
	return 0;
}

static enum fio_q_status queue_io(struct thread_data *td, struct io_u *io_u)
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

static int remove_dir(struct thread_data *td, struct fio_file *f)
{
	dprint(FD_FILE, "remove directory %s\n", f->file_name);
	return rmdir(f->file_name);
}

static struct ioengine_ops ioengine_dircreate = {
	.name		= "dircreate",
	.version	= FIO_IOOPS_VERSION,
	.init		= init,
	.cleanup	= cleanup,
	.queue		= queue_io,
	.get_file_size	= get_file_size,
	.open_file	= create_dir,
	.close_file	= generic_close_file,
	.unlink_file    = remove_dir,
	.flags		= FIO_DISKLESSIO | FIO_SYNCIO | FIO_FAKEIO |
				FIO_NOSTATS | FIO_NOFILEHASH,
};

static struct ioengine_ops ioengine_dirstat = {
	.name		= "dirstat",
	.version	= FIO_IOOPS_VERSION,
	.setup		= setup_dirs,
	.init		= init,
	.cleanup	= cleanup,
	.queue		= queue_io,
	.invalidate	= invalidate_do_nothing,
	.get_file_size	= generic_get_file_size,
	.open_file	= stat_dir,
	.unlink_file	= remove_dir,
	.flags		=  FIO_DISKLESSIO | FIO_SYNCIO | FIO_FAKEIO |
				FIO_NOSTATS | FIO_NOFILEHASH,
	.options	= options,
	.option_struct_size = sizeof(struct filestat_options),
};

static struct ioengine_ops ioengine_dirdelete = {
	.name		= "dirdelete",
	.version	= FIO_IOOPS_VERSION,
	.setup		= setup_dirs,
	.init		= init,
	.invalidate	= invalidate_do_nothing,
	.cleanup	= cleanup,
	.queue		= queue_io,
	.get_file_size	= get_file_size,
	.open_file	= delete_dir,
	.unlink_file	= remove_dir,
	.flags		= FIO_DISKLESSIO | FIO_SYNCIO | FIO_FAKEIO |
				FIO_NOSTATS | FIO_NOFILEHASH,
};


static void fio_init fio_fileoperations_register(void)
{
	register_ioengine(&ioengine_dircreate);
	register_ioengine(&ioengine_dirstat);
	register_ioengine(&ioengine_dirdelete);
}

static void fio_exit fio_fileoperations_unregister(void)
{
	unregister_ioengine(&ioengine_dircreate);
	unregister_ioengine(&ioengine_dirstat);
	unregister_ioengine(&ioengine_dirdelete);
}
