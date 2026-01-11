/*
 * file/directory operations engine
 *
 * IO engine that doesn't do any IO, just operates files/directories
 * and tracks the latency of the operation.
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

enum fio_engine {
	UNKNOWN_OP_ENGINE = 0,
	FILE_OP_ENGINE = 1,
	DIR_OP_ENGINE = 2,
};

struct fc_data {
	enum fio_ddir stat_ddir;
	enum fio_engine op_engine;
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

static int open_file(struct thread_data *td, struct fio_file *f)
{
	struct timespec start;
	int do_lat = !td->o.disable_lat;
	struct fc_data *fcd = td->io_ops_data;

	dprint(FD_FILE, "fd open %s\n", f->file_name);

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

	if (fcd->op_engine == FILE_OP_ENGINE)
		f->fd = open(f->file_name, O_CREAT|O_RDWR, 0600);
	else if (fcd->op_engine == DIR_OP_ENGINE)
		f->fd = fio_mkdir(f->file_name, S_IFDIR);
	else {
		log_err("fio: unknown file/directory operation engine\n");
		return 1;
	}

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
		add_clat_sample(td, data->stat_ddir, nsec, 0, NULL);
	}

	return 0;
}

static int stat_file(struct thread_data *td, struct fio_file *f)
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

	dprint(FD_FILE, "fd stat %s\n", f->file_name);

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
		add_clat_sample(td, data->stat_ddir, nsec, 0, NULL);
	}

	return 0;
}

static int delete_file(struct thread_data *td, struct fio_file *f)
{
	struct timespec start;
	int do_lat = !td->o.disable_lat;
	struct fc_data *fcd = td->io_ops_data;
	int ret;

	dprint(FD_FILE, "fd delete %s\n", f->file_name);

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

	if (fcd->op_engine == FILE_OP_ENGINE)
		ret = unlink(f->file_name);
	else if (fcd->op_engine == DIR_OP_ENGINE)
		ret = rmdir(f->file_name);
	else {
		log_err("fio: unknown file/directory operation engine\n");
		return 1;
	}

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
		add_clat_sample(td, data->stat_ddir, nsec, 0, NULL);
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
	if (io_u->ddir == DDIR_SYNC && do_io_u_sync(td, io_u))
		io_u->error = errno;
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

	data->op_engine = UNKNOWN_OP_ENGINE;

	if (!strncmp(td->o.ioengine, "file", 4)) {
		data->op_engine = FILE_OP_ENGINE;
		dprint(FD_FILE, "Operate engine type: file\n");
	}
	if (!strncmp(td->o.ioengine, "dir", 3)) {
		data->op_engine = DIR_OP_ENGINE;
		dprint(FD_FILE, "Operate engine type: directory\n");
	}

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

static struct ioengine_ops ioengine_filecreate = {
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

static struct ioengine_ops ioengine_filestat = {
	.name		= "filestat",
	.version	= FIO_IOOPS_VERSION,
	.init		= init,
	.cleanup	= cleanup,
	.queue		= queue_io,
	.invalidate	= invalidate_do_nothing,
	.get_file_size	= generic_get_file_size,
	.open_file	= stat_file,
	.flags		=  FIO_SYNCIO | FIO_FAKEIO |
				FIO_NOSTATS | FIO_NOFILEHASH,
	.options	= options,
	.option_struct_size = sizeof(struct filestat_options),
};

static struct ioengine_ops ioengine_filedelete = {
	.name		= "filedelete",
	.version	= FIO_IOOPS_VERSION,
	.init		= init,
	.invalidate	= invalidate_do_nothing,
	.cleanup	= cleanup,
	.queue		= queue_io,
	.get_file_size	= generic_get_file_size,
	.open_file	= delete_file,
	.flags		=  FIO_SYNCIO | FIO_FAKEIO |
				FIO_NOSTATS | FIO_NOFILEHASH,
};

static struct ioengine_ops ioengine_dircreate = {
	.name		= "dircreate",
	.version	= FIO_IOOPS_VERSION,
	.init		= init,
	.cleanup	= cleanup,
	.queue		= queue_io,
	.get_file_size	= get_file_size,
	.open_file	= open_file,
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
	.open_file	= stat_file,
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
	.open_file	= delete_file,
	.unlink_file	= remove_dir,
	.flags		= FIO_DISKLESSIO | FIO_SYNCIO | FIO_FAKEIO |
				FIO_NOSTATS | FIO_NOFILEHASH,
};

static void fio_init fio_fileoperations_register(void)
{
	register_ioengine(&ioengine_filecreate);
	register_ioengine(&ioengine_filestat);
	register_ioengine(&ioengine_filedelete);
	register_ioengine(&ioengine_dircreate);
	register_ioengine(&ioengine_dirstat);
	register_ioengine(&ioengine_dirdelete);
}

static void fio_exit fio_fileoperations_unregister(void)
{
	unregister_ioengine(&ioengine_filecreate);
	unregister_ioengine(&ioengine_filestat);
	unregister_ioengine(&ioengine_filedelete);
	unregister_ioengine(&ioengine_dircreate);
	unregister_ioengine(&ioengine_dirstat);
	unregister_ioengine(&ioengine_dirdelete);
}
