/*
 * filestat engine
 *
 * IO engine that doesn't do any IO, just stat files and tracks the latency
 * of the file stat.
 */
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../fio.h"
#include "../optgroup.h"

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
	/*FIO_FILESTAT_STATX	= 3,*/
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
			  /*
			  { .ival = "statx",
			    .oval = FIO_FILESTAT_STATX,
			    .help = "Use statx(2)",
			  },
			  */
		},
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_FILESTAT,
	},
	{
		.name	= NULL,
	},
};

static int stat_file(struct thread_data *td, struct fio_file *f)
{
	struct filestat_options *o = td->eo;
	struct timespec start;
	int do_lat = !td->o.disable_lat;
	struct stat statbuf;
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

	switch (o->stat_type){
	case FIO_FILESTAT_STAT:
		ret = stat(f->file_name, &statbuf);
		break;
	case FIO_FILESTAT_LSTAT:
		ret = lstat(f->file_name, &statbuf);
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
		add_clat_sample(td, data->stat_ddir, nsec, 0, 0, 0);
	}

	return 0;
}

static enum fio_q_status queue_io(struct thread_data *td, struct io_u fio_unused *io_u)
{
	return FIO_Q_COMPLETED;
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

static int stat_invalidate(struct thread_data *td, struct fio_file *f)
{
	/* do nothing because file not opened */
	return 0;
}

static struct ioengine_ops ioengine = {
	.name		= "filestat",
	.version	= FIO_IOOPS_VERSION,
	.init		= init,
	.cleanup	= cleanup,
	.queue		= queue_io,
	.invalidate	= stat_invalidate,
	.get_file_size	= generic_get_file_size,
	.open_file	= stat_file,
	.flags		=  FIO_SYNCIO | FIO_FAKEIO |
				FIO_NOSTATS | FIO_NOFILEHASH,
	.options	= options,
	.option_struct_size = sizeof(struct filestat_options),
};

static void fio_init fio_filestat_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_filestat_unregister(void)
{
	unregister_ioengine(&ioengine);
}
