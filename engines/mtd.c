/*
 * MTD engine
 *
 * IO engine that reads/writes from MTD character devices.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <mtd/mtd-user.h>

#include "../fio.h"
#include "../optgroup.h"
#include "../oslib/libmtd.h"

static libmtd_t desc;

struct fio_mtd_data {
	struct mtd_dev_info info;
};

struct fio_mtd_options {
	void *pad; /* avoid off1 == 0 */
	unsigned int skip_bad;
};

static struct fio_option options[] = {
	{
		.name	= "skip_bad",
		.lname	= "Skip operations against bad blocks",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct fio_mtd_options, skip_bad),
		.help	= "Skip operations against known bad blocks.",
		.hide	= 1,
		.def	= "0",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_MTD,
	},
	{
		.name	= NULL,
	},
};

static int fio_mtd_maybe_mark_bad(struct thread_data *td,
				  struct fio_mtd_data *fmd,
				  struct io_u *io_u, int eb)
{
	int ret;
	if (errno == EIO) {
		ret = mtd_mark_bad(&fmd->info, io_u->file->fd, eb);
		if (ret != 0) {
			io_u->error = errno;
			td_verror(td, errno, "mtd_mark_bad");
			return -1;
		}
	}
	return 0;
}

static int fio_mtd_is_bad(struct thread_data *td,
			  struct fio_mtd_data *fmd,
			  struct io_u *io_u, int eb)
{
	int ret = mtd_is_bad(&fmd->info, io_u->file->fd, eb);
	if (ret == -1) {
		io_u->error = errno;
		td_verror(td, errno, "mtd_is_bad");
	} else if (ret == 1)
		io_u->error = EIO;	/* Silent failure--don't flood stderr */
	return ret;
}

static enum fio_q_status fio_mtd_queue(struct thread_data *td,
				       struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	struct fio_mtd_data *fmd = FILE_ENG_DATA(f);
	struct fio_mtd_options *o = td->eo;
	int local_offs = 0;
	int ret;

	fio_ro_check(td, io_u);

	/*
	 * Errors tend to pertain to particular erase blocks, so divide up
	 * I/O to erase block size.
	 * If an error is encountered, log it and keep going onto the next
	 * block because the error probably just pertains to that block.
	 * TODO(dehrenberg): Divide up reads and writes into page-sized
	 * operations to get more fine-grained information about errors.
	 */
	while (local_offs < io_u->buflen) {
		int eb = (io_u->offset + local_offs) / fmd->info.eb_size;
		int eb_offs = (io_u->offset + local_offs) % fmd->info.eb_size;
		/* The length is the smaller of the length remaining in the
		 * buffer and the distance to the end of the erase block */
		int len = min((int)io_u->buflen - local_offs,
			      (int)fmd->info.eb_size - eb_offs);
		char *buf = ((char *)io_u->buf) + local_offs;

		if (o->skip_bad) {
			ret = fio_mtd_is_bad(td, fmd, io_u, eb);
			if (ret == -1)
				break;
			else if (ret == 1)
				goto next;
		}
		if (io_u->ddir == DDIR_READ) {
			ret = mtd_read(&fmd->info, f->fd, eb, eb_offs, buf, len);
			if (ret != 0) {
				io_u->error = errno;
				td_verror(td, errno, "mtd_read");
				if (fio_mtd_maybe_mark_bad(td, fmd, io_u, eb))
					break;
			}
		} else if (io_u->ddir == DDIR_WRITE) {
			ret = mtd_write(desc, &fmd->info, f->fd, eb,
					    eb_offs, buf, len, NULL, 0, 0);
			if (ret != 0) {
				io_u->error = errno;
				td_verror(td, errno, "mtd_write");
				if (fio_mtd_maybe_mark_bad(td, fmd, io_u, eb))
					break;
			}
		} else if (io_u->ddir == DDIR_TRIM) {
			if (eb_offs != 0 || len != fmd->info.eb_size) {
				io_u->error = EINVAL;
				td_verror(td, EINVAL,
					  "trim on MTD must be erase block-aligned");
			}
			ret = mtd_erase(desc, &fmd->info, f->fd, eb);
			if (ret != 0) {
				io_u->error = errno;
				td_verror(td, errno, "mtd_erase");
				if (fio_mtd_maybe_mark_bad(td, fmd, io_u, eb))
					break;
			}
		} else {
			io_u->error = ENOTSUP;
			td_verror(td, io_u->error, "operation not supported on mtd");
		}

next:
		local_offs += len;
	}

	return FIO_Q_COMPLETED;
}

static int fio_mtd_open_file(struct thread_data *td, struct fio_file *f)
{
	struct fio_mtd_data *fmd;
	int ret;

	ret = generic_open_file(td, f);
	if (ret)
		return ret;

	fmd = calloc(1, sizeof(*fmd));
	if (!fmd)
		goto err_close;

	ret = mtd_get_dev_info(desc, f->file_name, &fmd->info);
	if (ret != 0) {
		td_verror(td, errno, "mtd_get_dev_info");
		goto err_free;
	}

	FILE_SET_ENG_DATA(f, fmd);
	return 0;

err_free:
	free(fmd);
err_close:
	{
		int fio_unused __ret;
		__ret = generic_close_file(td, f);
		return 1;
	}
}

static int fio_mtd_close_file(struct thread_data *td, struct fio_file *f)
{
	struct fio_mtd_data *fmd = FILE_ENG_DATA(f);

	FILE_SET_ENG_DATA(f, NULL);
	free(fmd);

	return generic_close_file(td, f);
}

static int fio_mtd_get_file_size(struct thread_data *td, struct fio_file *f)
{
	struct mtd_dev_info info;

	int ret = mtd_get_dev_info(desc, f->file_name, &info);
	if (ret != 0) {
		td_verror(td, errno, "mtd_get_dev_info");
		return errno;
	}
	f->real_file_size = info.size;

	return 0;
}

static struct ioengine_ops ioengine = {
	.name		= "mtd",
	.version	= FIO_IOOPS_VERSION,
	.queue		= fio_mtd_queue,
	.open_file	= fio_mtd_open_file,
	.close_file	= fio_mtd_close_file,
	.get_file_size	= fio_mtd_get_file_size,
	.flags		= FIO_SYNCIO | FIO_NOEXTEND,
	.options	= options,
	.option_struct_size	= sizeof(struct fio_mtd_options),
};

static void fio_init fio_mtd_register(void)
{
	desc = libmtd_open();
	register_ioengine(&ioengine);
}

static void fio_exit fio_mtd_unregister(void)
{
	unregister_ioengine(&ioengine);
	libmtd_close(desc);
	desc = NULL;
}



