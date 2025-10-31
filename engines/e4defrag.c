/*
 * ioe_e4defrag:  ioengine for https://git.kernel.org/pub/scm/linux/kernel/git/axboe/fio
 *
 * IO engine that does regular EXT4_IOC_MOVE_EXT ioctls to simulate
 * defragment activity
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>

#include "../fio.h"
#include "../optgroup.h"

#ifndef EXT4_IOC_MOVE_EXT
#define EXT4_IOC_MOVE_EXT               _IOWR('f', 15, struct move_extent)
struct move_extent {
	__u32 reserved;         /* should be zero */
	__u32 donor_fd;         /* donor file descriptor */
	__u64 orig_start;       /* logical start offset in block for orig */
	__u64 donor_start;      /* logical start offset in block for donor */
	__u64 len;              /* block length to be moved */
	__u64 moved_len;        /* moved block length */
};
#endif

struct e4defrag_data {
	int donor_fd;
	int bsz;
};

struct e4defrag_options {
	void *pad;
	unsigned int inplace;
	char * donor_name;
};

static struct fio_option options[] = {
	{
		.name	= "donorname",
		.lname	= "Donor Name",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct e4defrag_options, donor_name),
		.help	= "File used as a block donor",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_E4DEFRAG,
	},
	{
		.name	= "inplace",
		.lname	= "In Place",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct e4defrag_options, inplace),
		.minval	= 0,
		.maxval	= 1,
		.help	= "Alloc and free space inside defrag event",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_E4DEFRAG,
	},
	{
		.name	= NULL,
	},
};

static int fio_e4defrag_init(struct thread_data *td)
{
	int r, len = 0;
	struct e4defrag_options *o = td->eo;
	struct e4defrag_data *ed;
	struct stat stub;
	char donor_name[PATH_MAX];

	if (!o->donor_name || !strlen(o->donor_name)) {
		log_err("'donorname' options required\n");
		return 1;
	}

	ed = calloc(1, sizeof(*ed));
	if (!ed) {
		td_verror(td, ENOMEM, "io_queue_init");
		return 1;
	}

	if (td->o.directory)
		len = sprintf(donor_name, "%s/", td->o.directory);
	sprintf(donor_name + len, "%s", o->donor_name);

	ed->donor_fd = open(donor_name, O_CREAT|O_WRONLY, 0644);
	if (ed->donor_fd < 0) {
		td_verror(td, errno, "io_queue_init");
		log_err("Can't open donor file %s err:%d\n", donor_name, ed->donor_fd);
		free(ed);
		return 1;
	}

	if (!o->inplace) {
		long long __len = td->o.file_size_high - td->o.start_offset;
		r = fallocate(ed->donor_fd, 0, td->o.start_offset, __len);
		if (r)
			goto err;
	}
	r = fstat(ed->donor_fd, &stub);
	if (r)
		goto err;

	ed->bsz = stub.st_blksize;
	td->io_ops_data = ed;
	return 0;
err:
	td_verror(td, errno, "io_queue_init");
	close(ed->donor_fd);
	free(ed);
	return 1;
}

static void fio_e4defrag_cleanup(struct thread_data *td)
{
	struct e4defrag_data *ed = td->io_ops_data;
	if (ed) {
		if (ed->donor_fd >= 0)
			close(ed->donor_fd);
		free(ed);
	}
}


static enum fio_q_status fio_e4defrag_queue(struct thread_data *td,
					    struct io_u *io_u)
{

	int ret;
	unsigned long long len;
	struct move_extent me;
	struct fio_file *f = io_u->file;
	struct e4defrag_data *ed = td->io_ops_data;
	struct e4defrag_options *o = td->eo;

	fio_ro_check(td, io_u);

	/* Theoretically defragmentation should not change data, but it
	 * changes data layout. So this function handle only DDIR_WRITE
	 * in order to satisfy strict read only access pattern
	 */
	if (io_u->ddir != DDIR_WRITE) {
		io_u->error = EINVAL;
		return FIO_Q_COMPLETED;
	}

	if (o->inplace) {
		ret = fallocate(ed->donor_fd, 0, io_u->offset, io_u->xfer_buflen);
		if (ret)
			goto out;
	}

	memset(&me, 0, sizeof(me));
	me.donor_fd = ed->donor_fd;
	me.orig_start = io_u->offset / ed->bsz;
	me.donor_start = me.orig_start;
	len = (io_u->offset + io_u->xfer_buflen + ed->bsz -1);
	me.len = len / ed->bsz - me.orig_start;

	ret = ioctl(f->fd, EXT4_IOC_MOVE_EXT, &me);
	len = me.moved_len * ed->bsz;

	if (len > io_u->xfer_buflen)
		len = io_u->xfer_buflen;

	if (len != io_u->xfer_buflen) {
		if (len) {
			io_u->resid = io_u->xfer_buflen - len;
			io_u->error = 0;
		} else {
			/* access beyond i_size */
			io_u->error = EINVAL;
		}
	}
	if (ret)
		io_u->error = errno;

	if (o->inplace)
		ret = ftruncate(ed->donor_fd, 0);
out:
	if (ret && !io_u->error)
		io_u->error = errno;

	return FIO_Q_COMPLETED;
}

static struct ioengine_ops ioengine = {
	.name			= "e4defrag",
	.version		= FIO_IOOPS_VERSION,
	.init			= fio_e4defrag_init,
	.queue			= fio_e4defrag_queue,
	.open_file		= generic_open_file,
	.close_file		= generic_close_file,
	.get_file_size		= generic_get_file_size,
	.flags			= FIO_SYNCIO,
	.cleanup		= fio_e4defrag_cleanup,
	.options		= options,
	.option_struct_size	= sizeof(struct e4defrag_options),

};

static void fio_init fio_syncio_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_syncio_unregister(void)
{
	unregister_ioengine(&ioengine);
}
