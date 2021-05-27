/*
 * libpmem: IO engine that uses PMDK libpmem to read and write data
 *
 * Copyright (C) 2017 Nippon Telegraph and Telephone Corporation.
 * Copyright 2018-2021, Intel Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License,
 * version 2 as published by the Free Software Foundation..
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 */

/*
 * libpmem engine
 *
 * IO engine that uses libpmem (part of PMDK collection) to write data
 *	and libc's memcpy to read. It requires PMDK >= 1.5.
 *
 * To use:
 *   ioengine=libpmem
 *
 * Other relevant settings:
 *   iodepth=1
 *   direct=1
 *   sync=1
 *   directory=/mnt/pmem0/
 *   bs=4k
 *
 *   sync=1 means that pmem_drain() is executed for each write operation.
 *   Otherwise is not and should be called on demand.
 *
 *   direct=1 means PMEM_F_MEM_NONTEMPORAL flag is set in pmem_memcpy().
 *
 *   The pmem device must have a DAX-capable filesystem and be mounted
 *   with DAX enabled. Directory must point to a mount point of DAX FS.
 *
 *   Example:
 *     mkfs.xfs /dev/pmem0
 *     mkdir /mnt/pmem0
 *     mount -o dax /dev/pmem0 /mnt/pmem0
 *
 * See examples/libpmem.fio for complete usage example.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <libpmem.h>

#include "../fio.h"
#include "../verify.h"

struct fio_libpmem_data {
	void *libpmem_ptr;
	size_t libpmem_sz;
	off_t libpmem_off;
};

static int fio_libpmem_init(struct thread_data *td)
{
	struct thread_options *o = &td->o;

	dprint(FD_IO, "o->rw_min_bs %llu\n o->fsync_blocks %u\n o->fdatasync_blocks %u\n",
			o->rw_min_bs, o->fsync_blocks, o->fdatasync_blocks);
	dprint(FD_IO, "DEBUG fio_libpmem_init\n");

	if ((o->rw_min_bs & page_mask) &&
	    (o->fsync_blocks || o->fdatasync_blocks)) {
		log_err("libpmem: mmap options dictate a minimum block size of "
				"%llu bytes\n",	(unsigned long long) page_size);
		return 1;
	}
	return 0;
}

/*
 * This is the pmem_map_file execution function, a helper to
 * fio_libpmem_open_file function.
 */
static int fio_libpmem_file(struct thread_data *td, struct fio_file *f,
			    size_t length, off_t off)
{
	struct fio_libpmem_data *fdd = FILE_ENG_DATA(f);
	mode_t mode = S_IWUSR | S_IRUSR;
	size_t mapped_len;
	int is_pmem;

	dprint(FD_IO, "DEBUG fio_libpmem_file\n");
	dprint(FD_IO, "f->file_name = %s td->o.verify = %d \n", f->file_name,
			td->o.verify);
	dprint(FD_IO, "length = %ld f->fd = %d off = %ld file mode = %d \n",
			length, f->fd, off, mode);

	/* unmap any existing mapping */
	if (fdd->libpmem_ptr) {
		dprint(FD_IO,"pmem_unmap \n");
		if (pmem_unmap(fdd->libpmem_ptr, fdd->libpmem_sz) < 0)
			return errno;
		fdd->libpmem_ptr = NULL;
	}

	if((fdd->libpmem_ptr = pmem_map_file(f->file_name, length, PMEM_FILE_CREATE, mode, &mapped_len, &is_pmem)) == NULL) {
		td_verror(td, errno, pmem_errormsg());
		goto err;
	}

	if (!is_pmem) {
		td_verror(td, errno, "file_name does not point to persistent memory");
	}

err:
	if (td->error && fdd->libpmem_ptr)
		pmem_unmap(fdd->libpmem_ptr, length);

	return td->error;
}

static int fio_libpmem_open_file(struct thread_data *td, struct fio_file *f)
{
	struct fio_libpmem_data *fdd;

	dprint(FD_IO, "DEBUG fio_libpmem_open_file\n");
	dprint(FD_IO, "f->io_size=%ld\n", f->io_size);
	dprint(FD_IO, "td->o.size=%lld\n", td->o.size);
	dprint(FD_IO, "td->o.iodepth=%d\n", td->o.iodepth);
	dprint(FD_IO, "td->o.iodepth_batch=%d\n", td->o.iodepth_batch);

	if (fio_file_open(f))
		td_io_close_file(td, f);

	fdd = calloc(1, sizeof(*fdd));
	if (!fdd) {
		return 1;
	}
	FILE_SET_ENG_DATA(f, fdd);
	fdd->libpmem_sz = f->io_size;
	fdd->libpmem_off = 0;

	return fio_libpmem_file(td, f, fdd->libpmem_sz, fdd->libpmem_off);
}

static int fio_libpmem_prep(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	struct fio_libpmem_data *fdd = FILE_ENG_DATA(f);

	dprint(FD_IO, "DEBUG fio_libpmem_prep\n");
	dprint(FD_IO, "io_u->offset %llu : fdd->libpmem_off %ld : "
			"io_u->buflen %llu : fdd->libpmem_sz %ld\n",
			io_u->offset, fdd->libpmem_off,
			io_u->buflen, fdd->libpmem_sz);

	if (io_u->buflen > f->real_file_size) {
		log_err("libpmem: bs bigger than the file size\n");
		return EIO;
	}

	io_u->mmap_data = fdd->libpmem_ptr + io_u->offset - fdd->libpmem_off
				- f->file_offset;
	return 0;
}

static enum fio_q_status fio_libpmem_queue(struct thread_data *td,
					   struct io_u *io_u)
{
	unsigned flags = 0;

	fio_ro_check(td, io_u);
	io_u->error = 0;

	dprint(FD_IO, "DEBUG fio_libpmem_queue\n");
	dprint(FD_IO, "td->o.odirect %d td->o.sync_io %d\n",
			td->o.odirect, td->o.sync_io);
	/* map both O_SYNC / DSYNC to not use NODRAIN */
	flags = td->o.sync_io ? 0 : PMEM_F_MEM_NODRAIN;
	flags |= td->o.odirect ? PMEM_F_MEM_NONTEMPORAL : PMEM_F_MEM_TEMPORAL;

	switch (io_u->ddir) {
	case DDIR_READ:
		memcpy(io_u->xfer_buf, io_u->mmap_data, io_u->xfer_buflen);
		break;
	case DDIR_WRITE:
		dprint(FD_IO, "DEBUG mmap_data=%p, xfer_buf=%p\n",
				io_u->mmap_data, io_u->xfer_buf);
		pmem_memcpy(io_u->mmap_data,
					io_u->xfer_buf,
					io_u->xfer_buflen,
					flags);
		break;
	case DDIR_SYNC:
	case DDIR_DATASYNC:
	case DDIR_SYNC_FILE_RANGE:
		pmem_drain();
		break;
	default:
		io_u->error = EINVAL;
		break;
	}

	return FIO_Q_COMPLETED;
}

static int fio_libpmem_close_file(struct thread_data *td, struct fio_file *f)
{
	struct fio_libpmem_data *fdd = FILE_ENG_DATA(f);
	int ret = 0;

	dprint(FD_IO, "DEBUG fio_libpmem_close_file\n");

	if (fdd->libpmem_ptr)
		ret = pmem_unmap(fdd->libpmem_ptr, fdd->libpmem_sz);
	if (fio_file_open(f))
		ret &= generic_close_file(td, f);

	FILE_SET_ENG_DATA(f, NULL);
	free(fdd);

	return ret;
}

FIO_STATIC struct ioengine_ops ioengine = {
	.name		= "libpmem",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_libpmem_init,
	.prep		= fio_libpmem_prep,
	.queue		= fio_libpmem_queue,
	.open_file	= fio_libpmem_open_file,
	.close_file	= fio_libpmem_close_file,
	.get_file_size	= generic_get_file_size,
	.prepopulate_file = generic_prepopulate_file,
	.flags		= FIO_SYNCIO | FIO_RAWIO | FIO_DISKLESSIO | FIO_NOEXTEND |
				FIO_NODISKUTIL | FIO_BARRIER | FIO_MEMALIGN,
};

static void fio_init fio_libpmem_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_libpmem_unregister(void)
{
	unregister_ioengine(&ioengine);
}
