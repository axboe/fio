/*
 * Custom fio(1) engine that submits synchronous atomic writes to file.
 *
 * Copyright (C) 2012 Fusion-io, Inc.
 * Author: Santhosh Kumar Koundinya.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; under version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License version
 * 2 for more details.
 *
 * You should have received a copy of the GNU General Public License Version 2
 * along with this program; if not see <http://www.gnu.org/licenses/>
 */

#include <stdlib.h>
#include <stdint.h>

#include "../fio.h"

#include <vsl_dp_experimental/vectored_write.h>

/* Fix sector size to 512 bytes independent of actual sector size, just like
 * the linux kernel. */
#define SECTOR_SHIFT    9
#define SECTOR_SIZE    (1U<<SECTOR_SHIFT)

struct acs_file_data {
	struct vsl_iovec iov[IO_VECTOR_LIMIT];
};

static int queue(struct thread_data *td, struct io_u *io_u)
{
	int rc;
	int iov_index;
	off_t offset;
	char *xfer_buf;
	size_t xfer_buflen;
	struct acs_file_data *d = io_u->file->file_data;

	if (io_u->ddir != DDIR_WRITE) {
		td_vmsg(td, -EIO, "only writes supported", "io_u->ddir");
		rc = -EIO;
		goto out;
	}
	if (io_u->xfer_buflen > IO_SIZE_MAX) {
		td_vmsg(td, -EIO, "data too big", "io_u->xfer_buflen");
		rc = -EIO;
		goto out;
	}
	if (io_u->xfer_buflen & (SECTOR_SIZE - 1)) {
		td_vmsg(td, -EIO, "unaligned data size", "io_u->xfer_buflen");
		rc = -EIO;
		goto out;
	}

	/* Chop up the write into minimal number of iovec's necessary */
	iov_index = 0;
	offset = io_u->offset;
	xfer_buf = io_u->xfer_buf;
	xfer_buflen = io_u->xfer_buflen;
	while (xfer_buflen) {
		struct vsl_iovec *iov = &d->iov[iov_index++];

		iov->iov_len = xfer_buflen > IO_VECTOR_MAX_SIZE ?
		    IO_VECTOR_MAX_SIZE : xfer_buflen;
		iov->iov_base = (uint64_t) xfer_buf;
		iov->sector = offset >> SECTOR_SHIFT;
		iov->iov_flag = VSL_IOV_WRITE;

		offset += iov->iov_len;
		xfer_buf += iov->iov_len;
		xfer_buflen -= iov->iov_len;
	}
	assert(xfer_buflen == 0);
	assert(iov_index <= IO_VECTOR_LIMIT);

	rc = vsl_vectored_write(io_u->file->fd, d->iov, iov_index, O_ATOMIC);
	if (rc == -1) {
		td_verror(td, -errno, "vsl_vectored_write");
		rc = -EIO;
		goto out;
	} else {
		io_u->error = 0;
		rc = FIO_Q_COMPLETED;
	}

out:
	if (rc < 0)
		io_u->error = rc;

	return rc;
}

static int open_file(struct thread_data *td, struct fio_file *f)
{
	int rc;
	struct acs_file_data *d = NULL;

	d = malloc(sizeof(*d));
	if (!d) {
		td_verror(td, -ENOMEM, "malloc");
		rc = -ENOMEM;
		goto error;
	}
	f->file_data = d;

	rc = generic_open_file(td, f);

out:
	return rc;

error:
	f->fd = -1;
	f->file_data = NULL;
	if (d)
		free(d);

	goto out;
}

static int close_file(struct thread_data *td, struct fio_file *f)
{
	if (f->file_data) {
		free(f->file_data);
		f->file_data = NULL;
	}

	return generic_close_file(td, f);
}

static struct ioengine_ops ioengine = {
	.name = "fusion-aw-sync",
	.version = FIO_IOOPS_VERSION,
	.queue = queue,
	.open_file = open_file,
	.close_file = close_file,
	.get_file_size = generic_get_file_size,
	.flags = FIO_SYNCIO | FIO_RAWIO | FIO_MEMALIGN
};

static void fio_init fio_fusion_aw_init(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_fusion_aw_exit(void)
{
	unregister_ioengine(&ioengine);
}
