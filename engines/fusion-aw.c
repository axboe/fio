/*
 * Custom fio(1) engine that submits synchronous atomic writes to file.
 *
 * Copyright (C) 2013 Fusion-io, Inc.
 * Author: Santhosh Kumar Koundinya (skoundinya@fusionio.com).
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

#include <nvm/nvm_primitives.h>

#define NUM_ATOMIC_CAPABILITIES (5)

struct fas_data {
	nvm_handle_t nvm_handle;
	size_t xfer_buf_align;
	size_t xfer_buflen_align;
	size_t xfer_buflen_max;
	size_t sector_size;
};

static int queue(struct thread_data *td, struct io_u *io_u)
{
	struct fas_data *d = FILE_ENG_DATA(io_u->file);
	int rc;

	if (io_u->ddir != DDIR_WRITE) {
		td_vmsg(td, EINVAL, "only writes supported", "io_u->ddir");
		rc = -EINVAL;
		goto out;
	}

	if ((size_t) io_u->xfer_buf % d->xfer_buf_align) {
		td_vmsg(td, EINVAL, "unaligned data buffer", "io_u->xfer_buf");
		rc = -EINVAL;
		goto out;
	}

	if (io_u->xfer_buflen % d->xfer_buflen_align) {
		td_vmsg(td, EINVAL, "unaligned data size", "io_u->xfer_buflen");
		rc = -EINVAL;
		goto out;
	}

	if (io_u->xfer_buflen > d->xfer_buflen_max) {
		td_vmsg(td, EINVAL, "data too big", "io_u->xfer_buflen");
		rc = -EINVAL;
		goto out;
	}

	rc = nvm_atomic_write(d->nvm_handle, (uint64_t) io_u->xfer_buf,
		io_u->xfer_buflen, io_u->offset / d->sector_size);
	if (rc == -1) {
		td_verror(td, errno, "nvm_atomic_write");
		rc = -errno;
		goto out;
	}
	rc = FIO_Q_COMPLETED;
out:
	if (rc < 0)
		io_u->error = -rc;

	return rc;
}

static int open_file(struct thread_data *td, struct fio_file *f)
{
	int rc;
	int fio_unused close_file_rc;
	struct fas_data *d;
	nvm_version_t nvm_version;
	nvm_capability_t nvm_capability[NUM_ATOMIC_CAPABILITIES];


	d = malloc(sizeof(*d));
	if (!d) {
		td_verror(td, ENOMEM, "malloc");
		rc = ENOMEM;
		goto error;
	}
	d->nvm_handle = -1;
	FILE_SET_ENG_DATA(f, d);

	rc = generic_open_file(td, f);

	if (rc)
		goto free_engine_data;

	/* Set the version of the library as seen when engine is compiled */
	nvm_version.major = NVM_PRIMITIVES_API_MAJOR;
	nvm_version.minor = NVM_PRIMITIVES_API_MINOR;
	nvm_version.micro = NVM_PRIMITIVES_API_MICRO;

	d->nvm_handle = nvm_get_handle(f->fd, &nvm_version);
	if (d->nvm_handle == -1) {
		td_vmsg(td, errno, "nvm_get_handle failed", "nvm_get_handle");
		rc = errno;
		goto close_file;
	}

	nvm_capability[0].cap_id = NVM_CAP_ATOMIC_WRITE_START_ALIGN_ID;
	nvm_capability[1].cap_id = NVM_CAP_ATOMIC_WRITE_MULTIPLICITY_ID;
	nvm_capability[2].cap_id = NVM_CAP_ATOMIC_WRITE_MAX_VECTOR_SIZE_ID;
	nvm_capability[3].cap_id = NVM_CAP_SECTOR_SIZE_ID;
	nvm_capability[4].cap_id = NVM_CAP_ATOMIC_MAX_IOV_ID;
	rc = nvm_get_capabilities(d->nvm_handle, nvm_capability,
                                  NUM_ATOMIC_CAPABILITIES, false);
	if (rc == -1) {
		td_vmsg(td, errno, "error in getting atomic write capabilities", "nvm_get_capabilities");
		rc = errno;
		goto close_file;
	} else if (rc < NUM_ATOMIC_CAPABILITIES) {
		td_vmsg(td, EINVAL, "couldn't get all the atomic write capabilities" , "nvm_get_capabilities");
		rc = ECANCELED;
		goto close_file;
	}
	/* Reset rc to 0 because we got all capabilities we needed */
	rc = 0;
	d->xfer_buf_align = nvm_capability[0].cap_value;
	d->xfer_buflen_align = nvm_capability[1].cap_value;
	d->xfer_buflen_max = d->xfer_buflen_align * nvm_capability[2].cap_value * nvm_capability[4].cap_value;
	d->sector_size = nvm_capability[3].cap_value;

out:
	return rc;
close_file:
	close_file_rc = generic_close_file(td, f);
free_engine_data:
	free(d);
error:
	f->fd = -1;
	FILE_SET_ENG_DATA(f, NULL);
	goto out;
}

static int close_file(struct thread_data *td, struct fio_file *f)
{
	struct fas_data *d = FILE_ENG_DATA(f);

	if (d) {
		if (d->nvm_handle != -1)
			nvm_release_handle(d->nvm_handle);
		free(d);
		FILE_SET_ENG_DATA(f, NULL);
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
