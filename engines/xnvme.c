/*
 * fio xNVMe IO Engine
 *
 * IO engine using the xNVMe C API.
 *
 * See: http://xnvme.io/
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdlib.h>
#include <assert.h>
#include <libxnvme.h>
#include "fio.h"
#include "verify.h"
#include "zbd_types.h"
#include "dataplacement.h"
#include "optgroup.h"

static pthread_mutex_t g_serialize = PTHREAD_MUTEX_INITIALIZER;

struct xnvme_fioe_fwrap {
	/* fio file representation */
	struct fio_file *fio_file;

	/* xNVMe device handle */
	struct xnvme_dev *dev;
	/* xNVMe device geometry */
	const struct xnvme_geo *geo;

	struct xnvme_queue *queue;

	uint32_t ssw;
	uint32_t lba_nbytes;
	uint32_t md_nbytes;
	uint32_t lba_pow2;

	uint8_t _pad[16];
};
XNVME_STATIC_ASSERT(sizeof(struct xnvme_fioe_fwrap) == 64, "Incorrect size")

struct xnvme_fioe_data {
	/* I/O completion queue */
	struct io_u **iocq;

	/* # of iocq entries; incremented via getevents()/cb_pool() */
	uint64_t completed;

	/*
	 *  # of errors; incremented when observed on completion via
	 *  getevents()/cb_pool()
	 */
	uint64_t ecount;

	/* Controller which device/file to select */
	int32_t prev;
	int32_t cur;

	/* Number of devices/files for which open() has been called */
	int64_t nopen;
	/* Number of devices/files allocated in files[] */
	uint64_t nallocated;

	struct iovec *iovec;
	struct iovec *md_iovec;

	struct xnvme_fioe_fwrap files[];
};
XNVME_STATIC_ASSERT(sizeof(struct xnvme_fioe_data) == 64, "Incorrect size")

struct xnvme_fioe_request {
	/* Context for NVMe PI */
	struct xnvme_pi_ctx pi_ctx;

	/* Separate metadata buffer pointer */
	void *md_buf;
};

struct xnvme_fioe_options {
	void *padding;
	unsigned int hipri;
	unsigned int sqpoll_thread;
	unsigned int xnvme_dev_nsid;
	unsigned int xnvme_iovec;
	unsigned int md_per_io_size;
	unsigned int pi_act;
	unsigned int apptag;
	unsigned int apptag_mask;
	unsigned int prchk;
	char *xnvme_be;
	char *xnvme_mem;
	char *xnvme_async;
	char *xnvme_sync;
	char *xnvme_admin;
	char *xnvme_dev_subnqn;
};

static int str_pi_chk_cb(void *data, const char *str)
{
	struct xnvme_fioe_options *o = data;

	if (strstr(str, "GUARD") != NULL)
		o->prchk = XNVME_PI_FLAGS_GUARD_CHECK;
	if (strstr(str, "REFTAG") != NULL)
		o->prchk |= XNVME_PI_FLAGS_REFTAG_CHECK;
	if (strstr(str, "APPTAG") != NULL)
		o->prchk |= XNVME_PI_FLAGS_APPTAG_CHECK;

	return 0;
}

static struct fio_option options[] = {
	{
		.name = "hipri",
		.lname = "High Priority",
		.type = FIO_OPT_STR_SET,
		.off1 = offsetof(struct xnvme_fioe_options, hipri),
		.help = "Use polled IO completions",
		.category = FIO_OPT_C_ENGINE,
		.group = FIO_OPT_G_XNVME,
	},
	{
		.name = "sqthread_poll",
		.lname = "Kernel SQ thread polling",
		.type = FIO_OPT_STR_SET,
		.off1 = offsetof(struct xnvme_fioe_options, sqpoll_thread),
		.help = "Offload submission/completion to kernel thread",
		.category = FIO_OPT_C_ENGINE,
		.group = FIO_OPT_G_XNVME,
	},
	{
		.name = "xnvme_be",
		.lname = "xNVMe Backend",
		.type = FIO_OPT_STR_STORE,
		.off1 = offsetof(struct xnvme_fioe_options, xnvme_be),
		.help = "Select xNVMe backend [spdk,linux,fbsd]",
		.category = FIO_OPT_C_ENGINE,
		.group = FIO_OPT_G_XNVME,
	},
	{
		.name = "xnvme_mem",
		.lname = "xNVMe Memory Backend",
		.type = FIO_OPT_STR_STORE,
		.off1 = offsetof(struct xnvme_fioe_options, xnvme_mem),
		.help = "Select xNVMe memory backend",
		.category = FIO_OPT_C_ENGINE,
		.group = FIO_OPT_G_XNVME,
	},
	{
		.name = "xnvme_async",
		.lname = "xNVMe Asynchronous command-interface",
		.type = FIO_OPT_STR_STORE,
		.off1 = offsetof(struct xnvme_fioe_options, xnvme_async),
		.help = "Select xNVMe async. interface: "
			"[emu,thrpool,io_uring,io_uring_cmd,libaio,posix,vfio,nil]",
		.category = FIO_OPT_C_ENGINE,
		.group = FIO_OPT_G_XNVME,
	},
	{
		.name = "xnvme_sync",
		.lname = "xNVMe Synchronous. command-interface",
		.type = FIO_OPT_STR_STORE,
		.off1 = offsetof(struct xnvme_fioe_options, xnvme_sync),
		.help = "Select xNVMe sync. interface: [nvme,psync,block]",
		.category = FIO_OPT_C_ENGINE,
		.group = FIO_OPT_G_XNVME,
	},
	{
		.name = "xnvme_admin",
		.lname = "xNVMe Admin command-interface",
		.type = FIO_OPT_STR_STORE,
		.off1 = offsetof(struct xnvme_fioe_options, xnvme_admin),
		.help = "Select xNVMe admin. cmd-interface: [nvme,block]",
		.category = FIO_OPT_C_ENGINE,
		.group = FIO_OPT_G_XNVME,
	},
	{
		.name = "xnvme_dev_nsid",
		.lname = "xNVMe Namespace-Identifier, for user-space NVMe driver",
		.type = FIO_OPT_INT,
		.off1 = offsetof(struct xnvme_fioe_options, xnvme_dev_nsid),
		.help = "xNVMe Namespace-Identifier, for user-space NVMe driver",
		.category = FIO_OPT_C_ENGINE,
		.group = FIO_OPT_G_XNVME,
	},
	{
		.name = "xnvme_dev_subnqn",
		.lname = "Subsystem nqn for Fabrics",
		.type = FIO_OPT_STR_STORE,
		.off1 = offsetof(struct xnvme_fioe_options, xnvme_dev_subnqn),
		.help = "Subsystem NQN for Fabrics",
		.category = FIO_OPT_C_ENGINE,
		.group = FIO_OPT_G_XNVME,
	},
	{
		.name = "xnvme_iovec",
		.lname = "Vectored IOs",
		.type = FIO_OPT_STR_SET,
		.off1 = offsetof(struct xnvme_fioe_options, xnvme_iovec),
		.help = "Send vectored IOs",
		.category = FIO_OPT_C_ENGINE,
		.group = FIO_OPT_G_XNVME,
	},
	{
		.name	= "md_per_io_size",
		.lname	= "Separate Metadata Buffer Size per I/O",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct xnvme_fioe_options, md_per_io_size),
		.def	= "0",
		.help	= "Size of separate metadata buffer per I/O (Default: 0)",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_XNVME,
	},
	{
		.name	= "pi_act",
		.lname	= "Protection Information Action",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct xnvme_fioe_options, pi_act),
		.def	= "1",
		.help	= "Protection Information Action bit (pi_act=1 or pi_act=0)",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_XNVME,
	},
	{
		.name	= "pi_chk",
		.lname	= "Protection Information Check",
		.type	= FIO_OPT_STR_STORE,
		.def	= NULL,
		.help	= "Control of Protection Information Checking (pi_chk=GUARD,REFTAG,APPTAG)",
		.cb	= str_pi_chk_cb,
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_XNVME,
	},
	{
		.name	= "apptag",
		.lname	= "Application Tag used in Protection Information",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct xnvme_fioe_options, apptag),
		.def	= "0x1234",
		.help	= "Application Tag used in Protection Information field (Default: 0x1234)",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_XNVME,
	},
	{
		.name	= "apptag_mask",
		.lname	= "Application Tag Mask",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct xnvme_fioe_options, apptag_mask),
		.def	= "0xffff",
		.help	= "Application Tag Mask used with Application Tag (Default: 0xffff)",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_XNVME,
	},

	{
		.name = NULL,
	},
};

static void cb_pool(struct xnvme_cmd_ctx *ctx, void *cb_arg)
{
	struct io_u *io_u = cb_arg;
	struct xnvme_fioe_data *xd = io_u->mmap_data;
	struct xnvme_fioe_request *fio_req = io_u->engine_data;
	struct xnvme_fioe_fwrap *fwrap = &xd->files[io_u->file->fileno];
	bool pi_act = (fio_req->pi_ctx.pi_flags >> 3);
	int err;

	if (xnvme_cmd_ctx_cpl_status(ctx)) {
		xnvme_cmd_ctx_pr(ctx, XNVME_PR_DEF);
		xd->ecount += 1;
		io_u->error = EIO;
	}

	if (!io_u->error && fwrap->geo->pi_type && (io_u->ddir == DDIR_READ) && !pi_act) {
		err = xnvme_pi_verify(&fio_req->pi_ctx, io_u->xfer_buf,
				      fio_req->md_buf, io_u->xfer_buflen / fwrap->lba_nbytes);
		if (err) {
			xd->ecount += 1;
			io_u->error = EIO;
		}
	}

	xd->iocq[xd->completed++] = io_u;
	xnvme_queue_put_cmd_ctx(ctx->async.queue, ctx);
}

static struct xnvme_opts xnvme_opts_from_fioe(struct thread_data *td)
{
	struct xnvme_fioe_options *o = td->eo;
	struct xnvme_opts opts = xnvme_opts_default();

	opts.nsid = o->xnvme_dev_nsid;
	opts.subnqn = o->xnvme_dev_subnqn;
	opts.be = o->xnvme_be;
	opts.mem = o->xnvme_mem;
	opts.async = o->xnvme_async;
	opts.sync = o->xnvme_sync;
	opts.admin = o->xnvme_admin;

	opts.poll_io = o->hipri;
	opts.poll_sq = o->sqpoll_thread;

	opts.direct = td->o.odirect;

	return opts;
}

static void _dev_close(struct thread_data *td, struct xnvme_fioe_fwrap *fwrap)
{
	if (fwrap->dev)
		xnvme_queue_term(fwrap->queue);

	xnvme_dev_close(fwrap->dev);

	memset(fwrap, 0, sizeof(*fwrap));
}

static void xnvme_fioe_cleanup(struct thread_data *td)
{
	struct xnvme_fioe_data *xd = NULL;
	int err;

	if (!td->io_ops_data)
		return;

	xd = td->io_ops_data;

	err = pthread_mutex_lock(&g_serialize);
	if (err)
		log_err("ioeng->cleanup(): pthread_mutex_lock(), err(%d)\n", err);
		/* NOTE: not returning here */

	for (uint64_t i = 0; i < xd->nallocated; ++i)
		_dev_close(td, &xd->files[i]);

	if (!err) {
		err = pthread_mutex_unlock(&g_serialize);
		if (err)
			log_err("ioeng->cleanup(): pthread_mutex_unlock(), err(%d)\n", err);
	}

	free(xd->iocq);
	free(xd->iovec);
	free(xd->md_iovec);
	free(xd);
	td->io_ops_data = NULL;
}

static int _verify_options(struct thread_data *td, struct fio_file *f,
			   struct xnvme_fioe_fwrap *fwrap)
{
	struct xnvme_fioe_options *o = td->eo;
	unsigned int correct_md_size;

	for_each_rw_ddir(ddir) {
		if (td->o.min_bs[ddir] % fwrap->lba_nbytes || td->o.max_bs[ddir] % fwrap->lba_nbytes) {
			if (!fwrap->lba_pow2) {
				log_err("ioeng->_verify_options(%s): block size must be a multiple of %u "
					"(LBA data size + Metadata size)\n", f->file_name, fwrap->lba_nbytes);
			} else {
				log_err("ioeng->_verify_options(%s): block size must be a multiple of LBA data size\n",
					f->file_name);
			}
			return 1;
		}
		if (ddir == DDIR_TRIM)
			continue;

		correct_md_size = (td->o.max_bs[ddir] / fwrap->lba_nbytes) * fwrap->md_nbytes;
		if (fwrap->md_nbytes && fwrap->lba_pow2 && (o->md_per_io_size < correct_md_size)) {
			log_err("ioeng->_verify_options(%s): md_per_io_size should be at least %u bytes\n",
				f->file_name, correct_md_size);
			return 1;
		}
	}

	/*
	 * For extended logical block sizes we cannot use verify when
	 * end to end data protection checks are enabled, as the PI
	 * section of data buffer conflicts with verify.
	 */
	if (fwrap->md_nbytes && fwrap->geo->pi_type && !fwrap->lba_pow2 &&
	    td->o.verify != VERIFY_NONE) {
		log_err("ioeng->_verify_options(%s): for extended LBA, verify cannot be used when E2E data protection is enabled\n",
			f->file_name);
		return 1;
	}

	return 0;
}

/**
 * Helper function setting up device handles as addressed by the naming
 * convention of the given `fio_file` filename.
 *
 * Checks thread-options for explicit control of asynchronous implementation via
 * the ``--xnvme_async={thrpool,emu,posix,io_uring,libaio,nil}``.
 */
static int _dev_open(struct thread_data *td, struct fio_file *f)
{
	struct xnvme_opts opts = xnvme_opts_from_fioe(td);
	struct xnvme_fioe_options *o = td->eo;
	struct xnvme_fioe_data *xd = td->io_ops_data;
	struct xnvme_fioe_fwrap *fwrap;
	int flags = 0;
	int err;

	if (f->fileno > (int)xd->nallocated) {
		log_err("ioeng->_dev_open(%s): invalid assumption\n", f->file_name);
		return 1;
	}

	fwrap = &xd->files[f->fileno];

	err = pthread_mutex_lock(&g_serialize);
	if (err) {
		log_err("ioeng->_dev_open(%s): pthread_mutex_lock(), err(%d)\n", f->file_name,
			err);
		return -err;
	}

	fwrap->dev = xnvme_dev_open(f->file_name, &opts);
	if (!fwrap->dev) {
		log_err("ioeng->_dev_open(%s): xnvme_dev_open(), err(%d)\n", f->file_name, errno);
		goto failure;
	}
	fwrap->geo = xnvme_dev_get_geo(fwrap->dev);

	if (xnvme_queue_init(fwrap->dev, td->o.iodepth, flags, &(fwrap->queue))) {
		log_err("ioeng->_dev_open(%s): xnvme_queue_init(), err(?)\n", f->file_name);
		goto failure;
	}
	xnvme_queue_set_cb(fwrap->queue, cb_pool, NULL);

	fwrap->ssw = xnvme_dev_get_ssw(fwrap->dev);
	fwrap->lba_nbytes = fwrap->geo->lba_nbytes;
	fwrap->md_nbytes = fwrap->geo->nbytes_oob;

	if (fwrap->geo->lba_extended)
		fwrap->lba_pow2 = 0;
	else
		fwrap->lba_pow2 = 1;

	/*
	 * When PI action is set and PI size is equal to metadata size, the
	 * controller inserts/removes PI. So update the LBA data and metadata
	 * sizes accordingly.
	 */
	if (o->pi_act && fwrap->geo->pi_type &&
	    fwrap->geo->nbytes_oob == xnvme_pi_size(fwrap->geo->pi_format)) {
		if (fwrap->geo->lba_extended) {
			fwrap->lba_nbytes -= fwrap->geo->nbytes_oob;
			fwrap->lba_pow2 = 1;
		}
		fwrap->md_nbytes = 0;
	}

	if (_verify_options(td, f, fwrap)) {
		td_verror(td, EINVAL, "_dev_open");
		goto failure;
	}

	fwrap->fio_file = f;
	fwrap->fio_file->filetype = FIO_TYPE_BLOCK;
	fwrap->fio_file->real_file_size = fwrap->geo->tbytes;
	fio_file_set_size_known(fwrap->fio_file);

	err = pthread_mutex_unlock(&g_serialize);
	if (err)
		log_err("ioeng->_dev_open(%s): pthread_mutex_unlock(), err(%d)\n", f->file_name,
			err);

	return 0;

failure:
	xnvme_queue_term(fwrap->queue);
	xnvme_dev_close(fwrap->dev);

	err = pthread_mutex_unlock(&g_serialize);
	if (err)
		log_err("ioeng->_dev_open(%s): pthread_mutex_unlock(), err(%d)\n", f->file_name,
			err);

	return 1;
}

static int xnvme_fioe_init(struct thread_data *td)
{
	struct xnvme_fioe_data *xd = NULL;
	struct xnvme_fioe_options *o = td->eo;
	struct fio_file *f;
	unsigned int i;

	if (!td->o.use_thread) {
		log_err("ioeng->init(): --thread=1 is required\n");
		return 1;
	}

	/* Allocate xd and iocq */
	xd = calloc(1, sizeof(*xd) + sizeof(*xd->files) * td->o.nr_files);
	if (!xd) {
		log_err("ioeng->init(): !calloc(), err(%d)\n", errno);
		return 1;
	}

	xd->iocq = calloc(td->o.iodepth, sizeof(struct io_u *));
	if (!xd->iocq) {
		free(xd);
		log_err("ioeng->init(): !calloc(xd->iocq), err(%d)\n", errno);
		return 1;
	}

	if (o->xnvme_iovec) {
		xd->iovec = calloc(td->o.iodepth, sizeof(*xd->iovec));
		if (!xd->iovec) {
			free(xd->iocq);
			free(xd);
			log_err("ioeng->init(): !calloc(xd->iovec), err(%d)\n", errno);
			return 1;
		}
	}

	if (o->xnvme_iovec && o->md_per_io_size) {
		xd->md_iovec = calloc(td->o.iodepth, sizeof(*xd->md_iovec));
		if (!xd->md_iovec) {
			free(xd->iocq);
			free(xd->iovec);
			free(xd);
			log_err("ioeng->init(): !calloc(xd->md_iovec), err(%d)\n", errno);
			return 1;
		}
	}

	xd->prev = -1;
	td->io_ops_data = xd;

	for_each_file(td, f, i)
	{
		if (_dev_open(td, f)) {
			/*
			 * Note: We are not freeing xd, iocq, iovec and md_iovec.
			 * This will be done as part of cleanup routine.
			 */
			log_err("ioeng->init(): failed; _dev_open(%s)\n", f->file_name);
			return 1;
		}

		++(xd->nallocated);
	}

	if (xd->nallocated != td->o.nr_files) {
		log_err("ioeng->init(): failed; nallocated != td->o.nr_files\n");
		return 1;
	}

	return 0;
}

/* NOTE: using the first device for buffer-allocators) */
static int xnvme_fioe_iomem_alloc(struct thread_data *td, size_t total_mem)
{
	struct xnvme_fioe_data *xd = td->io_ops_data;
	struct xnvme_fioe_fwrap *fwrap = &xd->files[0];

	if (!fwrap->dev) {
		log_err("ioeng->iomem_alloc(): failed; no dev-handle\n");
		return 1;
	}

	td->orig_buffer = xnvme_buf_alloc(fwrap->dev, total_mem);

	return td->orig_buffer == NULL;
}

/* NOTE: using the first device for buffer-allocators) */
static void xnvme_fioe_iomem_free(struct thread_data *td)
{
	struct xnvme_fioe_data *xd = NULL;
	struct xnvme_fioe_fwrap *fwrap = NULL;

	if (!td->io_ops_data)
		return;

	xd = td->io_ops_data;
	fwrap = &xd->files[0];

	if (!fwrap->dev) {
		log_err("ioeng->iomem_free(): failed no dev-handle\n");
		return;
	}

	xnvme_buf_free(fwrap->dev, td->orig_buffer);
}

static int xnvme_fioe_io_u_init(struct thread_data *td, struct io_u *io_u)
{
	struct xnvme_fioe_request *fio_req;
	struct xnvme_fioe_options *o = td->eo;
	struct xnvme_fioe_data *xd = td->io_ops_data;
	struct xnvme_fioe_fwrap *fwrap = &xd->files[0];

	if (!fwrap->dev) {
		log_err("ioeng->io_u_init(): failed; no dev-handle\n");
		return 1;
	}

	io_u->mmap_data = td->io_ops_data;
	io_u->engine_data = NULL;

	fio_req = calloc(1, sizeof(*fio_req));
	if (!fio_req) {
		log_err("ioeng->io_u_init(): !calloc(fio_req), err(%d)\n", errno);
		return 1;
	}

	if (o->md_per_io_size) {
		fio_req->md_buf = xnvme_buf_alloc(fwrap->dev, o->md_per_io_size);
		if (!fio_req->md_buf) {
			free(fio_req);
			return 1;
		}
	}

	io_u->engine_data = fio_req;

	return 0;
}

static void xnvme_fioe_io_u_free(struct thread_data *td, struct io_u *io_u)
{
	struct xnvme_fioe_data *xd = NULL;
	struct xnvme_fioe_fwrap *fwrap = NULL;
	struct xnvme_fioe_request *fio_req = NULL;

	if (!td->io_ops_data)
		return;

	xd = td->io_ops_data;
	fwrap = &xd->files[0];

	if (!fwrap->dev) {
		log_err("ioeng->io_u_free(): failed no dev-handle\n");
		return;
	}

	fio_req = io_u->engine_data;
	if (fio_req->md_buf)
		xnvme_buf_free(fwrap->dev, fio_req->md_buf);

	free(fio_req);

	io_u->mmap_data = NULL;
}

static struct io_u *xnvme_fioe_event(struct thread_data *td, int event)
{
	struct xnvme_fioe_data *xd = td->io_ops_data;

	assert(event >= 0);
	assert((unsigned)event < xd->completed);

	return xd->iocq[event];
}

static int xnvme_fioe_getevents(struct thread_data *td, unsigned int min, unsigned int max,
				const struct timespec *t)
{
	struct xnvme_fioe_data *xd = td->io_ops_data;
	struct xnvme_fioe_fwrap *fwrap = NULL;
	int nfiles = xd->nallocated;
	int err = 0;

	if (xd->prev != -1 && ++xd->prev < nfiles) {
		fwrap = &xd->files[xd->prev];
		xd->cur = xd->prev;
	}

	xd->completed = 0;
	for (;;) {
		if (fwrap == NULL || xd->cur == nfiles) {
			fwrap = &xd->files[0];
			xd->cur = 0;
		}

		while (fwrap != NULL && xd->cur < nfiles && err >= 0) {
			err = xnvme_queue_poke(fwrap->queue, max - xd->completed);
			if (err < 0) {
				switch (err) {
				case -EBUSY:
				case -EAGAIN:
					usleep(1);
					break;

				default:
					log_err("ioeng->getevents(): unhandled IO error\n");
					assert(false);
					return 0;
				}
			}
			if (xd->completed >= min) {
				xd->prev = xd->cur;
				return xd->completed;
			}
			xd->cur++;
			fwrap = &xd->files[xd->cur];

			if (err < 0) {
				switch (err) {
				case -EBUSY:
				case -EAGAIN:
					usleep(1);
					break;
				}
			}
		}
	}

	xd->cur = 0;

	return xd->completed;
}

static enum fio_q_status xnvme_fioe_queue(struct thread_data *td, struct io_u *io_u)
{
	struct xnvme_fioe_data *xd = td->io_ops_data;
	struct xnvme_fioe_options *o = td->eo;
	struct xnvme_fioe_fwrap *fwrap;
	struct xnvme_cmd_ctx *ctx;
	struct xnvme_fioe_request *fio_req = io_u->engine_data;
	uint32_t nsid;
	uint64_t slba;
	uint16_t nlb;
	int err;
	bool vectored_io = ((struct xnvme_fioe_options *)td->eo)->xnvme_iovec;
	uint32_t dir = io_u->dtype;

	fio_ro_check(td, io_u);

	fwrap = &xd->files[io_u->file->fileno];
	nsid = xnvme_dev_get_nsid(fwrap->dev);

	if (fwrap->lba_pow2) {
		slba = io_u->offset >> fwrap->ssw;
		nlb = (io_u->xfer_buflen >> fwrap->ssw) - 1;
	} else {
		slba = io_u->offset / fwrap->lba_nbytes;
		nlb = (io_u->xfer_buflen / fwrap->lba_nbytes) - 1;
	}

	ctx = xnvme_queue_get_cmd_ctx(fwrap->queue);
	ctx->async.cb_arg = io_u;

	ctx->cmd.common.nsid = nsid;
	ctx->cmd.nvm.slba = slba;
	ctx->cmd.nvm.nlb = nlb;
	if (dir) {
		ctx->cmd.nvm.dtype = io_u->dtype;
		ctx->cmd.nvm.cdw13.dspec = io_u->dspec;
	}

	switch (io_u->ddir) {
	case DDIR_READ:
		ctx->cmd.common.opcode = XNVME_SPEC_NVM_OPC_READ;
		break;

	case DDIR_WRITE:
		ctx->cmd.common.opcode = XNVME_SPEC_NVM_OPC_WRITE;
		break;

	default:
		log_err("ioeng->queue(): ENOSYS: %u\n", io_u->ddir);
		xnvme_queue_put_cmd_ctx(ctx->async.queue, ctx);

		io_u->error = ENOSYS;
		assert(false);
		return FIO_Q_COMPLETED;
	}

	if (fwrap->geo->pi_type && !o->pi_act) {
		err = xnvme_pi_ctx_init(&fio_req->pi_ctx, fwrap->lba_nbytes,
					fwrap->geo->nbytes_oob, fwrap->geo->lba_extended,
					fwrap->geo->pi_loc, fwrap->geo->pi_type,
					(o->pi_act << 3 | o->prchk), slba, o->apptag_mask,
					o->apptag, fwrap->geo->pi_format);
		if (err) {
			log_err("ioeng->queue(): err: '%d'\n", err);

			xnvme_queue_put_cmd_ctx(ctx->async.queue, ctx);

			io_u->error = abs(err);
			return FIO_Q_COMPLETED;
		}

		if (io_u->ddir == DDIR_WRITE)
			xnvme_pi_generate(&fio_req->pi_ctx, io_u->xfer_buf, fio_req->md_buf,
					  nlb + 1);
	}

	if (fwrap->geo->pi_type)
		ctx->cmd.nvm.prinfo = (o->pi_act << 3 | o->prchk);

	switch (fwrap->geo->pi_type) {
	case XNVME_PI_TYPE1:
	case XNVME_PI_TYPE2:
		switch (fwrap->geo->pi_format) {
		case XNVME_SPEC_NVM_NS_16B_GUARD:
			if (o->prchk & XNVME_PI_FLAGS_REFTAG_CHECK)
				ctx->cmd.nvm.ilbrt = (uint32_t)slba;
			break;
		case XNVME_SPEC_NVM_NS_64B_GUARD:
			if (o->prchk & XNVME_PI_FLAGS_REFTAG_CHECK) {
				ctx->cmd.nvm.ilbrt = (uint32_t)slba;
				ctx->cmd.common.cdw03 = ((slba >> 32) & 0xffff);
			}
			break;
		default:
			break;
		}
		if (o->prchk & XNVME_PI_FLAGS_APPTAG_CHECK) {
			ctx->cmd.nvm.lbat = o->apptag;
			ctx->cmd.nvm.lbatm = o->apptag_mask;
		}
		break;
	case XNVME_PI_TYPE3:
		if (o->prchk & XNVME_PI_FLAGS_APPTAG_CHECK) {
			ctx->cmd.nvm.lbat = o->apptag;
			ctx->cmd.nvm.lbatm = o->apptag_mask;
		}
		break;
	case XNVME_PI_DISABLE:
		break;
	}

	if (vectored_io) {
		xd->iovec[io_u->index].iov_base = io_u->xfer_buf;
		xd->iovec[io_u->index].iov_len = io_u->xfer_buflen;
		if (fwrap->md_nbytes && fwrap->lba_pow2) {
			xd->md_iovec[io_u->index].iov_base = fio_req->md_buf;
			xd->md_iovec[io_u->index].iov_len = fwrap->md_nbytes * (nlb + 1);
			err = xnvme_cmd_passv(ctx, &xd->iovec[io_u->index], 1, io_u->xfer_buflen,
					      &xd->md_iovec[io_u->index], 1,
					      fwrap->md_nbytes * (nlb + 1));
		} else {
			err = xnvme_cmd_passv(ctx, &xd->iovec[io_u->index], 1, io_u->xfer_buflen,
					      NULL, 0, 0);
		}
	} else {
		if (fwrap->md_nbytes && fwrap->lba_pow2)
			err = xnvme_cmd_pass(ctx, io_u->xfer_buf, io_u->xfer_buflen,
					     fio_req->md_buf, fwrap->md_nbytes * (nlb + 1));
		else
			err = xnvme_cmd_pass(ctx, io_u->xfer_buf, io_u->xfer_buflen, NULL, 0);
	}
	switch (err) {
	case 0:
		return FIO_Q_QUEUED;

	case -EBUSY:
	case -EAGAIN:
		xnvme_queue_put_cmd_ctx(ctx->async.queue, ctx);
		return FIO_Q_BUSY;

	default:
		log_err("ioeng->queue(): err: '%d'\n", err);

		xnvme_queue_put_cmd_ctx(ctx->async.queue, ctx);

		io_u->error = abs(err);
		assert(false);
		return FIO_Q_COMPLETED;
	}
}

static int xnvme_fioe_close(struct thread_data *td, struct fio_file *f)
{
	struct xnvme_fioe_data *xd = td->io_ops_data;

	dprint(FD_FILE, "xnvme close %s -- nopen: %ld\n", f->file_name, xd->nopen);

	--(xd->nopen);

	return 0;
}

static int xnvme_fioe_open(struct thread_data *td, struct fio_file *f)
{
	struct xnvme_fioe_data *xd = td->io_ops_data;

	dprint(FD_FILE, "xnvme open %s -- nopen: %ld\n", f->file_name, xd->nopen);

	if (f->fileno > (int)xd->nallocated) {
		log_err("ioeng->open(): f->fileno > xd->nallocated; invalid assumption\n");
		return 1;
	}
	if (xd->files[f->fileno].fio_file != f) {
		log_err("ioeng->open(): fio_file != f; invalid assumption\n");
		return 1;
	}

	++(xd->nopen);

	return 0;
}

static int xnvme_fioe_invalidate(struct thread_data *td, struct fio_file *f)
{
	/* Consider only doing this with be:spdk */
	return 0;
}

static int xnvme_fioe_get_max_open_zones(struct thread_data *td, struct fio_file *f,
					 unsigned int *max_open_zones)
{
	struct xnvme_opts opts = xnvme_opts_from_fioe(td);
	struct xnvme_dev *dev;
	const struct xnvme_spec_znd_idfy_ns *zns;
	int err = 0, err_lock;

	if (f->filetype != FIO_TYPE_FILE && f->filetype != FIO_TYPE_BLOCK &&
	    f->filetype != FIO_TYPE_CHAR) {
		log_info("ioeng->get_max_open_zoned(): ignoring filetype: %d\n", f->filetype);
		return 0;
	}
	err_lock = pthread_mutex_lock(&g_serialize);
	if (err_lock) {
		log_err("ioeng->get_max_open_zones(): pthread_mutex_lock(), err(%d)\n", err_lock);
		return -err_lock;
	}

	dev = xnvme_dev_open(f->file_name, &opts);
	if (!dev) {
		log_err("ioeng->get_max_open_zones(): xnvme_dev_open(), err(%d)\n", err_lock);
		err = -errno;
		goto exit;
	}
	if (xnvme_dev_get_geo(dev)->type != XNVME_GEO_ZONED) {
		errno = EINVAL;
		err = -errno;
		goto exit;
	}

	zns = (void *)xnvme_dev_get_ns_css(dev);
	if (!zns) {
		log_err("ioeng->get_max_open_zones(): xnvme_dev_get_ns_css(), err(%d)\n", errno);
		err = -errno;
		goto exit;
	}

	/*
	 * intentional overflow as the value is zero-based and NVMe
	 * defines 0xFFFFFFFF as unlimited thus overflowing to 0 which
	 * is how fio indicates unlimited and otherwise just converting
	 * to one-based.
	 */
	*max_open_zones = zns->mor + 1;

exit:
	xnvme_dev_close(dev);
	err_lock = pthread_mutex_unlock(&g_serialize);
	if (err_lock)
		log_err("ioeng->get_max_open_zones(): pthread_mutex_unlock(), err(%d)\n",
			err_lock);

	return err;
}

/**
 * Currently, this function is called before of I/O engine initialization, so,
 * we cannot consult the file-wrapping done when 'fioe' initializes.
 * Instead we just open based on the given filename.
 *
 * TODO: unify the different setup methods, consider keeping the handle around,
 * and consider how to support the --be option in this usecase
 */
static int xnvme_fioe_get_zoned_model(struct thread_data *td, struct fio_file *f,
				      enum zbd_zoned_model *model)
{
	struct xnvme_opts opts = xnvme_opts_from_fioe(td);
	struct xnvme_dev *dev;
	int err = 0, err_lock;

	if (f->filetype != FIO_TYPE_FILE && f->filetype != FIO_TYPE_BLOCK &&
	    f->filetype != FIO_TYPE_CHAR) {
		log_info("ioeng->get_zoned_model(): ignoring filetype: %d\n", f->filetype);
		return -EINVAL;
	}

	err = pthread_mutex_lock(&g_serialize);
	if (err) {
		log_err("ioeng->get_zoned_model(): pthread_mutex_lock(), err(%d)\n", err);
		return -err;
	}

	dev = xnvme_dev_open(f->file_name, &opts);
	if (!dev) {
		log_err("ioeng->get_zoned_model(): xnvme_dev_open(%s) failed, errno: %d\n",
			f->file_name, errno);
		err = -errno;
		goto exit;
	}

	switch (xnvme_dev_get_geo(dev)->type) {
	case XNVME_GEO_UNKNOWN:
		dprint(FD_ZBD, "%s: got 'unknown', assigning ZBD_NONE\n", f->file_name);
		*model = ZBD_NONE;
		break;

	case XNVME_GEO_CONVENTIONAL:
		dprint(FD_ZBD, "%s: got 'conventional', assigning ZBD_NONE\n", f->file_name);
		*model = ZBD_NONE;
		break;

	case XNVME_GEO_ZONED:
		dprint(FD_ZBD, "%s: got 'zoned', assigning ZBD_HOST_MANAGED\n", f->file_name);
		*model = ZBD_HOST_MANAGED;
		break;

	default:
		dprint(FD_ZBD, "%s: hit-default, assigning ZBD_NONE\n", f->file_name);
		*model = ZBD_NONE;
		errno = EINVAL;
		err = -errno;
		break;
	}

exit:
	xnvme_dev_close(dev);

	err_lock = pthread_mutex_unlock(&g_serialize);
	if (err_lock)
		log_err("ioeng->get_zoned_model(): pthread_mutex_unlock(), err(%d)\n", err_lock);

	return err;
}

/**
 * Fills the given ``zbdz`` with at most ``nr_zones`` zone-descriptors.
 *
 * The implementation converts the NVMe Zoned Command Set log-pages for Zone
 * descriptors into the Linux Kernel Zoned Block Report format.
 *
 * NOTE: This function is called before I/O engine initialization, that is,
 * before ``_dev_open`` has been called and file-wrapping is setup. Thus is has
 * to do the ``_dev_open`` itself, and shut it down again once it is done
 * retrieving the log-pages and converting them to the report format.
 *
 * TODO: unify the different setup methods, consider keeping the handle around,
 * and consider how to support the --async option in this usecase
 */
static int xnvme_fioe_report_zones(struct thread_data *td, struct fio_file *f, uint64_t offset,
				   struct zbd_zone *zbdz, unsigned int nr_zones)
{
	struct xnvme_opts opts = xnvme_opts_from_fioe(td);
	const struct xnvme_spec_znd_idfy_lbafe *lbafe = NULL;
	struct xnvme_dev *dev = NULL;
	const struct xnvme_geo *geo = NULL;
	struct xnvme_znd_report *rprt = NULL;
	uint32_t ssw;
	uint64_t slba;
	unsigned int limit = 0;
	int err = 0, err_lock;

	dprint(FD_ZBD, "%s: report_zones() offset: %zu, nr_zones: %u\n", f->file_name, offset,
	       nr_zones);

	err = pthread_mutex_lock(&g_serialize);
	if (err) {
		log_err("ioeng->report_zones(%s): pthread_mutex_lock(), err(%d)\n", f->file_name,
			err);
		return -err;
	}

	dev = xnvme_dev_open(f->file_name, &opts);
	if (!dev) {
		log_err("ioeng->report_zones(%s): xnvme_dev_open(), err(%d)\n", f->file_name,
			errno);
		goto exit;
	}

	geo = xnvme_dev_get_geo(dev);
	ssw = xnvme_dev_get_ssw(dev);
	lbafe = xnvme_znd_dev_get_lbafe(dev);

	limit = nr_zones > geo->nzone ? geo->nzone : nr_zones;

	dprint(FD_ZBD, "%s: limit: %u\n", f->file_name, limit);

	slba = ((offset >> ssw) / geo->nsect) * geo->nsect;

	rprt = xnvme_znd_report_from_dev(dev, slba, limit, 0);
	if (!rprt) {
		log_err("ioeng->report_zones(%s): xnvme_znd_report_from_dev(), err(%d)\n",
			f->file_name, errno);
		err = -errno;
		goto exit;
	}
	if (rprt->nentries != limit) {
		log_err("ioeng->report_zones(%s): nentries != nr_zones\n", f->file_name);
		err = 1;
		goto exit;
	}
	if (offset > geo->tbytes) {
		log_err("ioeng->report_zones(%s): out-of-bounds\n", f->file_name);
		goto exit;
	}

	/* Transform the zone-report */
	for (uint32_t idx = 0; idx < rprt->nentries; ++idx) {
		struct xnvme_spec_znd_descr *descr = XNVME_ZND_REPORT_DESCR(rprt, idx);

		zbdz[idx].start = descr->zslba << ssw;
		zbdz[idx].len = lbafe->zsze << ssw;
		zbdz[idx].capacity = descr->zcap << ssw;
		zbdz[idx].wp = descr->wp << ssw;

		switch (descr->zt) {
		case XNVME_SPEC_ZND_TYPE_SEQWR:
			zbdz[idx].type = ZBD_ZONE_TYPE_SWR;
			break;

		default:
			log_err("ioeng->report_zones(%s): invalid type for zone at offset(%zu)\n",
				f->file_name, zbdz[idx].start);
			err = -EIO;
			goto exit;
		}

		switch (descr->zs) {
		case XNVME_SPEC_ZND_STATE_EMPTY:
			zbdz[idx].cond = ZBD_ZONE_COND_EMPTY;
			break;
		case XNVME_SPEC_ZND_STATE_IOPEN:
			zbdz[idx].cond = ZBD_ZONE_COND_IMP_OPEN;
			break;
		case XNVME_SPEC_ZND_STATE_EOPEN:
			zbdz[idx].cond = ZBD_ZONE_COND_EXP_OPEN;
			break;
		case XNVME_SPEC_ZND_STATE_CLOSED:
			zbdz[idx].cond = ZBD_ZONE_COND_CLOSED;
			break;
		case XNVME_SPEC_ZND_STATE_FULL:
			zbdz[idx].cond = ZBD_ZONE_COND_FULL;
			break;

		case XNVME_SPEC_ZND_STATE_RONLY:
		case XNVME_SPEC_ZND_STATE_OFFLINE:
		default:
			zbdz[idx].cond = ZBD_ZONE_COND_OFFLINE;
			break;
		}
	}

exit:
	xnvme_buf_virt_free(rprt);

	xnvme_dev_close(dev);

	err_lock = pthread_mutex_unlock(&g_serialize);
	if (err_lock)
		log_err("ioeng->report_zones(): pthread_mutex_unlock(), err: %d\n", err_lock);

	dprint(FD_ZBD, "err: %d, nr_zones: %d\n", err, (int)nr_zones);

	return err ? err : (int)limit;
}

/**
 * NOTE: This function may get called before I/O engine initialization, that is,
 * before ``_dev_open`` has been called and file-wrapping is setup. In such
 * case it has to do ``_dev_open`` itself, and shut it down again once it is
 * done resetting write pointer of zones.
 */
static int xnvme_fioe_reset_wp(struct thread_data *td, struct fio_file *f, uint64_t offset,
			       uint64_t length)
{
	struct xnvme_opts opts = xnvme_opts_from_fioe(td);
	struct xnvme_fioe_data *xd = NULL;
	struct xnvme_fioe_fwrap *fwrap = NULL;
	struct xnvme_dev *dev = NULL;
	const struct xnvme_geo *geo = NULL;
	uint64_t first, last;
	uint32_t ssw;
	uint32_t nsid;
	int err = 0, err_lock;

	if (td->io_ops_data) {
		xd = td->io_ops_data;
		fwrap = &xd->files[f->fileno];

		assert(fwrap->dev);
		assert(fwrap->geo);

		dev = fwrap->dev;
		geo = fwrap->geo;
		ssw = fwrap->ssw;
	} else {
		err = pthread_mutex_lock(&g_serialize);
		if (err) {
			log_err("ioeng->reset_wp(): pthread_mutex_lock(), err(%d)\n", err);
			return -err;
		}

		dev = xnvme_dev_open(f->file_name, &opts);
		if (!dev) {
			log_err("ioeng->reset_wp(): xnvme_dev_open(%s) failed, errno(%d)\n",
				f->file_name, errno);
			goto exit;
		}
		geo = xnvme_dev_get_geo(dev);
		ssw = xnvme_dev_get_ssw(dev);
	}

	nsid = xnvme_dev_get_nsid(dev);

	first = ((offset >> ssw) / geo->nsect) * geo->nsect;
	last = (((offset + length) >> ssw) / geo->nsect) * geo->nsect;
	dprint(FD_ZBD, "first: 0x%lx, last: 0x%lx\n", first, last);

	for (uint64_t zslba = first; zslba < last; zslba += geo->nsect) {
		struct xnvme_cmd_ctx ctx = xnvme_cmd_ctx_from_dev(dev);

		if (zslba >= (geo->nsect * geo->nzone)) {
			log_err("ioeng->reset_wp(): out-of-bounds\n");
			err = 0;
			break;
		}

		err = xnvme_znd_mgmt_send(&ctx, nsid, zslba, false,
					  XNVME_SPEC_ZND_CMD_MGMT_SEND_RESET, 0x0, NULL);
		if (err || xnvme_cmd_ctx_cpl_status(&ctx)) {
			err = err ? err : -EIO;
			log_err("ioeng->reset_wp(): err(%d), sc(%d)", err, ctx.cpl.status.sc);
			goto exit;
		}
	}

exit:
	if (!td->io_ops_data) {
		xnvme_dev_close(dev);

		err_lock = pthread_mutex_unlock(&g_serialize);
		if (err_lock)
			log_err("ioeng->reset_wp(): pthread_mutex_unlock(), err(%d)\n", err_lock);
	}

	return err;
}

static int xnvme_fioe_fetch_ruhs(struct thread_data *td, struct fio_file *f,
				 struct fio_ruhs_info *fruhs_info)
{
	struct xnvme_opts opts = xnvme_opts_from_fioe(td);
	struct xnvme_dev *dev;
	struct xnvme_spec_ruhs *ruhs;
	struct xnvme_cmd_ctx ctx;
	uint32_t ruhs_nbytes, nr_ruhs;
	uint32_t nsid;
	int err = 0, err_lock;

	if (f->filetype != FIO_TYPE_CHAR && f->filetype != FIO_TYPE_FILE) {
		log_err("ioeng->fdp_ruhs(): ignoring filetype: %d\n", f->filetype);
		return -EINVAL;
	}

	err = pthread_mutex_lock(&g_serialize);
	if (err) {
		log_err("ioeng->fdp_ruhs(): pthread_mutex_lock(), err(%d)\n", err);
		return -err;
	}

	dev = xnvme_dev_open(f->file_name, &opts);
	if (!dev) {
		log_err("ioeng->fdp_ruhs(): xnvme_dev_open(%s) failed, errno: %d\n",
			f->file_name, errno);
		err = -errno;
		goto exit;
	}

	nr_ruhs = fruhs_info->nr_ruhs;
	ruhs_nbytes = sizeof(*ruhs) + (fruhs_info->nr_ruhs * sizeof(struct xnvme_spec_ruhs_desc));
	ruhs = xnvme_buf_alloc(dev, ruhs_nbytes);
	if (!ruhs) {
		err = -errno;
		goto exit;
	}
	memset(ruhs, 0, ruhs_nbytes);

	ctx = xnvme_cmd_ctx_from_dev(dev);
	nsid = xnvme_dev_get_nsid(dev);

	err = xnvme_nvm_mgmt_recv(&ctx, nsid, XNVME_SPEC_IO_MGMT_RECV_RUHS, 0, ruhs, ruhs_nbytes);

	if (err || xnvme_cmd_ctx_cpl_status(&ctx)) {
		err = err ? err : -EIO;
		log_err("ioeng->fdp_ruhs(): err(%d), sc(%d)", err, ctx.cpl.status.sc);
		goto free_buffer;
	}

	fruhs_info->nr_ruhs = ruhs->nruhsd;
	for (uint32_t idx = 0; idx < nr_ruhs; ++idx) {
		fruhs_info->plis[idx] = le16_to_cpu(ruhs->desc[idx].pi);
	}

free_buffer:
	xnvme_buf_free(dev, ruhs);
exit:
	xnvme_dev_close(dev);

	err_lock = pthread_mutex_unlock(&g_serialize);
	if (err_lock)
		log_err("ioeng->fdp_ruhs(): pthread_mutex_unlock(), err(%d)\n", err_lock);

	return err;
}

static int xnvme_fioe_get_file_size(struct thread_data *td, struct fio_file *f)
{
	struct xnvme_opts opts = xnvme_opts_from_fioe(td);
	struct xnvme_dev *dev;
	int ret = 0, err;

	if (fio_file_size_known(f))
		return 0;

	ret = pthread_mutex_lock(&g_serialize);
	if (ret) {
		log_err("ioeng->reset_wp(): pthread_mutex_lock(), err(%d)\n", ret);
		return -ret;
	}

	dev = xnvme_dev_open(f->file_name, &opts);
	if (!dev) {
		log_err("%s: failed retrieving device handle, errno: %d\n", f->file_name, errno);
		ret = -errno;
		goto exit;
	}

	f->real_file_size = xnvme_dev_get_geo(dev)->tbytes;
	fio_file_set_size_known(f);

	if (td->o.zone_mode == ZONE_MODE_ZBD)
		f->filetype = FIO_TYPE_BLOCK;

exit:
	xnvme_dev_close(dev);
	err = pthread_mutex_unlock(&g_serialize);
	if (err)
		log_err("ioeng->reset_wp(): pthread_mutex_unlock(), err(%d)\n", err);

	return ret;
}

FIO_STATIC struct ioengine_ops ioengine = {
	.name = "xnvme",
	.version = FIO_IOOPS_VERSION,
	.options = options,
	.option_struct_size = sizeof(struct xnvme_fioe_options),
	.flags = FIO_DISKLESSIO | FIO_NODISKUTIL | FIO_NOEXTEND | FIO_MEMALIGN | FIO_RAWIO,

	.cleanup = xnvme_fioe_cleanup,
	.init = xnvme_fioe_init,

	.iomem_free = xnvme_fioe_iomem_free,
	.iomem_alloc = xnvme_fioe_iomem_alloc,

	.io_u_free = xnvme_fioe_io_u_free,
	.io_u_init = xnvme_fioe_io_u_init,

	.event = xnvme_fioe_event,
	.getevents = xnvme_fioe_getevents,
	.queue = xnvme_fioe_queue,

	.close_file = xnvme_fioe_close,
	.open_file = xnvme_fioe_open,
	.get_file_size = xnvme_fioe_get_file_size,

	.invalidate = xnvme_fioe_invalidate,
	.get_max_open_zones = xnvme_fioe_get_max_open_zones,
	.get_zoned_model = xnvme_fioe_get_zoned_model,
	.report_zones = xnvme_fioe_report_zones,
	.reset_wp = xnvme_fioe_reset_wp,

	.fdp_fetch_ruhs = xnvme_fioe_fetch_ruhs,
};

static void fio_init fio_xnvme_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_xnvme_unregister(void)
{
	unregister_ioengine(&ioengine);
}
