/*
 *  PXV engine
 *
 */
/* Compile with the this command - gcc -g -Wall p.c ../libpxv.a -lz -pthread -ldl -lcrypto -llttng-ust */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <sys/uio.h>
#include <zlib.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/time.h>
#include <pxv.h>
#include <includes.h>
#include "fio.h"
#include "../optgroup.h"

#define PV_JOURNAL_DEVICE   "/dev/sdc"
#define PV_POOL_ID      1
#define PV_META_DEVICE      NULL
#define PV_POOL_DEVICE      "/dev/sdb"
#define PV_BLOCK_SIZE   4096
#define PV_SIZE         (1024ull * 1024ull * 1024ull)
#define PV_POOL_SIZE    10737418240

struct pxv_fio_volume {
	uint64_t vid;
	char *file_name;
};

struct pxv_data {
	struct pxv_options *pxv_opts;
	struct gvol *gvol;
	struct pxv_config pxv_conf;
	char *metadata_dev;
	
	uint64_t pool_size;
	uint64_t pool_id;
	int medium;
	size_t volume_size;
	bool use_direct_io;
	bool initialized;

	/* Test data */
	struct pxv_fio_volume *volumes;
	int num_volumes;
	struct io_u **aio_events;
};

struct fio_pxv_iou {
	struct thread_data *td;
	struct io_u *io_u;
};

/* fio configuration options read from the job file */
struct pxv_options {
	void *pad;
	char *pool_name;
	char *journal_name;
	int direct_io;
};

/* Calculate checksum of a buffer */
static uint32_t
crc_calculate(char *buf, uint32_t size) {
    return adler32(0, (Bytef *)buf, size);
}


static struct fio_option options[] = {
	{
		.name     = "poolname",
		.lname    = "pxv pool name",
		.type     = FIO_OPT_STR_STORE,
		.help     = "Pool Device Name for PXV",
		.off1     = offsetof(struct pxv_options, pool_name),
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_PXV,
	},
	{
		.name     = "journal",
		.lname    = "pxv journal name",
		.type     = FIO_OPT_STR_STORE,
		.help     = "Journal Device Name for PXV",
		.off1     = offsetof(struct pxv_options, journal_name),
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_PXV,
	},
	{
		.name     = "directio",
		.lname    = "use direct IO",
		.type     = FIO_OPT_INT,
		.help     = "Use direct IO to disks for journal and pool",
		.off1     = offsetof(struct pxv_options, direct_io),
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_PXV,
	},
	{
		.name     = NULL,
	},
};


/* ========== End Setup Functions =========== */
static void pxv_delete_volumes(struct thread_data *td)
{
	struct pxv_data *pxv;
	uint64_t vid;
	int i;
	pxv = td->io_ops_data;

	printf("Syncing and deleting Volumes pxv\n");
	for (i = 0; i < pxv->num_volumes; i++) {
		vid = pxv->volumes[i].vid;
		pv_fsync(vid, 0);
		pv_processUpdates(vid);
		pv_vclose(vid);
		pv_vdelete(vid);
	}
}

/* ======== Setup Functions ======== */
static void fio_pxv_cleanup(struct thread_data *td)
{
	struct pxv_data *pxv = td->io_ops_data;

	if (pxv) {
		pxv_delete_volumes(td);
		free(pxv->volumes);
		printf("Shutting down pxv\n");
		pv_stop(pxv->gvol);
		free(pxv->aio_events);
		free(pxv);
	}
}
/* PXV Inits the datastore */
static void pxv_init(struct thread_data *td)
{
	struct pxv_data *pxv = td->io_ops_data;
	struct pxv_config *pxv_conf = &pxv->pxv_conf;

	printf("Starting PXV.\n");

    pxv->gvol = pv_init(NULL, pxv_conf);
    pv_journal(pxv->gvol, pxv->pxv_opts->journal_name, pxv->medium);
    pv_pool(pxv->gvol, pxv->pool_id, pxv->pxv_opts->pool_name, pxv->pool_size, pxv->metadata_dev,
			pxv->medium, pxv->medium, 0);
    pv_replayJournal(pxv->gvol);
	
	pxv->initialized = true;
}
/* Parse all of the info so we can pv_init safely */
static void pxv_setup(struct thread_data *td)
{
	struct pxv_data *pxv = td->io_ops_data;
	struct pxv_options *o = td->eo;
	struct pxv_config *pxv_conf = &pxv->pxv_conf;

    pxv_conf->log_size = (1024ull * 1024ull * 1024ull);
    pxv_conf->crc_calculate = crc_calculate;
    pxv_conf->syncFileRange = false;

	pxv->pool_size = PV_POOL_SIZE;
	pxv->pool_id = PV_POOL_ID;

	pxv->use_direct_io = o->direct_io ? true : false;
	pxv->medium = pxv->use_direct_io ? STORAGE_MEDIUM_SSD : STORAGE_MEDIUM_MAGNETIC;

	pxv->pxv_opts->pool_name = o->pool_name ? o->pool_name : PV_POOL_DEVICE;
	pxv->pxv_opts->journal_name = o->journal_name ? o->journal_name : PV_JOURNAL_DEVICE;
	pxv->metadata_dev = PV_META_DEVICE;

	pxv->initialized = false;
	pxv->num_volumes = td->o.nr_files;
	pxv->volume_size = td->o.size ? td->o.size / pxv->num_volumes : PV_POOL_SIZE;
}

/* Create the requisite volume interfaces to do the IO to */
static void pxv_create_volumes(struct thread_data *td)
{
	struct pxv_data *pxv;
	uint64_t id = 0;
	int i; 

	pxv = td->io_ops_data;
	printf("Creating volumes for PXV.\n");
	pxv->volumes = malloc(pxv->num_volumes * sizeof(uint64_t));
	assert(pxv->volumes);

	for (i = 0; i < pxv->num_volumes; i++) {
		pxv->volumes[i].vid = pv_vcreate(pxv->gvol, pxv->pool_id, id++, 0,
			pxv->volume_size, false, true, NULL);
		pxv->volumes[i].file_name = td->files[i]->file_name;
	}
}

static int _fio_pxv_connect(struct thread_data *td)
{
	struct fio_file *f;
	uint64_t file_size;
	int i;
	/* Setup PXV configuration params */
	pxv_setup(td);

	/* Init PXV datastore */
	pxv_init(td);

	file_size = td->o.size / (td->o.nr_files ? td->o.nr_files : 1u);

	for (i = 0; i < td->o.nr_files; i++) {
		f = td->files[i];
		f->real_file_size = file_size;
	}

	/* Create Volumes */
	pxv_create_volumes(td);

	return 0;
}

static int _fio_setup_pxv_data(struct thread_data *td,
				struct pxv_data **pxv_data_ptr)
{
	struct pxv_data *pxv;

	if (td->io_ops_data)
		return 0;

	pxv = calloc(1, sizeof(struct pxv_data));
	if (!pxv)
		goto failed;

	pxv->initialized = false;

	pxv->pxv_opts = calloc(1, sizeof(struct pxv_options));
	pxv->aio_events = calloc(td->o.iodepth, sizeof(struct io_u *));
	if (!pxv->aio_events)
		goto failed;
	*pxv_data_ptr = pxv;
	return 0;

failed:
	if (pxv) {
		free(pxv->aio_events);
		free(pxv);
	}
	return 1;
}
static int fio_pxv_setup(struct thread_data *td)
{
	struct pxv_data *pxv = NULL;
	int r;
	/* allocate engine specific structure to deal with libpxv. */
	r = _fio_setup_pxv_data(td, &pxv);
	if (r) {
		log_err("fio_setup_pxv_data failed.\n");
		goto cleanup;
	}
	td->io_ops_data = pxv;

	/* Force single process mode.
	*/
	td->o.use_thread = 1;

	_fio_pxv_connect(td);

	return 0;
cleanup:
	fio_pxv_cleanup(td);
	return r;
}


uint64_t get_vid_from_file(struct thread_data *td, char* fname)
{
	struct pxv_data *pxv = td->io_ops_data;
	
	for (int i = 0; i < pxv->num_volumes; i++) {
		if (!strcmp(pxv->volumes[i].file_name, fname)) {
			return pxv->volumes[i].vid;
		};
	}
	log_err("====== Unable to fin vid from fname\n");
	assert(-1);
	return 0;
}

/* Align the buffers and create iovecs to pass to pv_pread/pwrite */
static void newWriteRequest(int iovcnt, struct iovec **iovp, char **bufp,
	uint32_t **crcp)
{
    struct iovec *iov;
    uint32_t *crc;
    char *buf;
    int i;

    if (*bufp == NULL) {
        assert(posix_memalign((void **)bufp, PV_BLOCK_SIZE, iovcnt * PV_BLOCK_SIZE) == 0);
    }
    buf = *bufp;
    if (*iovp == NULL) {
        iov = (struct iovec *)malloc(iovcnt * sizeof(struct iovec));
        *iovp = iov;
    } else {
        iov = *iovp;
    }
    if (*crcp == NULL) {
        crc = (uint32_t *)malloc(iovcnt * sizeof(uint32_t));
        *crcp = crc;
    } else {
        crc = *crcp;
    }
    for (i = 0; i < iovcnt; i++, buf += PV_BLOCK_SIZE) {
        iov[i].iov_base = buf;
        iov[i].iov_len = PV_BLOCK_SIZE;
        crc[i] = crc_calculate(buf, PV_BLOCK_SIZE);
		if (i + 1 == iovcnt)
			break;
    }
}
/*
 * Queue and run the IO
 */
static enum fio_q_status fio_pxv_queue(struct thread_data *td, struct io_u *io_u)
{
	struct iovec *iovp;
	uint32_t *crcp;
    struct pv_version version;
	int err, iovcnt;
	char *buf;
	size_t buf_len, offset;
	uint64_t vid;

	vid = get_vid_from_file(td, io_u->file->file_name); 
	assert(vid != 0);

	iovp = NULL;
	crcp = NULL;
	offset = io_u->offset;
	buf = io_u->xfer_buf;
	buf_len = io_u->xfer_buflen;
	assert(buf_len % PV_BLOCK_SIZE == 0);

	iovcnt = buf_len / PV_BLOCK_SIZE;

	fio_ro_check(td, io_u);

	if (io_u->ddir == DDIR_WRITE) {
		/* New Write Request */
		newWriteRequest(iovcnt, &iovp, &buf, &crcp);
		err = pv_pwritev(vid, offset, buf_len, iovp, iovcnt, &version, crcp, NULL, false);
		if (err != buf_len) {
			log_err(" ======= Write ERROR @!!! %d\n", err);
			goto failed;
		}
		if (true) {
			pv_fsync(vid, 0);
    		pv_processUpdates(vid);
			free(iovp);
			free(crcp);
		}
		return FIO_Q_COMPLETED;
	} else if (io_u->ddir == DDIR_READ) {
    	err = pv_pread(vid, buf, buf_len, offset, NULL, NULL, NULL, NULL);
		if (err != buf_len) {
			log_err(" ======= Read ERROR @!!! %d\n", err);
			goto failed;
		}
		return FIO_Q_COMPLETED;
	} 
	log_err("WARNING: Only DDIR_READ, DDIR_WRITE are supported!");
failed:
	io_u->error = -1;
	td_verror(td, io_u->error, "xfer");
	return FIO_Q_COMPLETED;
}

static struct io_u *fio_pxv_event(struct thread_data *td, int event)
{
	struct pxv_data *pxv = td->io_ops_data;
	return pxv->aio_events[event];
}


int fio_pxv_getevents(struct thread_data *td, unsigned int min,
	unsigned int max, const struct timespec *t)
{
	return 0;
#if 0
	struct pxv_data *pxv = td->io_ops_data;
	struct pxv_options *o = td->eo;
	unsigned int events = 0;
	struct io_u *u;
	struct fio_pxv_iou *fpi;
	unsigned int i;
	rados_completion_t first_unfinished;
	int observed_new = 0;

	/* loop through inflight ios until we find 'min' completions */
	do {
		first_unfinished = NULL;
		io_u_qiter(&td->io_u_all, u, i) {
			if (!(u->flags & IO_U_F_FLIGHT))
				continue;

			fpi = u->engine_data;
			if (fpi->completion) {
				if (rados_aio_is_complete(fpi->completion)) {
					if (fpi->write_op != NULL) {
						rados_release_write_op(fpi->write_op);
						fpi->write_op = NULL;
					}
					rados_aio_release(fpi->completion);
					fpi->completion = NULL;
					rados->aio_events[events] = u;
					events++;
					observed_new = 1;
				} else if (first_unfinished == NULL) {
					first_unfinished = fpi->completion;
				}
			}
			if (events >= max)
				break;
		}
		if (events >= min)
			return events;
		if (first_unfinished == NULL || busy_poll)
			continue;

		if (!observed_new)
			rados_aio_wait_for_complete(first_unfinished);
	} while (1);
  return events;
#endif
}


/* open/invalidate are noops. we set the FIO_DISKLESSIO flag in ioengine_ops to
   prevent fio from creating the files
*/
static int fio_pxv_open(struct thread_data *td, struct fio_file *f)
{
	return 0;
}
static int fio_pxv_invalidate(struct thread_data *td, struct fio_file *f)
{
	return 0;
}

static void fio_pxv_io_u_free(struct thread_data *td, struct io_u *io_u)
{
	struct fio_pxv_iou *fpi = io_u->engine_data;

	if (fpi) {
		io_u->engine_data = NULL;
		fpi->td = NULL;
		free(fpi);
	}
}

static int fio_pxv_io_u_init(struct thread_data *td, struct io_u *io_u)
{
	struct fio_pxv_iou *fpi;
	fpi = calloc(1, sizeof(*fpi));
	fpi->io_u = io_u;
	fpi->td = td;
	io_u->engine_data = fpi;
	return 0;
}

/* ioengine_ops for get_ioengine() */
static struct ioengine_ops ioengine = {
	.name = "pxv",
	.version		= FIO_IOOPS_VERSION,
	.flags			= FIO_DISKLESSIO,
	.setup			= fio_pxv_setup,
	.queue			= fio_pxv_queue,
	.getevents		= fio_pxv_getevents,
	.event			= fio_pxv_event,
	.cleanup		= fio_pxv_cleanup,
	.open_file		= fio_pxv_open,
	.invalidate		= fio_pxv_invalidate,
	.options		= options,
	.io_u_init		= fio_pxv_io_u_init,
	.io_u_free		= fio_pxv_io_u_free,
	.option_struct_size	= sizeof(struct pxv_options),
};

static void fio_init fio_pxv_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_pxv_unregister(void)
{
	unregister_ioengine(&ioengine);
}
