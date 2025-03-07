/**
 * FIO engine for DAOS File System (dfs).
 *
 * (C) Copyright 2020-2021 Intel Corporation.
 */

#include <fio.h>
#include <optgroup.h>

#include <daos.h>
#include <daos_fs.h>

static bool		daos_initialized;
static int		num_threads;
static pthread_mutex_t	daos_mutex = PTHREAD_MUTEX_INITIALIZER;
daos_handle_t		poh;  /* pool handle */
daos_handle_t		coh;  /* container handle */
daos_oclass_id_t	cid = OC_UNKNOWN;  /* object class */
dfs_t			*daosfs; /* dfs mount reference */

struct daos_iou {
	struct io_u	*io_u;
	daos_event_t	ev;
	d_sg_list_t	sgl;
	d_iov_t		iov;
	daos_size_t	size;
	bool		complete;
};

struct daos_data {
	daos_handle_t	eqh;
	dfs_obj_t	*obj;
	struct io_u	**io_us;
	int		queued;
	int		num_ios;
};

struct daos_fio_options {
	void		*pad;
	char		*pool;   /* Pool UUID */
	char		*cont;   /* Container UUID */
	daos_size_t	chsz;    /* Chunk size */
	char		*oclass; /* object class */
#if !defined(DAOS_API_VERSION_MAJOR) || DAOS_API_VERSION_MAJOR < 1
	char		*svcl;   /* service replica list, deprecated */
#endif
};

static struct fio_option options[] = {
	{
		.name		= "pool",
		.lname		= "pool uuid or label",
		.type		= FIO_OPT_STR_STORE,
		.off1		= offsetof(struct daos_fio_options, pool),
		.help		= "DAOS pool uuid or label",
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_DFS,
	},
	{
		.name           = "cont",
		.lname          = "container uuid or label",
		.type           = FIO_OPT_STR_STORE,
		.off1           = offsetof(struct daos_fio_options, cont),
		.help           = "DAOS container uuid or label",
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_DFS,
	},
	{
		.name           = "chunk_size",
		.lname          = "DFS chunk size",
		.type           = FIO_OPT_ULL,
		.off1           = offsetof(struct daos_fio_options, chsz),
		.help           = "DFS chunk size in bytes",
		.def		= "0", /* use container default */
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_DFS,
	},
	{
		.name           = "object_class",
		.lname          = "object class",
		.type           = FIO_OPT_STR_STORE,
		.off1           = offsetof(struct daos_fio_options, oclass),
		.help           = "DAOS object class",
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_DFS,
	},
#if !defined(DAOS_API_VERSION_MAJOR) || DAOS_API_VERSION_MAJOR < 1
	{
		.name           = "svcl",
		.lname          = "List of service ranks",
		.type           = FIO_OPT_STR_STORE,
		.off1           = offsetof(struct daos_fio_options, svcl),
		.help           = "List of pool replicated service ranks",
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_DFS,
	},
#endif
	{
		.name           = NULL,
	},
};

static int daos_fio_global_init(struct thread_data *td)
{
	struct daos_fio_options	*eo = td->eo;
	daos_pool_info_t	pool_info;
	daos_cont_info_t	co_info;
	int			rc = 0;

#if !defined(DAOS_API_VERSION_MAJOR) || DAOS_API_VERSION_MAJOR < 1
	if (!eo->pool || !eo->cont || !eo->svcl) {
#else
	if (!eo->pool || !eo->cont) {
#endif
		log_err("Missing required DAOS options\n");
		return EINVAL;
	}

	rc = daos_init();
	if (rc != -DER_ALREADY && rc) {
		log_err("Failed to initialize daos %d\n", rc);
		td_verror(td, rc, "daos_init");
		return rc;
	}

#if !defined(DAOS_API_VERSION_MAJOR) || \
    (DAOS_API_VERSION_MAJOR == 1 && DAOS_API_VERSION_MINOR < 3)
	uuid_t pool_uuid, co_uuid;

	rc = uuid_parse(eo->pool, pool_uuid);
	if (rc) {
		log_err("Failed to parse 'Pool uuid': %s\n", eo->pool);
		td_verror(td, EINVAL, "uuid_parse(eo->pool)");
		return EINVAL;
	}

	rc = uuid_parse(eo->cont, co_uuid);
	if (rc) {
		log_err("Failed to parse 'Cont uuid': %s\n", eo->cont);
		td_verror(td, EINVAL, "uuid_parse(eo->cont)");
		return EINVAL;
	}
#endif

	/* Connect to the DAOS pool */
#if !defined(DAOS_API_VERSION_MAJOR) || DAOS_API_VERSION_MAJOR < 1
	d_rank_list_t *svcl = NULL;

	svcl = daos_rank_list_parse(eo->svcl, ":");
	if (svcl == NULL) {
		log_err("Failed to parse svcl\n");
		td_verror(td, EINVAL, "daos_rank_list_parse");
		return EINVAL;
	}

	rc = daos_pool_connect(pool_uuid, NULL, svcl, DAOS_PC_RW,
			&poh, &pool_info, NULL);
	d_rank_list_free(svcl);
#elif (DAOS_API_VERSION_MAJOR == 1 && DAOS_API_VERSION_MINOR < 3)
	rc = daos_pool_connect(pool_uuid, NULL, DAOS_PC_RW, &poh, &pool_info,
			       NULL);
#else
	rc = daos_pool_connect(eo->pool, NULL, DAOS_PC_RW, &poh, &pool_info,
			       NULL);
#endif
	if (rc) {
		log_err("Failed to connect to pool %d\n", rc);
		td_verror(td, rc, "daos_pool_connect");
		return rc;
	}

	/* Open the DAOS container */
#if !defined(DAOS_API_VERSION_MAJOR) || \
    (DAOS_API_VERSION_MAJOR == 1 && DAOS_API_VERSION_MINOR < 3)
	rc = daos_cont_open(poh, co_uuid, DAOS_COO_RW, &coh, &co_info, NULL);
#else
	rc = daos_cont_open(poh, eo->cont, DAOS_COO_RW, &coh, &co_info, NULL);
#endif
	if (rc) {
		log_err("Failed to open container: %d\n", rc);
		td_verror(td, rc, "daos_cont_open");
		(void)daos_pool_disconnect(poh, NULL);
		return rc;
	}

	/* Mount encapsulated filesystem */
	rc = dfs_mount(poh, coh, O_RDWR, &daosfs);
	if (rc) {
		log_err("Failed to mount DFS namespace: %d\n", rc);
		td_verror(td, rc, "dfs_mount");
		(void)daos_pool_disconnect(poh, NULL);
		(void)daos_cont_close(coh, NULL);
		return rc;
	}

	/* Retrieve object class to use, if specified */
	if (eo->oclass)
		cid = daos_oclass_name2id(eo->oclass);

	return 0;
}

static int daos_fio_global_cleanup()
{
	int rc;
	int ret = 0;

	rc = dfs_umount(daosfs);
	if (rc) {
		log_err("failed to umount dfs: %d\n", rc);
		ret = rc;
	}
	rc = daos_cont_close(coh, NULL);
	if (rc) {
		log_err("failed to close container: %d\n", rc);
		if (ret == 0)
			ret = rc;
	}
	rc = daos_pool_disconnect(poh, NULL);
	if (rc) {
		log_err("failed to disconnect pool: %d\n", rc);
		if (ret == 0)
			ret = rc;
	}
	rc = daos_fini();
	if (rc) {
		log_err("failed to finalize daos: %d\n", rc);
		if (ret == 0)
			ret = rc;
	}

	return ret;
}

static int daos_fio_setup(struct thread_data *td)
{
	return 0;
}

static int daos_fio_init(struct thread_data *td)
{
	struct daos_data	*dd;
	int			rc = 0;

	pthread_mutex_lock(&daos_mutex);

	dd = malloc(sizeof(*dd));
	if (dd == NULL) {
		log_err("Failed to allocate DAOS-private data\n");
		rc = ENOMEM;
		goto out;
	}

	dd->queued	= 0;
	dd->num_ios	= td->o.iodepth;
	dd->io_us	= calloc(dd->num_ios, sizeof(struct io_u *));
	if (dd->io_us == NULL) {
		log_err("Failed to allocate IO queue\n");
		rc = ENOMEM;
		goto out;
	}

	/* initialize DAOS stack if not already up */
	if (!daos_initialized) {
		rc = daos_fio_global_init(td);
		if (rc)
			goto out;
		daos_initialized = true;
	}

	rc = daos_eq_create(&dd->eqh);
	if (rc) {
		log_err("Failed to create event queue: %d\n", rc);
		td_verror(td, rc, "daos_eq_create");
		goto out;
	}

	td->io_ops_data = dd;
	num_threads++;
out:
	if (rc) {
		if (dd) {
			free(dd->io_us);
			free(dd);
		}
		if (num_threads == 0 && daos_initialized) {
			/* don't clobber error return value */
			(void)daos_fio_global_cleanup();
			daos_initialized = false;
		}
	}
	pthread_mutex_unlock(&daos_mutex);
	return rc;
}

static void daos_fio_cleanup(struct thread_data *td)
{
	struct daos_data	*dd = td->io_ops_data;
	int			rc;

	if (dd == NULL)
		return;

	rc = daos_eq_destroy(dd->eqh, DAOS_EQ_DESTROY_FORCE);
	if (rc < 0) {
		log_err("failed to destroy event queue: %d\n", rc);
		td_verror(td, rc, "daos_eq_destroy");
	}

	free(dd->io_us);
	free(dd);

	pthread_mutex_lock(&daos_mutex);
	num_threads--;
	if (daos_initialized && num_threads == 0) {
		int ret;

		ret = daos_fio_global_cleanup();
		if (ret < 0 && rc == 0) {
			log_err("failed to clean up: %d\n", ret);
			td_verror(td, ret, "daos_fio_global_cleanup");
		}
		daos_initialized = false;
	}
	pthread_mutex_unlock(&daos_mutex);
}

static int daos_fio_get_file_size(struct thread_data *td, struct fio_file *f)
{
	char		*file_name = f->file_name;
	struct stat	stbuf = {0};
	int		rc;

	dprint(FD_FILE, "dfs stat %s\n", f->file_name);

	if (!daos_initialized)
		return 0;

	rc = dfs_stat(daosfs, NULL, file_name, &stbuf);
	if (rc) {
		log_err("Failed to stat %s: %d\n", f->file_name, rc);
		td_verror(td, rc, "dfs_stat");
		return rc;
	}

	f->real_file_size = stbuf.st_size;
	return 0;
}

static int daos_fio_close(struct thread_data *td, struct fio_file *f)
{
	struct daos_data	*dd = td->io_ops_data;
	int			rc;

	dprint(FD_FILE, "dfs release %s\n", f->file_name);

	rc = dfs_release(dd->obj);
	if (rc) {
		log_err("Failed to release %s: %d\n", f->file_name, rc);
		td_verror(td, rc, "dfs_release");
		return rc;
	}

	return 0;
}

static int daos_fio_open(struct thread_data *td, struct fio_file *f)
{
	struct daos_data	*dd = td->io_ops_data;
	struct daos_fio_options	*eo = td->eo;
	int			flags = 0;
	int			rc;

	dprint(FD_FILE, "dfs open %s (%s/%d/%d)\n",
	       f->file_name, td_write(td) & !read_only ? "rw" : "r",
	       td->o.create_on_open, td->o.allow_create);

	if (td->o.create_on_open && td->o.allow_create)
		flags |= O_CREAT;

	if (td_write(td)) {
		if (!read_only)
			flags |= O_RDWR;
		if (td->o.allow_create)
			flags |= O_CREAT;
	} else if (td_read(td)) {
		flags |= O_RDONLY;
	}

	rc = dfs_open(daosfs, NULL, f->file_name,
		      S_IFREG | S_IRUSR | S_IWUSR,
		      flags, cid, eo->chsz, NULL, &dd->obj);
	if (rc) {
		log_err("Failed to open %s: %d\n", f->file_name, rc);
		td_verror(td, rc, "dfs_open");
		return rc;
	}

	return 0;
}

static int daos_fio_unlink(struct thread_data *td, struct fio_file *f)
{
	int rc;

	dprint(FD_FILE, "dfs remove %s\n", f->file_name);

	rc = dfs_remove(daosfs, NULL, f->file_name, false, NULL);
	if (rc) {
		log_err("Failed to remove %s: %d\n", f->file_name, rc);
		td_verror(td, rc, "dfs_remove");
		return rc;
	}

	return 0;
}

static int daos_fio_invalidate(struct thread_data *td, struct fio_file *f)
{
	dprint(FD_FILE, "dfs invalidate %s\n", f->file_name);
	return 0;
}

static void daos_fio_io_u_free(struct thread_data *td, struct io_u *io_u)
{
	struct daos_iou *io = io_u->engine_data;

	if (io) {
		io_u->engine_data = NULL;
		free(io);
	}
}

static int daos_fio_io_u_init(struct thread_data *td, struct io_u *io_u)
{
	struct daos_iou *io;

	io = malloc(sizeof(struct daos_iou));
	if (!io) {
		td_verror(td, ENOMEM, "malloc");
		return ENOMEM;
	}
	io->io_u = io_u;
	io_u->engine_data = io;
	return 0;
}

static struct io_u * daos_fio_event(struct thread_data *td, int event)
{
	struct daos_data *dd = td->io_ops_data;

	return dd->io_us[event];
}

static int daos_fio_getevents(struct thread_data *td, unsigned int min,
			      unsigned int max, const struct timespec *t)
{
	struct daos_data	*dd = td->io_ops_data;
	daos_event_t		*evp[max];
	unsigned int		events = 0;
	int			i;
	int			rc;

	while (events < min) {
		rc = daos_eq_poll(dd->eqh, 0, DAOS_EQ_NOWAIT, max, evp);
		if (rc < 0) {
			log_err("Event poll failed: %d\n", rc);
			td_verror(td, rc, "daos_eq_poll");
			return events;
		}

		for (i = 0; i < rc; i++) {
			struct daos_iou	*io;
			struct io_u	*io_u;

			io = container_of(evp[i], struct daos_iou, ev);
			if (io->complete)
				log_err("Completion on already completed I/O\n");

			io_u = io->io_u;
			if (io->ev.ev_error)
				io_u->error = io->ev.ev_error;
			else
				io_u->resid = 0;

			dd->io_us[events] = io_u;
			dd->queued--;
			daos_event_fini(&io->ev);
			io->complete = true;
			events++;
		}
	}

	dprint(FD_IO, "dfs eq_pool returning %d (%u/%u)\n", events, min, max);

	return events;
}

static enum fio_q_status daos_fio_queue(struct thread_data *td,
					struct io_u *io_u)
{
	struct daos_data	*dd = td->io_ops_data;
	struct daos_iou		*io = io_u->engine_data;
	daos_off_t		offset = io_u->offset;
	int			rc;

	if (dd->queued == td->o.iodepth)
		return FIO_Q_BUSY;

	io->sgl.sg_nr = 1;
	io->sgl.sg_nr_out = 0;
	d_iov_set(&io->iov, io_u->xfer_buf, io_u->xfer_buflen);
	io->sgl.sg_iovs = &io->iov;
	io->size = io_u->xfer_buflen;

	io->complete = false;
	rc = daos_event_init(&io->ev, dd->eqh, NULL);
	if (rc) {
		log_err("Event init failed: %d\n", rc);
		io_u->error = rc;
		return FIO_Q_COMPLETED;
	}

	switch (io_u->ddir) {
	case DDIR_WRITE:
		rc = dfs_write(daosfs, dd->obj, &io->sgl, offset, &io->ev);
		if (rc) {
			log_err("dfs_write failed: %d\n", rc);
			io_u->error = rc;
			return FIO_Q_COMPLETED;
		}
		break;
	case DDIR_READ:
		rc = dfs_read(daosfs, dd->obj, &io->sgl, offset, &io->size,
			      &io->ev);
		if (rc) {
			log_err("dfs_read failed: %d\n", rc);
			io_u->error = rc;
			return FIO_Q_COMPLETED;
		}
		break;
	case DDIR_SYNC:
		io_u->error = 0;
		return FIO_Q_COMPLETED;
	default:
		dprint(FD_IO, "Invalid IO type: %d\n", io_u->ddir);
		io_u->error = -DER_INVAL;
		return FIO_Q_COMPLETED;
	}

	dd->queued++;
	return FIO_Q_QUEUED;
}

static int daos_fio_prep(struct thread_data fio_unused *td, struct io_u *io_u)
{
	return 0;
}

/* ioengine_ops for get_ioengine() */
FIO_STATIC struct ioengine_ops ioengine = {
	.name			= "dfs",
	.version		= FIO_IOOPS_VERSION,
	.flags			= FIO_DISKLESSIO | FIO_NODISKUTIL,

	.setup			= daos_fio_setup,
	.init			= daos_fio_init,
	.prep			= daos_fio_prep,
	.cleanup		= daos_fio_cleanup,

	.open_file		= daos_fio_open,
	.invalidate		= daos_fio_invalidate,
	.get_file_size		= daos_fio_get_file_size,
	.close_file		= daos_fio_close,
	.unlink_file		= daos_fio_unlink,

	.queue			= daos_fio_queue,
	.getevents		= daos_fio_getevents,
	.event			= daos_fio_event,
	.io_u_init		= daos_fio_io_u_init,
	.io_u_free		= daos_fio_io_u_free,

	.option_struct_size	= sizeof(struct daos_fio_options),
	.options		= options,
};

static void fio_init fio_dfs_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_dfs_unregister(void)
{
	unregister_ioengine(&ioengine);
}
