/*
 * libiscsi engine
 *
 * this engine read/write iscsi lun with libiscsi.
 */


#include "../fio.h"
#include "../optgroup.h"

#include <stdlib.h>
#include <iscsi/iscsi.h>
#include <iscsi/scsi-lowlevel.h>
#include <poll.h>

struct iscsi_lun;
struct iscsi_info;

struct iscsi_task {
	struct scsi_task	*scsi_task;
	struct iscsi_lun	*iscsi_lun;
	struct io_u		*io_u;
};

struct iscsi_lun {
	struct iscsi_info	*iscsi_info;
	struct iscsi_context	*iscsi;
	struct iscsi_url        *url;
	int			 block_size;
	uint64_t		 num_blocks;
};

struct iscsi_info {
	struct iscsi_lun	**luns;
	int			  nr_luns;
	struct pollfd		 *pfds;
	struct iscsi_task	**complete_events;
	int			  nr_events;
};

struct iscsi_options {
	void	*pad;
	char	*initiator;
};

static struct fio_option options[] = {
	{
		.name	  = "initiator",
		.lname	  = "initiator",
		.type	  = FIO_OPT_STR_STORE,
		.off1	  = offsetof(struct iscsi_options, initiator),
		.def	  = "iqn.2019-04.org.fio:fio",
		.help	  = "initiator name",
		.category = FIO_OPT_C_ENGINE,
		.group	  = FIO_OPT_G_ISCSI,
	},

	{
		.name = NULL,
	},
};

static int fio_iscsi_setup_lun(struct iscsi_info *iscsi_info,
			       char *initiator, struct fio_file *f, int i)
{
	struct iscsi_lun		*iscsi_lun  = NULL;
	struct scsi_task		*task	    = NULL;
	struct scsi_readcapacity16	*rc16	    = NULL;
	int				 ret	    = 0;

	iscsi_lun = malloc(sizeof(struct iscsi_lun));
	memset(iscsi_lun, 0, sizeof(struct iscsi_lun));

	iscsi_lun->iscsi_info = iscsi_info;

	iscsi_lun->url = iscsi_parse_full_url(NULL, f->file_name);
	if (iscsi_lun->url == NULL) {
		log_err("iscsi: failed to parse url: %s\n", f->file_name);
		ret = EINVAL;
		goto out;
	}

	iscsi_lun->iscsi = iscsi_create_context(initiator);
	if (iscsi_lun->iscsi == NULL) {
		log_err("iscsi: failed to create iscsi context.\n");
		ret = 1;
		goto out;
	}

	if (iscsi_set_targetname(iscsi_lun->iscsi, iscsi_lun->url->target)) {
		log_err("iscsi: failed to set target name.\n");
		ret = EINVAL;
		goto out;
	}

	if (iscsi_set_session_type(iscsi_lun->iscsi, ISCSI_SESSION_NORMAL) != 0) {
		log_err("iscsi: failed to set session type.\n");
		ret = EINVAL;
		goto out;
	}

	if (iscsi_set_header_digest(iscsi_lun->iscsi,
				    ISCSI_HEADER_DIGEST_NONE_CRC32C) != 0) {
		log_err("iscsi: failed to set header digest.\n");
		ret = EINVAL;
		goto out;
	}

	if (iscsi_full_connect_sync(iscsi_lun->iscsi,
				    iscsi_lun->url->portal,
				    iscsi_lun->url->lun)) {
		log_err("sicsi: failed to connect to LUN : %s\n",
			iscsi_get_error(iscsi_lun->iscsi));
		ret = EINVAL;
		goto out;
	}

	task = iscsi_readcapacity16_sync(iscsi_lun->iscsi, iscsi_lun->url->lun);
	if (task == NULL || task->status != SCSI_STATUS_GOOD) {
		log_err("iscsi: failed to send readcapacity command: %s\n",
			iscsi_get_error(iscsi_lun->iscsi));
		ret = EINVAL;
		goto out;
	}

	rc16 = scsi_datain_unmarshall(task);
	if (rc16 == NULL) {
		log_err("iscsi: failed to unmarshal readcapacity16 data.\n");
		ret = EINVAL;
		goto out;
	}

	iscsi_lun->block_size = rc16->block_length;
	iscsi_lun->num_blocks = rc16->returned_lba + 1;

	scsi_free_scsi_task(task);
	task = NULL;

	f->real_file_size = iscsi_lun->num_blocks * iscsi_lun->block_size;
	f->engine_data	  = iscsi_lun;

	iscsi_info->luns[i]    = iscsi_lun;
	iscsi_info->pfds[i].fd = iscsi_get_fd(iscsi_lun->iscsi);

out:
	if (task) {
		scsi_free_scsi_task(task);
	}

	if (ret && iscsi_lun) {
		if (iscsi_lun->iscsi != NULL) {
			if (iscsi_is_logged_in(iscsi_lun->iscsi)) {
				iscsi_logout_sync(iscsi_lun->iscsi);
			}
			iscsi_destroy_context(iscsi_lun->iscsi);
		}
		free(iscsi_lun);
	}

	return ret;
}

static int fio_iscsi_setup(struct thread_data *td)
{
	struct iscsi_options	*options    = td->eo;
	struct iscsi_info	*iscsi_info = NULL;
	int			 ret	    = 0;
	struct fio_file		*f;
	int			 i;

	iscsi_info	    = malloc(sizeof(struct iscsi_info));
	iscsi_info->nr_luns = td->o.nr_files;
	iscsi_info->luns    = calloc(iscsi_info->nr_luns, sizeof(struct iscsi_lun*));
	iscsi_info->pfds    = calloc(iscsi_info->nr_luns, sizeof(struct pollfd));

	iscsi_info->nr_events	    = 0;
	iscsi_info->complete_events = calloc(td->o.iodepth, sizeof(struct iscsi_task*));

	td->io_ops_data = iscsi_info;

	for_each_file(td, f, i) {
		ret = fio_iscsi_setup_lun(iscsi_info, options->initiator, f, i);
		if (ret < 0) break;
	}

	return ret;
}

static int fio_iscsi_init(struct thread_data *td) {
	return 0;
}

static void fio_iscsi_cleanup_lun(struct iscsi_lun *iscsi_lun) {
	if (iscsi_lun->iscsi != NULL) {
		if (iscsi_is_logged_in(iscsi_lun->iscsi)) {
			iscsi_logout_sync(iscsi_lun->iscsi);
		}
		iscsi_destroy_context(iscsi_lun->iscsi);
	}
	free(iscsi_lun);
}

static void fio_iscsi_cleanup(struct thread_data *td)
{
	struct iscsi_info *iscsi_info = td->io_ops_data;

	for (int i = 0; i < iscsi_info->nr_luns; i++) {
		if (iscsi_info->luns[i]) {
			fio_iscsi_cleanup_lun(iscsi_info->luns[i]);
			iscsi_info->luns[i] = NULL;
		}
	}

	free(iscsi_info->luns);
	free(iscsi_info->pfds);
	free(iscsi_info->complete_events);
	free(iscsi_info);
}

static int fio_iscsi_prep(struct thread_data *td, struct io_u *io_u)
{
	return 0;
}

static int fio_iscsi_open_file(struct thread_data *td, struct fio_file *f)
{
	return 0;
}

static int fio_iscsi_close_file(struct thread_data *td, struct fio_file *f)
{
	return 0;
}

static void iscsi_cb(struct iscsi_context *iscsi, int status,
		     void *command_data, void *private_data)
{
	struct iscsi_task	*iscsi_task = (struct iscsi_task*)private_data;
	struct iscsi_lun	*iscsi_lun  = iscsi_task->iscsi_lun;
	struct iscsi_info       *iscsi_info = iscsi_lun->iscsi_info;
	struct io_u             *io_u	    = iscsi_task->io_u;

	if (status == SCSI_STATUS_GOOD) {
		io_u->error = 0;
	} else {
		log_err("iscsi: request failed with error %s.\n",
			iscsi_get_error(iscsi_lun->iscsi));

		io_u->error = 1;
		io_u->resid = io_u->xfer_buflen;
	}

	iscsi_info->complete_events[iscsi_info->nr_events] = iscsi_task;
	iscsi_info->nr_events++;
}

static enum fio_q_status fio_iscsi_queue(struct thread_data *td,
					 struct io_u *io_u)
{
	struct iscsi_lun	*iscsi_lun  = io_u->file->engine_data;
	struct scsi_task	*scsi_task  = NULL;
	struct iscsi_task	*iscsi_task = malloc(sizeof(struct iscsi_task));
	int			 ret	    = -1;

	if (io_u->ddir == DDIR_READ || io_u->ddir == DDIR_WRITE) {
		if (io_u->offset % iscsi_lun->block_size != 0) {
			log_err("iscsi: offset is not align to block size.\n");
			ret = -1;
			goto out;
		}

		if (io_u->xfer_buflen % iscsi_lun->block_size != 0) {
			log_err("iscsi: buflen is not align to block size.\n");
			ret = -1;
			goto out;
		}
	}

	if (io_u->ddir == DDIR_READ) {
		scsi_task = scsi_cdb_read16(io_u->offset / iscsi_lun->block_size,
					    io_u->xfer_buflen,
					    iscsi_lun->block_size,
					    0, 0, 0, 0, 0);
		ret = scsi_task_add_data_in_buffer(scsi_task, io_u->xfer_buflen,
						   io_u->xfer_buf);
		if (ret < 0) {
			log_err("iscsi: failed to add data in buffer.\n");
			goto out;
		}
	} else if (io_u->ddir == DDIR_WRITE) {
		scsi_task = scsi_cdb_write16(io_u->offset / iscsi_lun->block_size,
					     io_u->xfer_buflen,
					     iscsi_lun->block_size,
					     0, 0, 0, 0, 0);
		ret = scsi_task_add_data_out_buffer(scsi_task, io_u->xfer_buflen,
						    io_u->xfer_buf);
		if (ret < 0) {
			log_err("iscsi: failed to add data out buffer.\n");
			goto out;
		}
	} else if (ddir_sync(io_u->ddir)) {
		scsi_task = scsi_cdb_synchronizecache16(
			0, iscsi_lun->num_blocks * iscsi_lun->block_size, 0, 0);
	} else {
		log_err("iscsi: invalid I/O operation: %d\n", io_u->ddir);
		ret = EINVAL;
		goto out;
	}

	iscsi_task->scsi_task = scsi_task;
	iscsi_task->iscsi_lun = iscsi_lun;
	iscsi_task->io_u      = io_u;

	ret = iscsi_scsi_command_async(iscsi_lun->iscsi, iscsi_lun->url->lun,
				       scsi_task, iscsi_cb, NULL, iscsi_task);
	if (ret < 0) {
		log_err("iscsi: failed to send scsi command.\n");
		goto out;
	}

	return FIO_Q_QUEUED;

out:
	if (iscsi_task) {
		free(iscsi_task);
	}

	if (scsi_task) {
		scsi_free_scsi_task(scsi_task);
	}

	if (ret) {
		io_u->error = ret;
	}
	return FIO_Q_COMPLETED;
}

static int fio_iscsi_getevents(struct thread_data *td, unsigned int min,
			       unsigned int max, const struct timespec *t)
{
	struct iscsi_info	*iscsi_info = td->io_ops_data;
	int			 ret	    = 0;

	iscsi_info->nr_events = 0;

	while (iscsi_info->nr_events < min) {
		for (int i = 0; i < iscsi_info->nr_luns; i++) {
			int events = iscsi_which_events(iscsi_info->luns[i]->iscsi);
			iscsi_info->pfds[i].events = events;
		}

		ret = poll(iscsi_info->pfds, iscsi_info->nr_luns, -1);
		if (ret < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			}
			log_err("iscsi: failed to poll events: %s.\n",
				strerror(errno));
			break;
		}

		for (int i = 0; i < iscsi_info->nr_luns; i++) {
			ret = iscsi_service(iscsi_info->luns[i]->iscsi,
					    iscsi_info->pfds[i].revents);
			assert(ret >= 0);
		}
	}

	return ret < 0 ? ret : iscsi_info->nr_events;
}

static struct io_u *fio_iscsi_event(struct thread_data *td, int event)
{
	struct iscsi_info	*iscsi_info = (struct iscsi_info*)td->io_ops_data;
	struct iscsi_task	*iscsi_task = iscsi_info->complete_events[event];
	struct io_u		*io_u	    = iscsi_task->io_u;

	iscsi_info->complete_events[event] = NULL;

	scsi_free_scsi_task(iscsi_task->scsi_task);
	free(iscsi_task);

	return io_u;
}

static struct ioengine_ops ioengine_iscsi = {
	.name               = "libiscsi",
	.version            = FIO_IOOPS_VERSION,
	.flags              = FIO_SYNCIO | FIO_DISKLESSIO | FIO_NODISKUTIL,
	.setup              = fio_iscsi_setup,
	.init               = fio_iscsi_init,
	.prep               = fio_iscsi_prep,
	.queue              = fio_iscsi_queue,
	.getevents          = fio_iscsi_getevents,
	.event              = fio_iscsi_event,
	.cleanup            = fio_iscsi_cleanup,
	.open_file          = fio_iscsi_open_file,
	.close_file         = fio_iscsi_close_file,
	.option_struct_size = sizeof(struct iscsi_options),
	.options	    = options,
};

static void fio_init fio_iscsi_register(void)
{
	register_ioengine(&ioengine_iscsi);
}

static void fio_exit fio_iscsi_unregister(void)
{
	unregister_ioengine(&ioengine_iscsi);
}
