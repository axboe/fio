/*
 * sgunmap engine
 *
 * IO engine that uses the Linux SG v3 interface to send UNMAP commands to
 * SCSI devices
 *
 * Based on the sg ioengine
 *
 * This ioengine only supports UNMAP commands for fio trim operation requests
 *
 * sgunmap can batch multiple trim commands together and send multiple ranges
 * with one system call
 *
 * iodepth_batch_submit determines how many ranges are sent with each IOCTL
 *
 * Read and write operations are not supported
 *
 * Only one device is supported for each job
 *
 */
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "../fio.h"

#ifdef FIO_HAVE_SGIO

#define MAX_10B_LBA  0xFFFFFFFFULL
#define SCSI_TIMEOUT_MS 30000   // 30 second timeout; currently no method to override
#define MAX_SB 64               // sense block maximum return size

struct sgio_cmd {
	unsigned char cdb[10];      // only need 10 bytes for UNMAP
	unsigned char sb[MAX_SB];   // add sense block to commands
	int nr;
};

struct sgio_data {
	struct sgio_cmd *cmd;
	void *sgbuf;
	char *sg_unmap_param;
	unsigned int bs;
	int type_checked;
	unsigned int range_count;
	unsigned int completed_range_count;
	struct io_u **io_us;
};

static void sgio_hdr_init(struct sgio_data *sd, struct sg_io_hdr *hdr,
			  struct io_u *io_u)
{
	struct sgio_cmd *sc = sd->cmd;

	memset(hdr, 0, sizeof(*hdr));

	hdr->interface_id = 'S';
	hdr->dxfer_direction = SG_DXFER_TO_DEV;
	hdr->cmd_len = sizeof(sc->cdb);
	hdr->mx_sb_len = sizeof(sc->sb);
	hdr->dxferp = sd->sg_unmap_param;
	hdr->cmdp = sc->cdb;
	hdr->sbp = sc->sb;
	hdr->timeout = SCSI_TIMEOUT_MS;
	hdr->pack_id = io_u->index;
	hdr->usr_ptr = io_u;
	hdr->cmdp[0] = 0x42; // unmap
}

static int fio_sgio_getevents(struct thread_data *td, unsigned int min,
			      unsigned int max,
			      const struct timespec fio_unused *t)
{
	struct sgio_data *sd = td->io_ops_data;

	return sd->completed_range_count;
}

static int fio_sgio_ioctl_doio(struct thread_data *td,
			       struct fio_file *f, struct io_u *io_u)
{
	struct sg_io_hdr *hdr = &io_u->hdr;
	int ret;

	ret = ioctl(f->fd, SG_IO, hdr);
	if (ret < 0)
		return ret;

	/* record if an io error occurred */
	if (hdr->info & SG_INFO_CHECK)
		io_u->error = EIO;

	return 0;
}

static enum fio_q_status fio_sgio_queue(struct thread_data *td,
					struct io_u *io_u)
{
	struct sg_io_hdr *hdr = &io_u->hdr;
	struct sgio_data *sd = td->io_ops_data;
	long long nr_blocks, lba;
	int offset;

	fio_ro_check(td, io_u);

	if (io_u->ddir != DDIR_TRIM) {
		td_verror(td, EINVAL, "sgunmap only supports trim operations");
		return FIO_Q_BUSY;
	}

	if (io_u->xfer_buflen & (sd->bs - 1)) {
		td_verror(td, EINVAL, "sgunmap range not sector aligned");
		return FIO_Q_BUSY;
	}

	nr_blocks = io_u->xfer_buflen / sd->bs;
	lba = io_u->offset / sd->bs;

	if (!sd->range_count)
		sgio_hdr_init(sd, hdr, io_u);

	sd->io_us[sd->range_count] = io_u;

	offset = 8 + 16 * sd->range_count;
	sd->sg_unmap_param[offset] = (unsigned char) ((lba >> 56) & 0xff);
	sd->sg_unmap_param[offset+1] = (unsigned char) ((lba >> 48) & 0xff);
	sd->sg_unmap_param[offset+2] = (unsigned char) ((lba >> 40) & 0xff);
	sd->sg_unmap_param[offset+3] = (unsigned char) ((lba >> 32) & 0xff);
	sd->sg_unmap_param[offset+4] = (unsigned char) ((lba >> 24) & 0xff);
	sd->sg_unmap_param[offset+5] = (unsigned char) ((lba >> 16) & 0xff);
	sd->sg_unmap_param[offset+6] = (unsigned char) ((lba >>  8) & 0xff);
	sd->sg_unmap_param[offset+7] = (unsigned char) (lba & 0xff);
	sd->sg_unmap_param[offset+8] = (unsigned char) ((nr_blocks >> 32) & 0xff);
	sd->sg_unmap_param[offset+9] = (unsigned char) ((nr_blocks >> 16) & 0xff);
	sd->sg_unmap_param[offset+10] = (unsigned char) ((nr_blocks >> 8) & 0xff);
	sd->sg_unmap_param[offset+11] = (unsigned char) (nr_blocks & 0xff);

	sd->range_count++;

	return FIO_Q_QUEUED;
}

static int fio_sgio_commit(struct thread_data *td)
{
	struct sgio_data *sd = td->io_ops_data;
	struct io_u *io_u;
	struct sg_io_hdr *hdr;
	struct timespec now;
	unsigned int i;
	int ret;

	if (!sd->range_count)
		return 0;

	io_u = sd->io_us[0];
	hdr = &io_u->hdr;

	hdr->dxfer_len = sd->range_count * 16 + 8;
	hdr->cmdp[7] = (unsigned char) (((sd->range_count * 16 + 8) >> 8) & 0xff);
	hdr->cmdp[8] = (unsigned char) ((sd->range_count * 16 + 8) & 0xff);

	sd->sg_unmap_param[0] = (unsigned char) (((16 * sd->range_count + 6) >> 8) & 0xff);
	sd->sg_unmap_param[1] = (unsigned char)  ((16 * sd->range_count + 6) & 0xff);
	sd->sg_unmap_param[2] = (unsigned char) (((16 * sd->range_count) >> 8) & 0xff);
	sd->sg_unmap_param[3] = (unsigned char)  ((16 * sd->range_count) & 0xff);

	ret = fio_sgio_ioctl_doio(td, io_u->file, io_u);

	if (ret < 0)
		for (i = 0; i < sd->range_count; i++)
			sd->io_us[i]->error = errno;
	else if (hdr->status)
		for (i = 0; i < sd->range_count; i++) {
			sd->io_us[i]->resid = hdr->resid;
			sd->io_us[i]->error = EIO;
		}
	else {
		if (fio_fill_issue_time(td)) {
			fio_gettime(&now, NULL);
			for (i = 0; i < sd->range_count; i++) {
				struct io_u *io_u = sd->io_us[i];

				memcpy(&io_u->issue_time, &now, sizeof(now));
				io_u_queued(td, io_u);
			}
		}
		io_u_mark_submit(td, sd->range_count);
	}

	if (io_u->error) {
		td_verror(td, io_u->error, "xfer");
		return 0;
	}

	sd->completed_range_count = sd->range_count;
	sd->range_count = 0;

	return ret;
}

static struct io_u *fio_sgio_event(struct thread_data *td, int event)
{
	struct sgio_data *sd = td->io_ops_data;

	return sd->io_us[event];
}

static int fio_sgio_read_capacity(struct thread_data *td, unsigned int *bs,
				  unsigned long long *max_lba)
{
	/*
	 * need to do read capacity operation w/o benefit of sd or
	 * io_u structures, which are not initialized until later.
	 */
	struct sg_io_hdr hdr;
	unsigned char cmd[16];
	unsigned char sb[64];
	unsigned char buf[32];  // read capacity return
	int ret;
	int fd = -1;

	struct fio_file *f = td->files[0];

	/* open file independent of rest of application */
	fd = open(f->file_name, O_RDONLY);
	if (fd < 0)
		return -errno;

	memset(&hdr, 0, sizeof(hdr));
	memset(cmd, 0, sizeof(cmd));
	memset(sb, 0, sizeof(sb));
	memset(buf, 0, sizeof(buf));

	/* First let's try a 10 byte read capacity. */
	hdr.interface_id = 'S';
	hdr.cmdp = cmd;
	hdr.cmd_len = 10;
	hdr.sbp = sb;
	hdr.mx_sb_len = sizeof(sb);
	hdr.timeout = SCSI_TIMEOUT_MS;
	hdr.cmdp[0] = 0x25;  // Read Capacity(10)
	hdr.dxfer_direction = SG_DXFER_FROM_DEV;
	hdr.dxferp = buf;
	hdr.dxfer_len = sizeof(buf);

	ret = ioctl(fd, SG_IO, &hdr);
	if (ret < 0) {
		close(fd);
		return ret;
	}

	*bs	 = ((unsigned long) buf[4] << 24) | ((unsigned long) buf[5] << 16) |
		   ((unsigned long) buf[6] << 8) | (unsigned long) buf[7];
	*max_lba = ((unsigned long) buf[0] << 24) | ((unsigned long) buf[1] << 16) |
		   ((unsigned long) buf[2] << 8) | (unsigned long) buf[3];

	/*
	 * If max lba masked by MAX_10B_LBA equals MAX_10B_LBA,
	 * then need to retry with 16 byte Read Capacity command.
	 */
	if (*max_lba == MAX_10B_LBA) {
		hdr.cmd_len = 16;
		hdr.cmdp[0] = 0x9e; // service action
		hdr.cmdp[1] = 0x10; // Read Capacity(16)
		hdr.cmdp[10] = (unsigned char) ((sizeof(buf) >> 24) & 0xff);
		hdr.cmdp[11] = (unsigned char) ((sizeof(buf) >> 16) & 0xff);
		hdr.cmdp[12] = (unsigned char) ((sizeof(buf) >> 8) & 0xff);
		hdr.cmdp[13] = (unsigned char) (sizeof(buf) & 0xff);

		hdr.dxfer_direction = SG_DXFER_FROM_DEV;
		hdr.dxferp = buf;
		hdr.dxfer_len = sizeof(buf);

		ret = ioctl(fd, SG_IO, &hdr);
		if (ret < 0) {
			close(fd);
			return ret;
		}

		/* record if an io error occurred */
		if (hdr.info & SG_INFO_CHECK)
			td_verror(td, EIO, "fio_sgio_read_capacity");

		*bs = (buf[8] << 24) | (buf[9] << 16) | (buf[10] << 8) | buf[11];
		*max_lba = ((unsigned long long)buf[0] << 56) |
				((unsigned long long)buf[1] << 48) |
				((unsigned long long)buf[2] << 40) |
				((unsigned long long)buf[3] << 32) |
				((unsigned long long)buf[4] << 24) |
				((unsigned long long)buf[5] << 16) |
				((unsigned long long)buf[6] << 8) |
				(unsigned long long)buf[7];
	}

	close(fd);
	return 0;
}

static void fio_sgio_cleanup(struct thread_data *td)
{
	struct sgio_data *sd = td->io_ops_data;

	if (sd) {
		free(sd->cmd);
		free(sd->sgbuf);
		free(sd->sg_unmap_param);
		free(sd->io_us);
		free(sd);
	}
}

static int fio_sgio_init(struct thread_data *td)
{
	struct sgio_data *sd;

	if (td->o.nr_files > 1) {
		log_err("sgunmap: ioengine works only with a single target\n");
		return EINVAL;
	}

	sd = calloc(1, sizeof(*sd));
	sd->cmd = calloc(1, sizeof(struct sgio_cmd));
	sd->sgbuf = calloc(1, sizeof(struct sg_io_hdr));
	sd->sg_unmap_param = calloc(td->o.iodepth + 1, sizeof(char[16]));
	sd->type_checked = 0;
	sd->range_count = 0;
	sd->completed_range_count = 0;
	sd->io_us = calloc(td->o.iodepth, sizeof(struct io_u *));

	td->io_ops_data = sd;

	return 0;
}

static int fio_sgio_type_check(struct thread_data *td, struct fio_file *f)
{
	struct sgio_data *sd = td->io_ops_data;
	unsigned int bs = 0;
	unsigned long long max_lba = 0;

	if (f->filetype == FIO_TYPE_BLOCK) {
		if (ioctl(f->fd, BLKSSZGET, &bs) < 0) {
			td_verror(td, errno, "ioctl");
			return 1;
		}
	} else if (f->filetype == FIO_TYPE_CHAR) {
		int version, ret;

		if (ioctl(f->fd, SG_GET_VERSION_NUM, &version) < 0) {
			td_verror(td, errno, "ioctl");
			return 1;
		}

		ret = fio_sgio_read_capacity(td, &bs, &max_lba);
		if (ret) {
			td_verror(td, td->error, "fio_sgio_read_capacity");
			log_err("ioengine sgunmap unable to read capacity successfully\n");
			return 1;
		}
	} else {
		td_verror(td, EINVAL, "wrong file type");
		log_err("ioengine sgunmap only works on block or character devices\n");
		return 1;
	}

	sd->bs = bs;
	sd->type_checked = 1;

	return 0;
}

static int fio_sgio_open(struct thread_data *td, struct fio_file *f)
{
	struct sgio_data *sd = td->io_ops_data;
	int ret;

	ret = generic_open_file(td, f);
	if (ret)
		return ret;

	if (sd && !sd->type_checked && fio_sgio_type_check(td, f)) {
		ret = generic_close_file(td, f);
		return 1;
	}

	return 0;
}

/*
 * Build an error string with details about the driver, host or scsi
 * error contained in the sg header Caller will use as necessary.
 */
static char *fio_sgio_errdetails(struct io_u *io_u)
{
	struct sg_io_hdr *hdr = &io_u->hdr;
#define MAXERRDETAIL 1024
#define MAXMSGCHUNK  128
	char *msg, msgchunk[MAXMSGCHUNK];
	int i;

	msg = calloc(1, MAXERRDETAIL);
	strcpy(msg, "");

	/*
	 * can't seem to find sg_err.h, so I'll just echo the define values
	 * so others can search on internet to find clearer clues of meaning.
	 */
	if (hdr->info & SG_INFO_CHECK) {
		if (hdr->host_status) {
			snprintf(msgchunk, MAXMSGCHUNK, "SG Host Status: 0x%02x; ", hdr->host_status);
			strlcat(msg, msgchunk, MAXERRDETAIL);
			switch (hdr->host_status) {
			case 0x01:
				strlcat(msg, "SG_ERR_DID_NO_CONNECT", MAXERRDETAIL);
				break;
			case 0x02:
				strlcat(msg, "SG_ERR_DID_BUS_BUSY", MAXERRDETAIL);
				break;
			case 0x03:
				strlcat(msg, "SG_ERR_DID_TIME_OUT", MAXERRDETAIL);
				break;
			case 0x04:
				strlcat(msg, "SG_ERR_DID_BAD_TARGET", MAXERRDETAIL);
				break;
			case 0x05:
				strlcat(msg, "SG_ERR_DID_ABORT", MAXERRDETAIL);
				break;
			case 0x06:
				strlcat(msg, "SG_ERR_DID_PARITY", MAXERRDETAIL);
				break;
			case 0x07:
				strlcat(msg, "SG_ERR_DID_ERROR (internal error)", MAXERRDETAIL);
				break;
			case 0x08:
				strlcat(msg, "SG_ERR_DID_RESET", MAXERRDETAIL);
				break;
			case 0x09:
				strlcat(msg, "SG_ERR_DID_BAD_INTR (unexpected)", MAXERRDETAIL);
				break;
			case 0x0a:
				strlcat(msg, "SG_ERR_DID_PASSTHROUGH", MAXERRDETAIL);
				break;
			case 0x0b:
				strlcat(msg, "SG_ERR_DID_SOFT_ERROR (driver retry?)", MAXERRDETAIL);
				break;
			case 0x0c:
				strlcat(msg, "SG_ERR_DID_IMM_RETRY", MAXERRDETAIL);
				break;
			case 0x0d:
				strlcat(msg, "SG_ERR_DID_REQUEUE", MAXERRDETAIL);
				break;
			case 0x0e:
				strlcat(msg, "SG_ERR_DID_TRANSPORT_DISRUPTED", MAXERRDETAIL);
				break;
			case 0x0f:
				strlcat(msg, "SG_ERR_DID_TRANSPORT_FAILFAST", MAXERRDETAIL);
				break;
			case 0x10:
				strlcat(msg, "SG_ERR_DID_TARGET_FAILURE", MAXERRDETAIL);
				break;
			case 0x11:
				strlcat(msg, "SG_ERR_DID_NEXUS_FAILURE", MAXERRDETAIL);
				break;
			case 0x12:
				strlcat(msg, "SG_ERR_DID_ALLOC_FAILURE", MAXERRDETAIL);
				break;
			case 0x13:
				strlcat(msg, "SG_ERR_DID_MEDIUM_ERROR", MAXERRDETAIL);
				break;
			default:
				strlcat(msg, "Unknown", MAXERRDETAIL);
				break;
			}
			strlcat(msg, ". ", MAXERRDETAIL);
		}
		if (hdr->driver_status) {
			snprintf(msgchunk, MAXMSGCHUNK, "SG Driver Status: 0x%02x; ", hdr->driver_status);
			strlcat(msg, msgchunk, MAXERRDETAIL);
			switch (hdr->driver_status & 0x0F) {
			case 0x01:
				strlcat(msg, "SG_ERR_DRIVER_BUSY", MAXERRDETAIL);
				break;
			case 0x02:
				strlcat(msg, "SG_ERR_DRIVER_SOFT", MAXERRDETAIL);
				break;
			case 0x03:
				strlcat(msg, "SG_ERR_DRIVER_MEDIA", MAXERRDETAIL);
				break;
			case 0x04:
				strlcat(msg, "SG_ERR_DRIVER_ERROR", MAXERRDETAIL);
				break;
			case 0x05:
				strlcat(msg, "SG_ERR_DRIVER_INVALID", MAXERRDETAIL);
				break;
			case 0x06:
				strlcat(msg, "SG_ERR_DRIVER_TIMEOUT", MAXERRDETAIL);
				break;
			case 0x07:
				strlcat(msg, "SG_ERR_DRIVER_HARD", MAXERRDETAIL);
				break;
			case 0x08:
				strlcat(msg, "SG_ERR_DRIVER_SENSE", MAXERRDETAIL);
				break;
			default:
				strlcat(msg, "Unknown", MAXERRDETAIL);
				break;
			}
			strlcat(msg, "; ", MAXERRDETAIL);
			switch (hdr->driver_status & 0xF0) {
			case 0x10:
				strlcat(msg, "SG_ERR_SUGGEST_RETRY", MAXERRDETAIL);
				break;
			case 0x20:
				strlcat(msg, "SG_ERR_SUGGEST_ABORT", MAXERRDETAIL);
				break;
			case 0x30:
				strlcat(msg, "SG_ERR_SUGGEST_REMAP", MAXERRDETAIL);
				break;
			case 0x40:
				strlcat(msg, "SG_ERR_SUGGEST_DIE", MAXERRDETAIL);
				break;
			case 0x80:
				strlcat(msg, "SG_ERR_SUGGEST_SENSE", MAXERRDETAIL);
				break;
			}
			strlcat(msg, ". ", MAXERRDETAIL);
		}
		if (hdr->status) {
			snprintf(msgchunk, MAXMSGCHUNK, "SG SCSI Status: 0x%02x; ", hdr->status);
			strlcat(msg, msgchunk, MAXERRDETAIL);
			// SCSI 3 status codes
			switch (hdr->status) {
			case 0x02:
				strlcat(msg, "CHECK_CONDITION", MAXERRDETAIL);
				break;
			case 0x04:
				strlcat(msg, "CONDITION_MET", MAXERRDETAIL);
				break;
			case 0x08:
				strlcat(msg, "BUSY", MAXERRDETAIL);
				break;
			case 0x10:
				strlcat(msg, "INTERMEDIATE", MAXERRDETAIL);
				break;
			case 0x14:
				strlcat(msg, "INTERMEDIATE_CONDITION_MET", MAXERRDETAIL);
				break;
			case 0x18:
				strlcat(msg, "RESERVATION_CONFLICT", MAXERRDETAIL);
				break;
			case 0x22:
				strlcat(msg, "COMMAND_TERMINATED", MAXERRDETAIL);
				break;
			case 0x28:
				strlcat(msg, "TASK_SET_FULL", MAXERRDETAIL);
				break;
			case 0x30:
				strlcat(msg, "ACA_ACTIVE", MAXERRDETAIL);
				break;
			case 0x40:
				strlcat(msg, "TASK_ABORTED", MAXERRDETAIL);
				break;
			default:
				strlcat(msg, "Unknown", MAXERRDETAIL);
				break;
			}
			strlcat(msg, ". ", MAXERRDETAIL);
		}
		if (hdr->sb_len_wr) {
			snprintf(msgchunk, MAXMSGCHUNK, "Sense Data (%d bytes):", hdr->sb_len_wr);
			strlcat(msg, msgchunk, MAXERRDETAIL);
			for (i = 0; i < hdr->sb_len_wr; i++) {
				snprintf(msgchunk, MAXMSGCHUNK, " %02x", hdr->sbp[i]);
				strlcat(msg, msgchunk, MAXERRDETAIL);
			}
			strlcat(msg, ". ", MAXERRDETAIL);
		}
		if (hdr->resid != 0) {
			snprintf(msgchunk, MAXMSGCHUNK, "SG Driver: %d bytes out of %d not transferred. ", hdr->resid, hdr->dxfer_len);
			strlcat(msg, msgchunk, MAXERRDETAIL);
		}
	}

	if (!(hdr->info & SG_INFO_CHECK) && !strlen(msg))
		strncpy(msg, "SG Driver did not report a Host, Driver or Device check",
			MAXERRDETAIL - 1);

	return msg;
}

/*
 * get max file size from read capacity.
 */
static int fio_sgio_get_file_size(struct thread_data *td, struct fio_file *f)
{
	/*
	 * get_file_size is being called even before sgio_init is
	 * called, so none of the sg_io structures are
	 * initialized in the thread_data yet.  So we need to do the
	 * ReadCapacity without any of those helpers.  One of the effects
	 * is that ReadCapacity may get called 4 times on each open:
	 * readcap(10) followed by readcap(16) if needed - just to get
	 * the file size after the init occurs - it will be called
	 * again when "type_check" is called during structure
	 * initialization I'm not sure how to prevent this little
	 * inefficiency.
	 */
	unsigned int bs = 0;
	unsigned long long max_lba = 0;
	int ret;

	if (fio_file_size_known(f))
		return 0;

	if (f->filetype != FIO_TYPE_BLOCK && f->filetype != FIO_TYPE_CHAR) {
		td_verror(td, EINVAL, "wrong file type");
		log_err("ioengine sgunmap only works on block or character devices\n");
		return 1;
	}

	ret = fio_sgio_read_capacity(td, &bs, &max_lba);
	if (ret) {
		td_verror(td, td->error, "fio_sgio_read_capacity");
		log_err("ioengine sgunmap unable to successfully execute read capacity to get block size and maximum lba\n");
		return 1;
	}

	f->real_file_size = (max_lba + 1) * bs;
	fio_file_set_size_known(f);
	return 0;
}

static struct ioengine_ops ioengine = {
	.name		= "sgunmap",
	.version	= FIO_IOOPS_VERSION,
	.flags		= FIO_ASYNCTRIM,
	.init		= fio_sgio_init,
	.queue		= fio_sgio_queue,
	.commit		= fio_sgio_commit,
	.getevents	= fio_sgio_getevents,
	.errdetails	= fio_sgio_errdetails,
	.event		= fio_sgio_event,
	.cleanup	= fio_sgio_cleanup,
	.open_file	= fio_sgio_open,
	.close_file	= generic_close_file,
	.get_file_size	= fio_sgio_get_file_size,
};

#else /* FIO_HAVE_SGIO */

/*
 * When we have a proper configure system in place, we simply wont build
 * and install this io engine. For now install a crippled version that
 * just complains and fails to load.
 */
static int fio_sgio_init(struct thread_data fio_unused *td)
{
	log_err("fio: ioengine sgunmap not available\n");
	return 1;
}

static struct ioengine_ops ioengine = {
	.name		= "sg",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_sgio_init,
};

#endif

static void fio_init fio_sgio_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_sgio_unregister(void)
{
	unregister_ioengine(&ioengine);
}
