/*
 * sg engine
 *
 * IO engine that uses the Linux SG v3 interface to talk to SCSI devices
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/poll.h>

#include "../fio.h"

#ifdef FIO_HAVE_SGIO

#define MAX_10B_LBA  0xFFFFFFFFULL
#define SCSI_TIMEOUT_MS 30000   // 30 second timeout; currently no method to override
#define MAX_SB 64               // sense block maximum return size
#define FALSE 0
#define TRUE 1

struct sgio_cmd {
	unsigned char cdb[16];  	// increase to support 16 byte commands
	unsigned char sb[MAX_SB];   // add sense block to commands
	int nr;
};

struct sgio_data {
	struct sgio_cmd *cmds;
	struct io_u **events;
	struct pollfd *pfds;
	int *fd_flags;
	void *sgbuf;
	unsigned int bs;
	long long max_lba;
	int type_checked;
};

static void sgio_hdr_init(struct sgio_data *sd, struct sg_io_hdr *hdr,
			  struct io_u *io_u, int fs)
{
	struct sgio_cmd *sc = &sd->cmds[io_u->index];

	memset(hdr, 0, sizeof(*hdr));
	memset(sc->cdb, 0, sizeof(sc->cdb));

	hdr->interface_id = 'S';
	hdr->cmdp = sc->cdb;
	hdr->cmd_len = sizeof(sc->cdb);
	hdr->sbp = sc->sb;
	hdr->mx_sb_len = sizeof(sc->sb);
	hdr->pack_id = io_u->index;
	hdr->usr_ptr = io_u;

	if (fs) {
		hdr->dxferp = io_u->xfer_buf;
		hdr->dxfer_len = io_u->xfer_buflen;
	}
}

static int pollin_events(struct pollfd *pfds, int fds)
{
	int i;

	for (i = 0; i < fds; i++)
		if (pfds[i].revents & POLLIN)
			return 1;

	return 0;
}

static int fio_sgio_getevents(struct thread_data *td, unsigned int min,
			      unsigned int max,
			      const struct timespec fio_unused *t)
{
	struct sgio_data *sd = td->io_ops->data;
	int left = max, eventNum, ret, r = 0;
	void *buf = sd->sgbuf;
	unsigned int i, events;
	struct fio_file *f;

	/*
	 * Fill in the file descriptors
	 */
	for_each_file(td, f, i) {
		/*
		 * don't block for min events == 0
		 */
		if (!min)
			sd->fd_flags[i] = fio_set_fd_nonblocking(f->fd, "sg");
		else
			sd->fd_flags[i] = -1;

		sd->pfds[i].fd = f->fd;
		sd->pfds[i].events = POLLIN;
	}

	while (left) {
		void *p;

		dprint(FD_IO, "sgio_getevents: sd %p: left=%d\n", sd, left);

		do {
			if (!min)
				break;

			ret = poll(sd->pfds, td->o.nr_files, -1);
			if (ret < 0) {
				if (!r)
					r = -errno;
				td_verror(td, errno, "poll");
				break;
			} else if (!ret)
				continue;

			if (pollin_events(sd->pfds, td->o.nr_files))
				break;
		} while (1);

		if (r < 0)
			break;

re_read:
		p = buf;
		events = 0;
		for_each_file(td, f, i) {
			for (eventNum=0; eventNum < left; eventNum++) {
				ret = read(f->fd, p, sizeof(struct sg_io_hdr));
				dprint(FD_IO, "sgio_getevents: ret: %d\n", ret);
				if (ret < 0) {
					if (errno == EAGAIN || errno == EINTR)  // not sure if EINTR is needed, but seems like it should be.
						continue;
					r = -errno;
					td_verror(td, errno, "read");
					break;
				} else if (ret) {
					p += ret;
					events += 1;  /* ret / sizeof(struct sg_io_hdr); */
					dprint(FD_IO, "sgio_getevents: events: %d\n", events);
				}
			}
		}

		if (r < 0)
			break;
		if (!events) {
			usleep(1000);
			goto re_read;
		}

		left -= events;
		r += events;

		for (i = 0; i < events; i++) {
			struct sg_io_hdr *hdr = (struct sg_io_hdr *) buf + i;
			sd->events[i] = hdr->usr_ptr;

			// record if an io error occurred
			if (hdr->info & SG_INFO_CHECK) { // || hdr->resid != 0) { doc indicates that resid can lie, so we won't check
				struct io_u *io_u;
				//printf("cmd: 0x%02x  info: 0x%02x  masked: 0x%02x  host: 0x%02x  driver: 0x%02x  sb_len_wr: 0x%02x  resid: 0x%02x\n",
				//		hdr->cmdp[0], hdr->info, hdr->masked_status, hdr->host_status, hdr->driver_status, hdr->sb_len_wr, hdr->resid);
				// copy the hdr data back into the completed io_u structure so error details can be post processed.
				io_u = (struct io_u *)(hdr->usr_ptr);
				memcpy((void*)&(io_u->hdr), (void*)hdr, sizeof(struct sg_io_hdr));
				sd->events[i]->error = EIO;
			}
		}
	}

	if (!min) {
		for_each_file(td, f, i) {
			if (sd->fd_flags[i] == -1)
				continue;

			if (fcntl(f->fd, F_SETFL, sd->fd_flags[i]) < 0)
				log_err("fio: sg failed to restore fcntl flags: %s\n", strerror(errno));
		}
	}

	return r;
}

static int fio_sgio_ioctl_doio(struct thread_data *td,
			       struct fio_file *f, struct io_u *io_u)
{
	struct sgio_data *sd = td->io_ops->data;
	struct sg_io_hdr *hdr = &io_u->hdr;
	int ret;

	sd->events[0] = io_u;

	ret = ioctl(f->fd, SG_IO, hdr);
	if (ret < 0)
		return ret;

	// record if an io error occurred
	if (hdr->info & SG_INFO_CHECK) {
		io_u->error = EIO;
	}

	return FIO_Q_COMPLETED;
}

static int fio_sgio_rw_doio(struct fio_file *f, struct io_u *io_u, int do_sync)
{
	struct sg_io_hdr *hdr = &io_u->hdr;
	int ret;

	ret = write(f->fd, hdr, sizeof(*hdr));
	if (ret < 0)
		return ret;

	if (do_sync) {
		ret = read(f->fd, hdr, sizeof(*hdr));
		if (ret < 0)
			return ret;

		// record if an io error occurred
		if (hdr->info & SG_INFO_CHECK) {
			io_u->error = EIO;
		}
		return FIO_Q_COMPLETED;
	}

	return FIO_Q_QUEUED;
}

static int fio_sgio_doio(struct thread_data *td, struct io_u *io_u, int do_sync)
{
	struct fio_file *f = io_u->file;
	int ret;

	if (f->filetype == FIO_TYPE_BD) {
		ret = fio_sgio_ioctl_doio(td, f, io_u);
		td->error = io_u->error;
	}
	else {
		ret = fio_sgio_rw_doio(f, io_u, do_sync);
		if (do_sync) td->error = io_u->error;
	}

	return ret;
}

static int fio_sgio_prep(struct thread_data *td, struct io_u *io_u)
{
	struct sg_io_hdr *hdr = &io_u->hdr;
	struct sgio_data *sd = td->io_ops->data;
	long long nr_blocks, lba;

	if (io_u->xfer_buflen & (sd->bs - 1)) {
		log_err("read/write not sector aligned\n");
		return EINVAL;
	}

	nr_blocks = io_u->xfer_buflen / sd->bs;
	lba = io_u->offset / sd->bs;

	if (io_u->ddir == DDIR_READ) {
		sgio_hdr_init(sd, hdr, io_u, 1);

		hdr->dxfer_direction = SG_DXFER_FROM_DEV;
		if (lba < MAX_10B_LBA) hdr->cmdp[0] = 0x28; // read(10)
		else                   hdr->cmdp[0] = 0x88; // read(16)
	} else if (io_u->ddir == DDIR_WRITE) {
		sgio_hdr_init(sd, hdr, io_u, 1);

		hdr->dxfer_direction = SG_DXFER_TO_DEV;
		if (lba < MAX_10B_LBA) hdr->cmdp[0] = 0x2a; // write(10)
		else                   hdr->cmdp[0] = 0x8a; // write(16)
	} else {
		sgio_hdr_init(sd, hdr, io_u, 0);
		hdr->dxfer_direction = SG_DXFER_NONE;
		if (lba < MAX_10B_LBA) hdr->cmdp[0] = 0x35; // synccache(10)
		else                   hdr->cmdp[0] = 0x91; // synccache(16)
	}

	// for synccache, we leave lba and length to 0 to sync all blocks on medium.
	if (hdr->dxfer_direction != SG_DXFER_NONE) {

		if (lba < MAX_10B_LBA) {
			hdr->cmdp[2] = (unsigned char) ((lba >> 24) & 0xff);
			hdr->cmdp[3] = (unsigned char) ((lba >> 16) & 0xff);
			hdr->cmdp[4] = (unsigned char) ((lba >>  8) & 0xff);
			hdr->cmdp[5] = (unsigned char) (lba & 0xff);
			hdr->cmdp[7] = (unsigned char) ((nr_blocks >> 8) & 0xff);
			hdr->cmdp[8] = (unsigned char) (nr_blocks & 0xff);
		}
		else {
			hdr->cmdp[2] = (unsigned char) ((lba >> 56) & 0xff);
			hdr->cmdp[3] = (unsigned char) ((lba >> 48) & 0xff);
			hdr->cmdp[4] = (unsigned char) ((lba >> 40) & 0xff);
			hdr->cmdp[5] = (unsigned char) ((lba >> 32) & 0xff);
			hdr->cmdp[6] = (unsigned char) ((lba >> 24) & 0xff);
			hdr->cmdp[7] = (unsigned char) ((lba >> 16) & 0xff);
			hdr->cmdp[8] = (unsigned char) ((lba >>  8) & 0xff);
			hdr->cmdp[9] = (unsigned char) (lba & 0xff);
			hdr->cmdp[10] = (unsigned char) ((nr_blocks >> 32) & 0xff);
			hdr->cmdp[11] = (unsigned char) ((nr_blocks >> 16) & 0xff);
			hdr->cmdp[12] = (unsigned char) ((nr_blocks >> 8) & 0xff);
			hdr->cmdp[13] = (unsigned char) (nr_blocks & 0xff);
		}
	}

	hdr->timeout = SCSI_TIMEOUT_MS;
	return 0;
}

static int fio_sgio_queue(struct thread_data *td, struct io_u *io_u)
{
	struct sg_io_hdr *hdr = &io_u->hdr;
	int ret, do_sync = 0;

	fio_ro_check(td, io_u);

	if (td->o.sync_io || td->o.odirect || ddir_sync(io_u->ddir))
		do_sync = 1;

	ret = fio_sgio_doio(td, io_u, do_sync);

	if (ret < 0)
		io_u->error = errno;
	else if (hdr->status) {
		io_u->resid = hdr->resid;
		io_u->error = EIO;
	}

	if (io_u->error) {
		td_verror(td, io_u->error, "xfer");
		return FIO_Q_COMPLETED;
	}

	return ret;
}

static struct io_u *fio_sgio_event(struct thread_data *td, int event)
{
	struct sgio_data *sd = td->io_ops->data;

	return sd->events[event];
}

static int fio_sgio_read_capacity(struct thread_data *td, unsigned int *bs, unsigned long long *max_lba)
{
	// need to do read capacity operation w/o benifit of sd or io_u structures, which are not initialized until later.
	struct sg_io_hdr hdr;
	unsigned char cmd[16];
	unsigned char sb[64];
	unsigned char buf[32];  // read capacity return
	int ret;
	int fd = -1;

	struct fio_file *f = td->files[0];

	// open file independent of rest of application
	fd = open(f->file_name, O_RDONLY);
	if (fd < 0) {
		return -errno;
	}

	memset(&hdr, 0, sizeof(hdr));
	memset(cmd, 0, sizeof(cmd));
	memset(sb, 0, sizeof(sb));
	memset(buf, 0, sizeof(buf));

	// First let's try a 10 byte read capacity.
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
	*bs		 = (buf[4] << 24) | (buf[5] << 16) | (buf[6] << 8) | buf[7];
	*max_lba = ((buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]) & 0x00000000FFFFFFFFULL;  // for some reason max_lba is being sign extended even though unsigned.


	// If max lba is 0xFFFFFFFF, then need to retry with 16 byte read capacity
	if (*max_lba == MAX_10B_LBA) {
		hdr.cmd_len = 16;
		hdr.cmdp[0] = 0x9e; // Read Capacity(16)
		hdr.cmdp[1] = 0x10; // service action
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

		// record if an io error occurred
		if (hdr.info & SG_INFO_CHECK) {
			td->error = EIO;
		}

		*bs = (buf[8] << 24) | (buf[9] << 16) | (buf[10] << 8) | buf[11];
		*max_lba = ((unsigned long long)buf[0] << 56) |
				((unsigned long long)buf[1] << 48) |
				((unsigned long long)buf[2] << 40) |
				((unsigned long long)buf[3] << 32) |
				((unsigned long long)buf[4] << 24) |
				((unsigned long long)buf[5] << 16) |
				((unsigned long long)buf[6] << 8) |
				(unsigned long long)buf[7];
		//printf("cmd: 0x%02x  status: 0x%02x\n", hdr->cmdp[0], hdr->status);
	}

	close(fd);

	return 0;
}

static void fio_sgio_cleanup(struct thread_data *td)
{
	struct sgio_data *sd = td->io_ops->data;

	if (sd) {
		free(sd->events);
		free(sd->cmds);
		free(sd->fd_flags);
		free(sd->pfds);
		free(sd->sgbuf);
		free(sd);
	}
}

static int fio_sgio_init(struct thread_data *td)
{
	struct sgio_data *sd;

	sd = malloc(sizeof(*sd));
	memset(sd, 0, sizeof(*sd));
	sd->cmds = malloc(td->o.iodepth * sizeof(struct sgio_cmd));
	memset(sd->cmds, 0, td->o.iodepth * sizeof(struct sgio_cmd));
	sd->events = malloc(td->o.iodepth * sizeof(struct io_u *));
	memset(sd->events, 0, td->o.iodepth * sizeof(struct io_u *));
	sd->pfds = malloc(sizeof(struct pollfd) * td->o.nr_files);
	memset(sd->pfds, 0, sizeof(struct pollfd) * td->o.nr_files);
	sd->fd_flags = malloc(sizeof(int) * td->o.nr_files);
	memset(sd->fd_flags, 0, sizeof(int) * td->o.nr_files);
	sd->sgbuf = malloc(sizeof(struct sg_io_hdr) * td->o.iodepth);
	memset(sd->sgbuf, 0, sizeof(struct sg_io_hdr) * td->o.iodepth);
	sd->type_checked = FALSE;
	td->io_ops->data = sd;

	/*
	 * we want to do it, regardless of whether odirect is set or not
	 */
	td->o.override_sync = 1;
	return 0;
}

static int fio_sgio_type_check(struct thread_data *td, struct fio_file *f)
{
	struct sgio_data *sd = td->io_ops->data;
	unsigned int bs = 0;
	unsigned long long max_lba = 0;


	if (f->filetype == FIO_TYPE_BD) {
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
			log_err("ioengine sg unable to read capacity successfully\n");
			return 1;
		}
	} else {
		td_verror(td, EINVAL, "wrong file type");
		log_err("ioengine sg only works on block devices\n");
		return 1;
	}

	sd->bs = bs;
	// Determine size of commands needed based on max_lba
	sd->max_lba = max_lba;
	if (max_lba > MAX_10B_LBA) {
		dprint(FD_IO, "sgio_type_check: using 16 byte operations: max_lba = 0x%016llx\n", max_lba);
	}


	if (f->filetype == FIO_TYPE_BD) {
		td->io_ops->getevents = NULL;
		td->io_ops->event = NULL;
	}
	sd->type_checked = TRUE;

	return 0;
}

static int fio_sgio_open(struct thread_data *td, struct fio_file *f)
{
	struct sgio_data *sd = td->io_ops->data;
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


#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t size)
{
	size_t dstlen;
	size_t srclen;

	dstlen = strlen(dst);
	size -= dstlen + 1;

	if (!size) return (dstlen); // return if no room

	srclen = strlen(src);
	if (srclen > size) srclen = size;

	memcpy(dst + dstlen, src, srclen);
	dst[dstlen + srclen] = '\0';

	return (dstlen + srclen);
}
#endif /* !HAVE_STRLCAT */

/*
 * Build an error string with details about the driver, host or scsi error contained in the sg header
 * Caller will use as necessary.
 */
static const char *fio_sgio_errdetails(struct io_u *io_u)
{
	struct sg_io_hdr *hdr = &io_u->hdr;
	const char *ret = "SG Driver did not report a Host, Driver or Device check";
#define MAXERRDETAIL 1024
#define MAXMSGCHUNK  128
	static char msg[MAXERRDETAIL];
	static char msgchunk[MAXMSGCHUNK];
	int i;
	msg[0] = '\0';

	// can't seem to find sg_err.h, so I'll just echo the define values so others can search on
	// internet to find clearer clues of meaning.
	if (hdr->info & SG_INFO_CHECK) {
		ret = msg;
		if (hdr->host_status) {
			snprintf(msgchunk, MAXMSGCHUNK, "SG Host Status: 0x%02x; ", hdr->host_status);
			strlcat(msg, msgchunk, MAXERRDETAIL);
			switch (hdr->host_status) {
			case 0x01: strlcat(msg, "SG_ERR_DID_NO_CONNECT", MAXERRDETAIL); break;
			case 0x02: strlcat(msg, "SG_ERR_DID_BUS_BUSY", MAXERRDETAIL); break;
			case 0x03: strlcat(msg, "SG_ERR_DID_TIME_OUT", MAXERRDETAIL); break;
			case 0x04: strlcat(msg, "SG_ERR_DID_BAD_TARGET", MAXERRDETAIL); break;
			case 0x05: strlcat(msg, "SG_ERR_DID_ABORT", MAXERRDETAIL); break;
			case 0x06: strlcat(msg, "SG_ERR_DID_PARITY", MAXERRDETAIL); break;
			case 0x07: strlcat(msg, "SG_ERR_DID_ERROR (internal error)", MAXERRDETAIL); break;
			case 0x08: strlcat(msg, "SG_ERR_DID_RESET", MAXERRDETAIL); break;
			case 0x09: strlcat(msg, "SG_ERR_DID_BAD_INTR (unexpected)", MAXERRDETAIL); break;
			case 0x0a: strlcat(msg, "SG_ERR_DID_PASSTHROUGH", MAXERRDETAIL); break;
			case 0x0b: strlcat(msg, "SG_ERR_DID_SOFT_ERROR (driver retry?)", MAXERRDETAIL); break;
			case 0x0c: strlcat(msg, "SG_ERR_DID_IMM_RETRY", MAXERRDETAIL); break;
			case 0x0d: strlcat(msg, "SG_ERR_DID_REQUEUE", MAXERRDETAIL); break;
			default: strlcat(msg, "Unknown", MAXERRDETAIL); break;
			}
			strlcat(msg, ". ", MAXERRDETAIL);
		}
		if (hdr->driver_status) {
			snprintf(msgchunk, MAXMSGCHUNK, "SG Driver Status: 0x%02x; ", hdr->driver_status);
			strlcat(msg, msgchunk, MAXERRDETAIL);
			switch (hdr->driver_status & 0x0F) {
			case 0x01: strlcat(msg, "SG_ERR_DRIVER_BUSY", MAXERRDETAIL); break;
			case 0x02: strlcat(msg, "SG_ERR_DRIVER_SOFT", MAXERRDETAIL); break;
			case 0x03: strlcat(msg, "SG_ERR_DRIVER_MEDIA", MAXERRDETAIL); break;
			case 0x04: strlcat(msg, "SG_ERR_DRIVER_ERROR", MAXERRDETAIL); break;
			case 0x05: strlcat(msg, "SG_ERR_DRIVER_INVALID", MAXERRDETAIL); break;
			case 0x06: strlcat(msg, "SG_ERR_DRIVER_TIMEOUT", MAXERRDETAIL); break;
			case 0x07: strlcat(msg, "SG_ERR_DRIVER_HARD", MAXERRDETAIL); break;
			case 0x08: strlcat(msg, "SG_ERR_DRIVER_SENSE", MAXERRDETAIL); break;
			default: strlcat(msg, "Unknown", MAXERRDETAIL); break;
			}
			strlcat(msg, "; ", MAXERRDETAIL);
			switch (hdr->driver_status & 0xF0) {
			case 0x10: strlcat(msg, "SG_ERR_SUGGEST_RETRY", MAXERRDETAIL); break;
			case 0x20: strlcat(msg, "SG_ERR_SUGGEST_ABORT", MAXERRDETAIL); break;
			case 0x30: strlcat(msg, "SG_ERR_SUGGEST_REMAP", MAXERRDETAIL); break;
			case 0x40: strlcat(msg, "SG_ERR_SUGGEST_DIE", MAXERRDETAIL); break;
			case 0x80: strlcat(msg, "SG_ERR_SUGGEST_SENSE", MAXERRDETAIL); break;
			}
			strlcat(msg, ". ", MAXERRDETAIL);
		}
		if (hdr->status) {
			snprintf(msgchunk, MAXMSGCHUNK, "SG SCSI Status: 0x%02x; ", hdr->status);
			strlcat(msg, msgchunk, MAXERRDETAIL);
			// SCSI 3 status codes
			switch (hdr->status) {
			case 0x02: strlcat(msg, "CHECK_CONDITION", MAXERRDETAIL); break;
			case 0x04: strlcat(msg, "CONDITION_MET", MAXERRDETAIL); break;
			case 0x08: strlcat(msg, "BUSY", MAXERRDETAIL); break;
			case 0x10: strlcat(msg, "INTERMEDIATE", MAXERRDETAIL); break;
			case 0x14: strlcat(msg, "INTERMEDIATE_CONDITION_MET", MAXERRDETAIL); break;
			case 0x18: strlcat(msg, "RESERVATION_CONFLICT", MAXERRDETAIL); break;
			case 0x22: strlcat(msg, "COMMAND_TERMINATED", MAXERRDETAIL); break;
			case 0x28: strlcat(msg, "TASK_SET_FULL", MAXERRDETAIL); break;
			case 0x30: strlcat(msg, "ACA_ACTIVE", MAXERRDETAIL); break;
			case 0x40: strlcat(msg, "TASK_ABORTED", MAXERRDETAIL); break;
			default: strlcat(msg, "Unknown", MAXERRDETAIL); break;
			}
			strlcat(msg, ". ", MAXERRDETAIL);
		}
		if (hdr->sb_len_wr) {
			snprintf(msgchunk, MAXMSGCHUNK, "Sense Data (%d bytes):", hdr->sb_len_wr);
			strlcat(msg, msgchunk, MAXERRDETAIL);
			for (i=0; i<hdr->sb_len_wr; i++) {
				snprintf(msgchunk, MAXMSGCHUNK, " %02x", hdr->sbp[i]);
				strlcat(msg, msgchunk, MAXERRDETAIL);
			}
			strlcat(msg, ". ", MAXERRDETAIL);
		}
		if (hdr->resid != 0) {
			snprintf(msgchunk, MAXMSGCHUNK, "SG Driver: %d bytes out of %d not transferred. ", hdr->resid, hdr->dxfer_len);
			strlcat(msg, msgchunk, MAXERRDETAIL);
			ret = msg;
		}
	}

	return ret;
}


/*
 * get max file size from read capacity.
 */
static int fio_sgio_get_file_size(struct thread_data *td, struct fio_file *f)
{
	// get_file_size is being called even before sgio_init is called, so none of the sg_io structures are
	// initialized in the thread_data yet.  So we need to do the ReadCapacity without any of those helpers.
	// One of the effects is that ReadCapacity may get called 4 times on each open:
	//   readcap(10) followed by readcap(16) if needed - just to get the file size
	//   after the init occurs - it will be called again when "type_check" is called during structure initialization
	// I'm not sure how to prevent this little inefficiency.

	unsigned int bs = 0;
	unsigned long long max_lba = 0;
	int ret;

	if (fio_file_size_known(f))
		return 0;

	ret = fio_sgio_read_capacity(td, &bs, &max_lba);
	if (ret ) {
		td_verror(td, td->error, "fio_sgio_read_capacity");
		log_err("ioengine sg unable to successfully execute read capacity to get block size and maximum lba\n");
		return 1;
	}
	f->real_file_size = (max_lba + 1) * bs;

	fio_file_set_size_known(f);
	//printf("real_file_size=0x%08llx\n", (long long) f->real_file_size);

	return 0;
}


static struct ioengine_ops ioengine = {
	.name		= "sg",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_sgio_init,
	.prep		= fio_sgio_prep,
	.queue		= fio_sgio_queue,
	.getevents	= fio_sgio_getevents,
	.errdetails = fio_sgio_errdetails,
	.event		= fio_sgio_event,
	.cleanup	= fio_sgio_cleanup,
	.open_file	= fio_sgio_open,
	.close_file	= generic_close_file,
	.get_file_size	= fio_sgio_get_file_size, // generic_get_file_size
	.flags		= FIO_SYNCIO | FIO_RAWIO,
};



#else /* FIO_HAVE_SGIO */

/*
 * When we have a proper configure system in place, we simply wont build
 * and install this io engine. For now install a crippled version that
 * just complains and fails to load.
 */
static int fio_sgio_init(struct thread_data fio_unused *td)
{
	log_err("fio: ioengine sg not available\n");
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
