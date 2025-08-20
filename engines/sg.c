/*
 * sg engine
 *
 * IO engine that uses the Linux SG v3 interface to talk to SCSI devices
 *
 * This ioengine can operate in two modes:
 *	sync	with block devices (/dev/sdX) or
 *		with character devices (/dev/sgY) with direct=1 or sync=1
 *	async	with character devices with direct=0 and sync=0
 *
 * What value does queue() return for the different cases?
 *				queue() return value
 * In sync mode:
 *  /dev/sdX		RWT	FIO_Q_COMPLETED
 *  /dev/sgY		RWT	FIO_Q_COMPLETED
 *   with direct=1 or sync=1
 *
 * In async mode:
 *  /dev/sgY		RWT	FIO_Q_QUEUED
 *   direct=0 and sync=0
 *
 * Because FIO_SYNCIO is set for this ioengine td_io_queue() will fill in
 * issue_time *before* each IO is sent to queue()
 *
 * Where are the IO counting functions called for the different cases?
 *
 * In sync mode:
 *  /dev/sdX (commit==NULL)
 *   RWT
 *    io_u_mark_depth()			called in td_io_queue()
 *    io_u_mark_submit/complete()	called in td_io_queue()
 *    issue_time			set in td_io_queue()
 *
 *  /dev/sgY with direct=1 or sync=1 (commit does nothing)
 *   RWT
 *    io_u_mark_depth()			called in td_io_queue()
 *    io_u_mark_submit/complete()	called in queue()
 *    issue_time			set in td_io_queue()
 *  
 * In async mode:
 *  /dev/sgY with direct=0 and sync=0
 *   RW: read and write operations are submitted in queue()
 *    io_u_mark_depth()			called in td_io_commit()
 *    io_u_mark_submit()		called in queue()
 *    issue_time			set in td_io_queue()
 *   T: trim operations are queued in queue() and submitted in commit()
 *    io_u_mark_depth()			called in td_io_commit()
 *    io_u_mark_submit()		called in commit()
 *    issue_time			set in commit()
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>

#include "../fio.h"
#include "../optgroup.h"

#ifdef FIO_HAVE_SGIO

#ifndef SGV4_FLAG_HIPRI
#define SGV4_FLAG_HIPRI 0x800
#endif

enum {
	FIO_SG_WRITE		= 1,
	FIO_SG_WRITE_VERIFY,
	FIO_SG_WRITE_SAME,
	FIO_SG_WRITE_SAME_NDOB,
	FIO_SG_WRITE_STREAM,
	FIO_SG_VERIFY_BYTCHK_00,
	FIO_SG_VERIFY_BYTCHK_01,
	FIO_SG_VERIFY_BYTCHK_11,
};

struct sg_options {
	void *pad;
	unsigned int hipri;
	unsigned int readfua;
	unsigned int writefua;
	unsigned int write_mode;
	uint16_t stream_id;
};

static struct fio_option options[] = {
        {
                .name   = "hipri",
                .lname  = "High Priority",
                .type   = FIO_OPT_STR_SET,
                .off1   = offsetof(struct sg_options, hipri),
                .help   = "Use polled IO completions",
                .category = FIO_OPT_C_ENGINE,
                .group  = FIO_OPT_G_SG,
        },
	{
		.name	= "readfua",
		.lname	= "sg engine read fua flag support",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct sg_options, readfua),
		.help	= "Set FUA flag (force unit access) for all Read operations",
		.def	= "0",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_SG,
	},
	{
		.name	= "writefua",
		.lname	= "sg engine write fua flag support",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct sg_options, writefua),
		.help	= "Set FUA flag (force unit access) for all Write operations",
		.def	= "0",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_SG,
	},
	{
		.name	= "sg_write_mode",
		.lname	= "specify sg write mode",
		.type	= FIO_OPT_STR,
		.off1	= offsetof(struct sg_options, write_mode),
		.help	= "Specify SCSI WRITE mode",
		.def	= "write",
		.posval = {
			  { .ival = "write",
			    .oval = FIO_SG_WRITE,
			    .help = "Issue standard SCSI WRITE commands",
			  },
			  { .ival = "write_and_verify",
			    .oval = FIO_SG_WRITE_VERIFY,
			    .help = "Issue SCSI WRITE AND VERIFY commands",
			  },
			  { .ival = "verify",
			    .oval = FIO_SG_WRITE_VERIFY,
			    .help = "Issue SCSI WRITE AND VERIFY commands. This "
				    "option is deprecated. Use write_and_verify instead.",
			  },
			  { .ival = "write_same",
			    .oval = FIO_SG_WRITE_SAME,
			    .help = "Issue SCSI WRITE SAME commands",
			  },
			  { .ival = "same",
			    .oval = FIO_SG_WRITE_SAME,
			    .help = "Issue SCSI WRITE SAME commands. This "
				    "option is deprecated. Use write_same instead.",
			  },
			  { .ival = "write_same_ndob",
			    .oval = FIO_SG_WRITE_SAME_NDOB,
			    .help = "Issue SCSI WRITE SAME(16) commands with NDOB flag set",
			  },
			  { .ival = "verify_bytchk_00",
			    .oval = FIO_SG_VERIFY_BYTCHK_00,
			    .help = "Issue SCSI VERIFY commands with BYTCHK set to 00",
			  },
			  { .ival = "verify_bytchk_01",
			    .oval = FIO_SG_VERIFY_BYTCHK_01,
			    .help = "Issue SCSI VERIFY commands with BYTCHK set to 01",
			  },
			  { .ival = "verify_bytchk_11",
			    .oval = FIO_SG_VERIFY_BYTCHK_11,
			    .help = "Issue SCSI VERIFY commands with BYTCHK set to 11",
			  },
			  { .ival = "write_stream",
			    .oval = FIO_SG_WRITE_STREAM,
			    .help = "Issue SCSI WRITE STREAM(16) commands",
			  },
		},
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_SG,
	},
	{
		.name	= "stream_id",
		.lname	= "stream id for WRITE STREAM(16) commands",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct sg_options, stream_id),
		.help	= "Stream ID for WRITE STREAM(16) commands",
		.def	= "0",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_SG,
	},
	{
		.name	= NULL,
	},
};

#define MAX_10B_LBA  0xFFFFFFFFULL
#define SCSI_TIMEOUT_MS 30000   // 30 second timeout; currently no method to override
#define MAX_SB 64               // sense block maximum return size
/*
#define FIO_SGIO_DEBUG
*/

struct sgio_cmd {
	unsigned char cdb[16];      // enhanced from 10 to support 16 byte commands
	unsigned char sb[MAX_SB];   // add sense block to commands
	int nr;
};

struct sgio_trim {
	uint8_t *unmap_param;
	unsigned int unmap_range_count;
	struct io_u **trim_io_us;
};

struct sgio_data {
	struct sgio_cmd *cmds;
	struct io_u **events;
	struct pollfd *pfds;
	int *fd_flags;
	void *sgbuf;
	unsigned int bs;
	int type_checked;
	struct sgio_trim **trim_queues;
	int current_queue;
#ifdef FIO_SGIO_DEBUG
	unsigned int *trim_queue_map;
#endif
};

static inline uint16_t sgio_get_be16(uint8_t *buf)
{
	return be16_to_cpu(*((uint16_t *) buf));
}

static inline uint32_t sgio_get_be32(uint8_t *buf)
{
	return be32_to_cpu(*((uint32_t *) buf));
}

static inline uint64_t sgio_get_be64(uint8_t *buf)
{
	return be64_to_cpu(*((uint64_t *) buf));
}

static inline void sgio_set_be16(uint16_t val, uint8_t *buf)
{
	uint16_t t = cpu_to_be16(val);

	memcpy(buf, &t, sizeof(uint16_t));
}

static inline void sgio_set_be32(uint32_t val, uint8_t *buf)
{
	uint32_t t = cpu_to_be32(val);

	memcpy(buf, &t, sizeof(uint32_t));
}

static inline void sgio_set_be64(uint64_t val, uint8_t *buf)
{
	uint64_t t = cpu_to_be64(val);

	memcpy(buf, &t, sizeof(uint64_t));
}

static inline bool sgio_unbuffered(struct thread_data *td)
{
	return (td->o.odirect || td->o.sync_io);
}

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
	hdr->timeout = SCSI_TIMEOUT_MS;

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

static int sg_fd_read(int fd, void *data, size_t size)
{
	int err = 0;

	while (size) {
		ssize_t ret;

		ret = read(fd, data, size);
		if (ret < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			err = errno;
			break;
		} else if (!ret)
			break;
		else {
			data += ret;
			size -= ret;
		}
	}

	if (err)
		return err;
	if (size)
		return EAGAIN;

	return 0;
}

static int fio_sgio_getevents(struct thread_data *td, unsigned int min,
			      unsigned int max,
			      const struct timespec fio_unused *t)
{
	struct sgio_data *sd = td->io_ops_data;
	int left = max, eventNum, ret, r = 0, trims = 0;
	void *buf = sd->sgbuf;
	unsigned int i, j, events;
	struct fio_file *f;
	struct io_u *io_u;

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

	/*
	** There are two counters here:
	**  - number of SCSI commands completed
	**  - number of io_us completed
	**
	** These are the same with reads and writes, but
	** could differ with trim/unmap commands because
	** a single unmap can include multiple io_us
	*/

	while (left > 0) {
		char *p;

		dprint(FD_IO, "sgio_getevents: sd %p: min=%d, max=%d, left=%d\n", sd, min, max, left);

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
			for (eventNum = 0; eventNum < left; eventNum++) {
				ret = sg_fd_read(f->fd, p, sizeof(struct sg_io_hdr));
				dprint(FD_IO, "sgio_getevents: sg_fd_read ret: %d\n", ret);
				if (ret) {
					r = -ret;
					td_verror(td, r, "sg_read");
					break;
				}
				io_u = ((struct sg_io_hdr *)p)->usr_ptr;
				if (io_u->ddir == DDIR_TRIM) {
					events += sd->trim_queues[io_u->index]->unmap_range_count;
					eventNum += sd->trim_queues[io_u->index]->unmap_range_count - 1;
				} else
					events++;

				p += sizeof(struct sg_io_hdr);
				dprint(FD_IO, "sgio_getevents: events: %d, eventNum: %d, left: %d\n", events, eventNum, left);
			}
		}

		if (r < 0 && !events)
			break;
		if (!events) {
			usleep(1000);
			goto re_read;
		}

		left -= events;
		r += events;

		for (i = 0; i < events; i++) {
			struct sg_io_hdr *hdr = (struct sg_io_hdr *) buf + i;
			sd->events[i + trims] = hdr->usr_ptr;
			io_u = (struct io_u *)(hdr->usr_ptr);

			if (hdr->info & SG_INFO_CHECK) {
				/* record if an io error occurred, ignore resid */
				memcpy(&io_u->hdr, hdr, sizeof(struct sg_io_hdr));
				sd->events[i + trims]->error = EIO;
			}

			if (io_u->ddir == DDIR_TRIM) {
				struct sgio_trim *st = sd->trim_queues[io_u->index];
#ifdef FIO_SGIO_DEBUG
				assert(st->trim_io_us[0] == io_u);
				assert(sd->trim_queue_map[io_u->index] == io_u->index);
				dprint(FD_IO, "sgio_getevents: reaping %d io_us from trim queue %d\n", st->unmap_range_count, io_u->index);
				dprint(FD_IO, "sgio_getevents: reaped io_u %d and stored in events[%d]\n", io_u->index, i+trims);
#endif
				for (j = 1; j < st->unmap_range_count; j++) {
					++trims;
					sd->events[i + trims] = st->trim_io_us[j];
#ifdef FIO_SGIO_DEBUG
					dprint(FD_IO, "sgio_getevents: reaped io_u %d and stored in events[%d]\n", st->trim_io_us[j]->index, i+trims);
					assert(sd->trim_queue_map[st->trim_io_us[j]->index] == io_u->index);
#endif
					if (hdr->info & SG_INFO_CHECK) {
						/* record if an io error occurred, ignore resid */
						memcpy(&st->trim_io_us[j]->hdr, hdr, sizeof(struct sg_io_hdr));
						sd->events[i + trims]->error = EIO;
					}
				}
				events -= st->unmap_range_count - 1;
				st->unmap_range_count = 0;
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

static enum fio_q_status fio_sgio_ioctl_doio(struct thread_data *td,
					     struct fio_file *f,
					     struct io_u *io_u)
{
	struct sgio_data *sd = td->io_ops_data;
	struct sg_io_hdr *hdr = &io_u->hdr;
	int ret;

	sd->events[0] = io_u;

	ret = ioctl(f->fd, SG_IO, hdr);
	if (ret < 0)
		return ret;

	/* record if an io error occurred */
	if (hdr->info & SG_INFO_CHECK)
		io_u->error = EIO;

	return FIO_Q_COMPLETED;
}

static enum fio_q_status fio_sgio_rw_doio(struct thread_data *td,
					  struct fio_file *f,
					  struct io_u *io_u, int do_sync)
{
	struct sg_io_hdr *hdr = &io_u->hdr;
	int ret;

	ret = write(f->fd, hdr, sizeof(*hdr));
	if (ret < 0)
		return ret;

	if (do_sync) {
		/*
		 * We can't just read back the first command that completes
		 * and assume it's the one we need, it could be any command
		 * that is inflight.
		 */
		do {
			struct io_u *__io_u;

			ret = read(f->fd, hdr, sizeof(*hdr));
			if (ret < 0)
				return ret;

			__io_u = hdr->usr_ptr;

			/* record if an io error occurred */
			if (hdr->info & SG_INFO_CHECK)
				__io_u->error = EIO;

			if (__io_u == io_u)
				break;

			if (io_u_sync_complete(td, __io_u))
				break;

		} while (1);

		return FIO_Q_COMPLETED;
	}

	return FIO_Q_QUEUED;
}

static enum fio_q_status fio_sgio_doio(struct thread_data *td,
				       struct io_u *io_u, int do_sync)
{
	struct fio_file *f = io_u->file;
	enum fio_q_status ret;

	if (f->filetype == FIO_TYPE_BLOCK) {
		ret = fio_sgio_ioctl_doio(td, f, io_u);
		if (io_u->error)
			td_verror(td, io_u->error, __func__);
	} else {
		ret = fio_sgio_rw_doio(td, f, io_u, do_sync);
		if (io_u->error && do_sync)
			td_verror(td, io_u->error, __func__);
	}

	return ret;
}

static void fio_sgio_rw_lba(struct sg_io_hdr *hdr, unsigned long long lba,
			    unsigned long long nr_blocks, bool override16)
{
	if (lba < MAX_10B_LBA && !override16) {
		sgio_set_be32((uint32_t) lba, &hdr->cmdp[2]);
		sgio_set_be16((uint16_t) nr_blocks, &hdr->cmdp[7]);
	} else {
		sgio_set_be64(lba, &hdr->cmdp[2]);
		sgio_set_be32((uint32_t) nr_blocks, &hdr->cmdp[10]);
	}

	return;
}

static int fio_sgio_prep(struct thread_data *td, struct io_u *io_u)
{
	struct sg_io_hdr *hdr = &io_u->hdr;
	struct sg_options *o = td->eo;
	struct sgio_data *sd = td->io_ops_data;
	unsigned long long nr_blocks, lba;
	int offset;

	if (io_u->xfer_buflen & (sd->bs - 1)) {
		log_err("read/write not sector aligned\n");
		return EINVAL;
	}

	nr_blocks = io_u->xfer_buflen / sd->bs;
	lba = io_u->offset / sd->bs;

	if (io_u->ddir == DDIR_READ) {
		sgio_hdr_init(sd, hdr, io_u, 1);

		hdr->dxfer_direction = SG_DXFER_FROM_DEV;
		if (lba < MAX_10B_LBA)
			hdr->cmdp[0] = 0x28; // read(10)
		else
			hdr->cmdp[0] = 0x88; // read(16)

		if (o->hipri)
			hdr->flags |= SGV4_FLAG_HIPRI;
		if (o->readfua)
			hdr->cmdp[1] |= 0x08;

		fio_sgio_rw_lba(hdr, lba, nr_blocks, false);

	} else if (io_u->ddir == DDIR_WRITE) {
		sgio_hdr_init(sd, hdr, io_u, 1);

		hdr->dxfer_direction = SG_DXFER_TO_DEV;
		switch(o->write_mode) {
		case FIO_SG_WRITE:
			if (lba < MAX_10B_LBA)
				hdr->cmdp[0] = 0x2a; // write(10)
			else
				hdr->cmdp[0] = 0x8a; // write(16)
			if (o->hipri)
				hdr->flags |= SGV4_FLAG_HIPRI;
			if (o->writefua)
				hdr->cmdp[1] |= 0x08;
			break;
		case FIO_SG_WRITE_VERIFY:
			if (lba < MAX_10B_LBA)
				hdr->cmdp[0] = 0x2e; // write and verify(10)
			else
				hdr->cmdp[0] = 0x8e; // write and verify(16)
			break;
			// BYTCHK is disabled by virtue of the memset in sgio_hdr_init
		case FIO_SG_WRITE_SAME:
			hdr->dxfer_len = sd->bs;
			if (lba < MAX_10B_LBA)
				hdr->cmdp[0] = 0x41; // write same(10)
			else
				hdr->cmdp[0] = 0x93; // write same(16)
			break;
		case FIO_SG_WRITE_SAME_NDOB:
			hdr->cmdp[0] = 0x93; // write same(16)
			hdr->cmdp[1] |= 0x1; // no data output buffer
			hdr->dxfer_len = 0;
			break;
		case FIO_SG_WRITE_STREAM:
			hdr->cmdp[0] = 0x9a; // write stream (16)
			if (o->writefua)
				hdr->cmdp[1] |= 0x08;
			sgio_set_be64(lba, &hdr->cmdp[2]);
			sgio_set_be16((uint16_t) io_u->file->engine_pos, &hdr->cmdp[10]);
			sgio_set_be16((uint16_t) nr_blocks, &hdr->cmdp[12]);
			break;
		case FIO_SG_VERIFY_BYTCHK_00:
			if (lba < MAX_10B_LBA)
				hdr->cmdp[0] = 0x2f; // VERIFY(10)
			else
				hdr->cmdp[0] = 0x8f; // VERIFY(16)
			hdr->dxfer_len = 0;
			break;
		case FIO_SG_VERIFY_BYTCHK_01:
			if (lba < MAX_10B_LBA)
				hdr->cmdp[0] = 0x2f; // VERIFY(10)
			else
				hdr->cmdp[0] = 0x8f; // VERIFY(16)
			hdr->cmdp[1] |= 0x02;		// BYTCHK = 01b
			break;
		case FIO_SG_VERIFY_BYTCHK_11:
			if (lba < MAX_10B_LBA)
				hdr->cmdp[0] = 0x2f; // VERIFY(10)
			else
				hdr->cmdp[0] = 0x8f; // VERIFY(16)
			hdr->cmdp[1] |= 0x06;		// BYTCHK = 11b
			hdr->dxfer_len = sd->bs;
			break;
		};

		if (o->write_mode != FIO_SG_WRITE_STREAM)
			fio_sgio_rw_lba(hdr, lba, nr_blocks,
				o->write_mode == FIO_SG_WRITE_SAME_NDOB);

	} else if (io_u->ddir == DDIR_TRIM) {
		struct sgio_trim *st;

		if (sd->current_queue == -1) {
			sgio_hdr_init(sd, hdr, io_u, 0);

			hdr->cmd_len = 10;
			hdr->dxfer_direction = SG_DXFER_TO_DEV;
			hdr->cmdp[0] = 0x42; // unmap
			sd->current_queue = io_u->index;
			st = sd->trim_queues[sd->current_queue];
			hdr->dxferp = st->unmap_param;
#ifdef FIO_SGIO_DEBUG
			assert(sd->trim_queues[io_u->index]->unmap_range_count == 0);
			dprint(FD_IO, "sg: creating new queue based on io_u %d\n", io_u->index);
#endif
		}
		else
			st = sd->trim_queues[sd->current_queue];

		dprint(FD_IO, "sg: adding io_u %d to trim queue %d\n", io_u->index, sd->current_queue);
		st->trim_io_us[st->unmap_range_count] = io_u;
#ifdef FIO_SGIO_DEBUG
		sd->trim_queue_map[io_u->index] = sd->current_queue;
#endif

		offset = 8 + 16 * st->unmap_range_count;
		sgio_set_be64(lba, &st->unmap_param[offset]);
		sgio_set_be32((uint32_t) nr_blocks, &st->unmap_param[offset + 8]);

		st->unmap_range_count++;

	} else if (ddir_sync(io_u->ddir)) {
		sgio_hdr_init(sd, hdr, io_u, 0);
		hdr->dxfer_direction = SG_DXFER_NONE;
		if (lba < MAX_10B_LBA)
			hdr->cmdp[0] = 0x35; // synccache(10)
		else
			hdr->cmdp[0] = 0x91; // synccache(16)
	} else
		assert(0);

	return 0;
}

static void fio_sgio_unmap_setup(struct sg_io_hdr *hdr, struct sgio_trim *st)
{
	uint16_t cnt = st->unmap_range_count * 16;

	hdr->dxfer_len = cnt + 8;
	sgio_set_be16(cnt + 8, &hdr->cmdp[7]);
	sgio_set_be16(cnt + 6, st->unmap_param);
	sgio_set_be16(cnt, &st->unmap_param[2]);

	return;
}

static enum fio_q_status fio_sgio_queue(struct thread_data *td,
					struct io_u *io_u)
{
	struct sg_io_hdr *hdr = &io_u->hdr;
	struct sgio_data *sd = td->io_ops_data;
	int ret, do_sync = 0;

	fio_ro_check(td, io_u);

	if (sgio_unbuffered(td) || ddir_sync(io_u->ddir))
		do_sync = 1;

	if (io_u->ddir == DDIR_TRIM) {
		if (do_sync || io_u->file->filetype == FIO_TYPE_BLOCK) {
			struct sgio_trim *st = sd->trim_queues[sd->current_queue];

			/* finish cdb setup for unmap because we are
			** doing unmap commands synchronously */
#ifdef FIO_SGIO_DEBUG
			assert(st->unmap_range_count == 1);
			assert(io_u == st->trim_io_us[0]);
#endif
			hdr = &io_u->hdr;

			fio_sgio_unmap_setup(hdr, st);

			st->unmap_range_count = 0;
			sd->current_queue = -1;
		} else
			/* queue up trim ranges and submit in commit() */
			return FIO_Q_QUEUED;
	}

	ret = fio_sgio_doio(td, io_u, do_sync);

	if (ret < 0)
		io_u->error = errno;
	else if (hdr->status) {
		io_u->resid = hdr->resid;
		io_u->error = EIO;
	} else if (td->io_ops->commit != NULL) {
		if (do_sync && !ddir_sync(io_u->ddir)) {
			io_u_mark_submit(td, 1);
			io_u_mark_complete(td, 1);
		} else if (io_u->ddir == DDIR_READ || io_u->ddir == DDIR_WRITE) {
			io_u_mark_submit(td, 1);
			io_u_queued(td, io_u);
		}
	}

	if (io_u->error) {
		td_verror(td, io_u->error, "xfer");
		return FIO_Q_COMPLETED;
	}

	return ret;
}

static int fio_sgio_commit(struct thread_data *td)
{
	struct sgio_data *sd = td->io_ops_data;
	struct sgio_trim *st;
	struct io_u *io_u;
	struct sg_io_hdr *hdr;
	struct timespec now;
	unsigned int i;
	int ret;

	if (sd->current_queue == -1)
		return 0;

	st = sd->trim_queues[sd->current_queue];
	io_u = st->trim_io_us[0];
	hdr = &io_u->hdr;

	fio_sgio_unmap_setup(hdr, st);

	sd->current_queue = -1;

	ret = fio_sgio_rw_doio(td, io_u->file, io_u, 0);

	if (ret < 0 || hdr->status) {
		int error;

		if (ret < 0)
			error = errno;
		else {
			error = EIO;
			ret = -EIO;
		}

		for (i = 0; i < st->unmap_range_count; i++) {
			st->trim_io_us[i]->error = error;
			clear_io_u(td, st->trim_io_us[i]);
			if (hdr->status)
				st->trim_io_us[i]->resid = hdr->resid;
		}

		td_verror(td, error, "xfer");
		return ret;
	}

	if (fio_fill_issue_time(td)) {
		fio_gettime(&now, NULL);
		for (i = 0; i < st->unmap_range_count; i++) {
			memcpy(&st->trim_io_us[i]->issue_time, &now, sizeof(now));
			io_u_queued(td, io_u);
		}
	}
	io_u_mark_submit(td, st->unmap_range_count);

	return 0;
}

static struct io_u *fio_sgio_event(struct thread_data *td, int event)
{
	struct sgio_data *sd = td->io_ops_data;

	return sd->events[event];
}

static int fio_sgio_read_capacity(struct thread_data *td, unsigned int *bs,
				  unsigned long long *max_lba)
{
	/*
	 * need to do read capacity operation w/o benefit of sd or
	 * io_u structures, which are not initialized until later.
	 */
	struct sg_io_hdr hdr;
	unsigned long long hlba;
	unsigned int blksz = 0;
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

	if (hdr.info & SG_INFO_CHECK) {
		/* RCAP(10) might be unsupported by device. Force RCAP(16) */
		hlba = MAX_10B_LBA;
	} else {
		blksz = sgio_get_be32(&buf[4]);
		hlba = sgio_get_be32(buf);
	}

	/*
	 * If max lba masked by MAX_10B_LBA equals MAX_10B_LBA,
	 * then need to retry with 16 byte Read Capacity command.
	 */
	if (hlba == MAX_10B_LBA) {
		hdr.cmd_len = 16;
		hdr.cmdp[0] = 0x9e; // service action
		hdr.cmdp[1] = 0x10; // Read Capacity(16)
		sgio_set_be32(sizeof(buf), &hdr.cmdp[10]);

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

		blksz = sgio_get_be32(&buf[8]);
		hlba = sgio_get_be64(buf);
	}

	if (blksz) {
		*bs = blksz;
		*max_lba = hlba;
		ret = 0;
	} else {
		ret = EIO;
	}

	close(fd);
	return ret;
}

static void fio_sgio_cleanup(struct thread_data *td)
{
	struct sgio_data *sd = td->io_ops_data;
	int i;

	if (sd) {
		free(sd->events);
		free(sd->cmds);
		free(sd->fd_flags);
		free(sd->pfds);
		free(sd->sgbuf);
#ifdef FIO_SGIO_DEBUG
		free(sd->trim_queue_map);
#endif

		for (i = 0; i < td->o.iodepth; i++) {
			free(sd->trim_queues[i]->unmap_param);
			free(sd->trim_queues[i]->trim_io_us);
			free(sd->trim_queues[i]);
		}

		free(sd->trim_queues);
		free(sd);
	}
}

static int fio_sgio_init(struct thread_data *td)
{
	struct sgio_data *sd;
	struct sgio_trim *st;
	struct sg_io_hdr *h3p;
	int i;

	sd = calloc(1, sizeof(*sd));
	sd->cmds = calloc(td->o.iodepth, sizeof(struct sgio_cmd));
	sd->sgbuf = calloc(td->o.iodepth, sizeof(struct sg_io_hdr));
	sd->events = calloc(td->o.iodepth, sizeof(struct io_u *));
	sd->pfds = calloc(td->o.nr_files, sizeof(struct pollfd));
	sd->fd_flags = calloc(td->o.nr_files, sizeof(int));
	sd->type_checked = 0;

	sd->trim_queues = calloc(td->o.iodepth, sizeof(struct sgio_trim *));
	sd->current_queue = -1;
#ifdef FIO_SGIO_DEBUG
	sd->trim_queue_map = calloc(td->o.iodepth, sizeof(int));
#endif
	for (i = 0, h3p = sd->sgbuf; i < td->o.iodepth; i++, ++h3p) {
		sd->trim_queues[i] = calloc(1, sizeof(struct sgio_trim));
		st = sd->trim_queues[i];
		st->unmap_param = calloc(td->o.iodepth + 1, sizeof(char[16]));
		st->unmap_range_count = 0;
		st->trim_io_us = calloc(td->o.iodepth, sizeof(struct io_u *));
		h3p->interface_id = 'S';
	}

	td->io_ops_data = sd;

	/*
	 * we want to do it, regardless of whether odirect is set or not
	 */
	td->o.override_sync = 1;
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
			log_err("ioengine sg unable to read capacity successfully\n");
			return 1;
		}
	} else {
		td_verror(td, EINVAL, "wrong file type");
		log_err("ioengine sg only works on block or character devices\n");
		return 1;
	}

	sd->bs = bs;
	// Determine size of commands needed based on max_lba
	if (max_lba >= MAX_10B_LBA) {
		dprint(FD_IO, "sgio_type_check: using 16 byte read/write "
			"commands for lba above 0x%016llx/0x%016llx\n",
			MAX_10B_LBA, max_lba);
	}

	if (f->filetype == FIO_TYPE_BLOCK) {
		td->io_ops->getevents = NULL;
		td->io_ops->event = NULL;
		td->io_ops->commit = NULL;
		/*
		** Setting these functions to null may cause problems
		** with filename=/dev/sda:/dev/sg0 since we are only
		** considering a single file
		*/
	}
	sd->type_checked = 1;

	return 0;
}

static int fio_sgio_stream_control(struct fio_file *f, bool open_stream, uint16_t *stream_id)
{
	struct sg_io_hdr hdr;
	unsigned char cmd[16];
	unsigned char sb[64];
	unsigned char buf[8];
	int ret;

	memset(&hdr, 0, sizeof(hdr));
	memset(cmd, 0, sizeof(cmd));
	memset(sb, 0, sizeof(sb));
	memset(buf, 0, sizeof(buf));

	hdr.interface_id = 'S';
	hdr.cmdp = cmd;
	hdr.cmd_len = 16;
	hdr.sbp = sb;
	hdr.mx_sb_len = sizeof(sb);
	hdr.timeout = SCSI_TIMEOUT_MS;
	hdr.cmdp[0] = 0x9e;
	hdr.dxfer_direction = SG_DXFER_FROM_DEV;
	hdr.dxferp = buf;
	hdr.dxfer_len = sizeof(buf);
	sgio_set_be32(sizeof(buf), &hdr.cmdp[10]);

	if (open_stream)
		hdr.cmdp[1] = 0x34;
	else {
		hdr.cmdp[1] = 0x54;
		sgio_set_be16(*stream_id, &hdr.cmdp[4]);
	}

	ret = ioctl(f->fd, SG_IO, &hdr);

	if (ret < 0)
		return ret;

	if (hdr.info & SG_INFO_CHECK)
		return 1;

	if (open_stream) {
		*stream_id = sgio_get_be16(&buf[4]);
		dprint(FD_FILE, "sgio_stream_control: opened stream %u\n", (unsigned int) *stream_id);
		assert(*stream_id != 0);
	} else
		dprint(FD_FILE, "sgio_stream_control: closed stream %u\n", (unsigned int) *stream_id);

	return 0;
}

static int fio_sgio_open(struct thread_data *td, struct fio_file *f)
{
	struct sgio_data *sd = td->io_ops_data;
	struct sg_options *o = td->eo;
	int ret;

	ret = generic_open_file(td, f);
	if (ret)
		return ret;

	if (sd && !sd->type_checked && fio_sgio_type_check(td, f)) {
		ret = generic_close_file(td, f);
		return ret;
	}

	if (o->write_mode == FIO_SG_WRITE_STREAM) {
		if (o->stream_id)
			f->engine_pos = o->stream_id;
		else {
			ret = fio_sgio_stream_control(f, true, (uint16_t *) &f->engine_pos);
			if (ret)
				return ret;
		}
	}

	return 0;
}

static int fio_sgio_close(struct thread_data *td, struct fio_file *f)
{
	struct sg_options *o = td->eo;
	int ret;

	if (!o->stream_id && o->write_mode == FIO_SG_WRITE_STREAM) {
		ret = fio_sgio_stream_control(f, false, (uint16_t *) &f->engine_pos);
		if (ret)
			return ret;
	}

	return generic_close_file(td, f);
}

/*
 * Build an error string with details about the driver, host or scsi
 * error contained in the sg header Caller will use as necessary.
 */
static char *fio_sgio_errdetails(struct thread_data *td, struct io_u *io_u)
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
			const uint8_t *const sbp = hdr->sbp;

			snprintf(msgchunk, MAXMSGCHUNK, "Sense Data (%d bytes):", hdr->sb_len_wr);
			strlcat(msg, msgchunk, MAXERRDETAIL);
			for (i = 0; i < hdr->sb_len_wr; i++) {
				snprintf(msgchunk, MAXMSGCHUNK, " %02x", sbp[i]);
				strlcat(msg, msgchunk, MAXERRDETAIL);
			}
			strlcat(msg, ". ", MAXERRDETAIL);
		}
		if (hdr->resid != 0) {
			snprintf(msgchunk, MAXMSGCHUNK, "SG Driver: %d bytes out of %d not transferred. ", hdr->resid, hdr->dxfer_len);
			strlcat(msg, msgchunk, MAXERRDETAIL);
		}
		if (hdr->cmdp) {
			strlcat(msg, "cdb:", MAXERRDETAIL);
			for (i = 0; i < hdr->cmd_len; i++) {
				snprintf(msgchunk, MAXMSGCHUNK, " %02x", hdr->cmdp[i]);
				strlcat(msg, msgchunk, MAXERRDETAIL);
			}
			strlcat(msg, ". ", MAXERRDETAIL);
			if (io_u->ddir == DDIR_TRIM) {
				unsigned char *param_list = hdr->dxferp;
				strlcat(msg, "dxferp:", MAXERRDETAIL);
				for (i = 0; i < hdr->dxfer_len; i++) {
					snprintf(msgchunk, MAXMSGCHUNK, " %02x", param_list[i]);
					strlcat(msg, msgchunk, MAXERRDETAIL);
				}
				strlcat(msg, ". ", MAXERRDETAIL);
			}
		}
	}

	if (!(hdr->info & SG_INFO_CHECK) && !strlen(msg))
		snprintf(msg, MAXERRDETAIL, "%s",
			 "SG Driver did not report a Host, Driver or Device check");

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
		log_err("ioengine sg only works on block or character devices\n");
		return 1;
	}

	ret = fio_sgio_read_capacity(td, &bs, &max_lba);
	if (ret ) {
		td_verror(td, td->error, "fio_sgio_read_capacity");
		log_err("ioengine sg unable to successfully execute read capacity to get block size and maximum lba\n");
		return 1;
	}

	f->real_file_size = (max_lba + 1) * bs;
	fio_file_set_size_known(f);
	return 0;
}


static struct ioengine_ops ioengine = {
	.name		= "sg",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_sgio_init,
	.prep		= fio_sgio_prep,
	.queue		= fio_sgio_queue,
	.commit		= fio_sgio_commit,
	.getevents	= fio_sgio_getevents,
	.errdetails	= fio_sgio_errdetails,
	.event		= fio_sgio_event,
	.cleanup	= fio_sgio_cleanup,
	.open_file	= fio_sgio_open,
	.close_file	= fio_sgio_close,
	.get_file_size	= fio_sgio_get_file_size,
	.flags		= FIO_SYNCIO | FIO_RAWIO | FIO_RO_NEEDS_RW_OPEN,
	.options	= options,
	.option_struct_size	= sizeof(struct sg_options)
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
