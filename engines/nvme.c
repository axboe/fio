/*
 * nvme structure declarations and helper functions for the
 * io_uring_cmd engine.
 */

#include "nvme.h"

static inline __u64 get_slba(struct nvme_data *data, struct io_u *io_u)
{
	if (data->lba_ext)
		return io_u->offset / data->lba_ext;
	else
		return io_u->offset >> data->lba_shift;
}

static inline __u32 get_nlb(struct nvme_data *data, struct io_u *io_u)
{
	if (data->lba_ext)
		return io_u->xfer_buflen / data->lba_ext - 1;
	else
		return (io_u->xfer_buflen >> data->lba_shift) - 1;
}

void fio_nvme_uring_cmd_trim_prep(struct nvme_uring_cmd *cmd, struct io_u *io_u,
				  struct nvme_dsm_range *dsm)
{
	struct nvme_data *data = FILE_ENG_DATA(io_u->file);

	cmd->opcode = nvme_cmd_dsm;
	cmd->nsid = data->nsid;
	cmd->cdw10 = 0;
	cmd->cdw11 = NVME_ATTRIBUTE_DEALLOCATE;
	cmd->addr = (__u64) (uintptr_t) dsm;
	cmd->data_len = sizeof(*dsm);

	dsm->slba = get_slba(data, io_u);
	/* nlb is a 1-based value for deallocate */
	dsm->nlb = get_nlb(data, io_u) + 1;
}

int fio_nvme_uring_cmd_prep(struct nvme_uring_cmd *cmd, struct io_u *io_u,
			    struct iovec *iov, struct nvme_dsm_range *dsm)
{
	struct nvme_data *data = FILE_ENG_DATA(io_u->file);
	__u64 slba;
	__u32 nlb;

	memset(cmd, 0, sizeof(struct nvme_uring_cmd));

	switch (io_u->ddir) {
	case DDIR_READ:
		cmd->opcode = nvme_cmd_read;
		break;
	case DDIR_WRITE:
		cmd->opcode = nvme_cmd_write;
		break;
	case DDIR_TRIM:
		fio_nvme_uring_cmd_trim_prep(cmd, io_u, dsm);
		return 0;
	default:
		return -ENOTSUP;
	}

	slba = get_slba(data, io_u);
	nlb = get_nlb(data, io_u);

	/* cdw10 and cdw11 represent starting lba */
	cmd->cdw10 = slba & 0xffffffff;
	cmd->cdw11 = slba >> 32;
	/* cdw12 represent number of lba's for read/write */
	cmd->cdw12 = nlb | (io_u->dtype << 20);
	cmd->cdw13 = io_u->dspec << 16;
	if (iov) {
		iov->iov_base = io_u->xfer_buf;
		iov->iov_len = io_u->xfer_buflen;
		cmd->addr = (__u64)(uintptr_t)iov;
		cmd->data_len = 1;
	} else {
		cmd->addr = (__u64)(uintptr_t)io_u->xfer_buf;
		cmd->data_len = io_u->xfer_buflen;
	}
	cmd->nsid = data->nsid;
	return 0;
}

static int nvme_identify(int fd, __u32 nsid, enum nvme_identify_cns cns,
			 enum nvme_csi csi, void *data)
{
	struct nvme_passthru_cmd cmd = {
		.opcode         = nvme_admin_identify,
		.nsid           = nsid,
		.addr           = (__u64)(uintptr_t)data,
		.data_len       = NVME_IDENTIFY_DATA_SIZE,
		.cdw10          = cns,
		.cdw11          = csi << NVME_IDENTIFY_CSI_SHIFT,
		.timeout_ms     = NVME_DEFAULT_IOCTL_TIMEOUT,
	};

	return ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
}

int fio_nvme_get_info(struct fio_file *f, __u32 *nsid, __u32 *lba_sz,
		      __u32 *ms, __u64 *nlba)
{
	struct nvme_id_ns ns;
	int namespace_id;
	int fd, err;
	__u32 format_idx;

	if (f->filetype != FIO_TYPE_CHAR) {
		log_err("ioengine io_uring_cmd only works with nvme ns "
			"generic char devices (/dev/ngXnY)\n");
		return 1;
	}

	fd = open(f->file_name, O_RDONLY);
	if (fd < 0)
		return -errno;

	namespace_id = ioctl(fd, NVME_IOCTL_ID);
	if (namespace_id < 0) {
		err = -errno;
		log_err("%s: failed to fetch namespace-id\n", f->file_name);
		goto out;
	}

	/*
	 * Identify namespace to get namespace-id, namespace size in LBA's
	 * and LBA data size.
	 */
	err = nvme_identify(fd, namespace_id, NVME_IDENTIFY_CNS_NS,
				NVME_CSI_NVM, &ns);
	if (err) {
		log_err("%s: failed to fetch identify namespace\n",
			f->file_name);
		close(fd);
		return err;
	}

	*nsid = namespace_id;

	/*
	 * 16 or 64 as maximum number of supported LBA formats.
	 * From flbas bit 0-3 indicates lsb and bit 5-6 indicates msb
	 * of the format index used to format the namespace.
	 */
	if (ns.nlbaf < 16)
		format_idx = ns.flbas & 0xf;
	else
		format_idx = (ns.flbas & 0xf) + (((ns.flbas >> 5) & 0x3) << 4);

	*lba_sz = 1 << ns.lbaf[format_idx].ds;

	/*
	 * Only extended LBA can be supported.
	 * Bit 4 for flbas indicates if metadata is transferred at the end of
	 * logical block creating an extended LBA.
	 */
	*ms = le16_to_cpu(ns.lbaf[format_idx].ms);
	if (*ms && !((ns.flbas >> 4) & 0x1)) {
		log_err("%s: only extended logical block can be supported\n",
			f->file_name);
		err = -ENOTSUP;
		goto out;
	}

	/* Check for end to end data protection support */
	if (ns.dps & 0x3) {
		log_err("%s: end to end data protection not supported\n",
			f->file_name);
		err = -ENOTSUP;
		goto out;
	}
	*nlba = ns.nsze;

out:
	close(fd);
	return err;
}

int fio_nvme_get_zoned_model(struct thread_data *td, struct fio_file *f,
			     enum zbd_zoned_model *model)
{
	struct nvme_data *data = FILE_ENG_DATA(f);
	struct nvme_id_ns ns;
	struct nvme_passthru_cmd cmd;
	int fd, ret = 0;

	if (f->filetype != FIO_TYPE_CHAR)
		return -EINVAL;

	/* File is not yet opened */
	fd = open(f->file_name, O_RDONLY | O_LARGEFILE);
	if (fd < 0)
		return -errno;

	/* Using nvme_id_ns for data as sizes are same */
	ret = nvme_identify(fd, data->nsid, NVME_IDENTIFY_CNS_CSI_CTRL,
				NVME_CSI_ZNS, &ns);
	if (ret) {
		*model = ZBD_NONE;
		goto out;
	}

	memset(&cmd, 0, sizeof(struct nvme_passthru_cmd));

	/* Using nvme_id_ns for data as sizes are same */
	ret = nvme_identify(fd, data->nsid, NVME_IDENTIFY_CNS_CSI_NS,
				NVME_CSI_ZNS, &ns);
	if (ret) {
		*model = ZBD_NONE;
		goto out;
	}

	*model = ZBD_HOST_MANAGED;
out:
	close(fd);
	return 0;
}

static int nvme_report_zones(int fd, __u32 nsid, __u64 slba, __u32 zras_feat,
			     __u32 data_len, void *data)
{
	struct nvme_passthru_cmd cmd = {
		.opcode         = nvme_zns_cmd_mgmt_recv,
		.nsid           = nsid,
		.addr           = (__u64)(uintptr_t)data,
		.data_len       = data_len,
		.cdw10          = slba & 0xffffffff,
		.cdw11          = slba >> 32,
		.cdw12		= (data_len >> 2) - 1,
		.cdw13		= NVME_ZNS_ZRA_REPORT_ZONES | zras_feat,
		.timeout_ms     = NVME_DEFAULT_IOCTL_TIMEOUT,
	};

	return ioctl(fd, NVME_IOCTL_IO_CMD, &cmd);
}

int fio_nvme_report_zones(struct thread_data *td, struct fio_file *f,
			  uint64_t offset, struct zbd_zone *zbdz,
			  unsigned int nr_zones)
{
	struct nvme_data *data = FILE_ENG_DATA(f);
	struct nvme_zone_report *zr;
	struct nvme_zns_id_ns zns_ns;
	struct nvme_id_ns ns;
	unsigned int i = 0, j, zones_fetched = 0;
	unsigned int max_zones, zones_chunks = 1024;
	int fd, ret = 0;
	__u32 zr_len;
	__u64 zlen;

	/* File is not yet opened */
	fd = open(f->file_name, O_RDONLY | O_LARGEFILE);
	if (fd < 0)
		return -errno;

	zones_fetched = 0;
	zr_len = sizeof(*zr) + (zones_chunks * sizeof(struct nvme_zns_desc));
	zr = calloc(1, zr_len);
	if (!zr) {
		close(fd);
		return -ENOMEM;
	}

	ret = nvme_identify(fd, data->nsid, NVME_IDENTIFY_CNS_NS,
				NVME_CSI_NVM, &ns);
	if (ret) {
		log_err("%s: nvme_identify_ns failed, err=%d\n", f->file_name,
			ret);
		goto out;
	}

	ret = nvme_identify(fd, data->nsid, NVME_IDENTIFY_CNS_CSI_NS,
				NVME_CSI_ZNS, &zns_ns);
	if (ret) {
		log_err("%s: nvme_zns_identify_ns failed, err=%d\n",
			f->file_name, ret);
		goto out;
	}
	zlen = zns_ns.lbafe[ns.flbas & 0x0f].zsze << data->lba_shift;

	max_zones = (f->real_file_size - offset) / zlen;
	if (max_zones < nr_zones)
		nr_zones = max_zones;

	if (nr_zones < zones_chunks)
		zones_chunks = nr_zones;

	while (zones_fetched < nr_zones) {
		if (zones_fetched + zones_chunks >= nr_zones) {
			zones_chunks = nr_zones - zones_fetched;
			zr_len = sizeof(*zr) + (zones_chunks * sizeof(struct nvme_zns_desc));
		}
		ret = nvme_report_zones(fd, data->nsid, offset >> data->lba_shift,
					NVME_ZNS_ZRAS_FEAT_ERZ, zr_len, (void *)zr);
		if (ret) {
			log_err("%s: nvme_zns_report_zones failed, err=%d\n",
				f->file_name, ret);
			goto out;
		}

		/* Transform the zone-report */
		for (j = 0; j < zr->nr_zones; j++, i++) {
			struct nvme_zns_desc *desc = (struct nvme_zns_desc *)&(zr->entries[j]);

			zbdz[i].start = desc->zslba << data->lba_shift;
			zbdz[i].len = zlen;
			zbdz[i].wp = desc->wp << data->lba_shift;
			zbdz[i].capacity = desc->zcap << data->lba_shift;

			/* Zone Type is stored in first 4 bits. */
			switch (desc->zt & 0x0f) {
			case NVME_ZONE_TYPE_SEQWRITE_REQ:
				zbdz[i].type = ZBD_ZONE_TYPE_SWR;
				break;
			default:
				log_err("%s: invalid type for zone at offset %llu.\n",
					f->file_name, (unsigned long long) desc->zslba);
				ret = -EIO;
				goto out;
			}

			/* Zone State is stored in last 4 bits. */
			switch (desc->zs >> 4) {
			case NVME_ZNS_ZS_EMPTY:
				zbdz[i].cond = ZBD_ZONE_COND_EMPTY;
				break;
			case NVME_ZNS_ZS_IMPL_OPEN:
				zbdz[i].cond = ZBD_ZONE_COND_IMP_OPEN;
				break;
			case NVME_ZNS_ZS_EXPL_OPEN:
				zbdz[i].cond = ZBD_ZONE_COND_EXP_OPEN;
				break;
			case NVME_ZNS_ZS_CLOSED:
				zbdz[i].cond = ZBD_ZONE_COND_CLOSED;
				break;
			case NVME_ZNS_ZS_FULL:
				zbdz[i].cond = ZBD_ZONE_COND_FULL;
				break;
			case NVME_ZNS_ZS_READ_ONLY:
			case NVME_ZNS_ZS_OFFLINE:
			default:
				/* Treat all these conditions as offline (don't use!) */
				zbdz[i].cond = ZBD_ZONE_COND_OFFLINE;
				zbdz[i].wp = zbdz[i].start;
			}
		}
		zones_fetched += zr->nr_zones;
		offset += zr->nr_zones * zlen;
	}

	ret = zones_fetched;
out:
	free(zr);
	close(fd);

	return ret;
}

int fio_nvme_reset_wp(struct thread_data *td, struct fio_file *f,
		      uint64_t offset, uint64_t length)
{
	struct nvme_data *data = FILE_ENG_DATA(f);
	unsigned int nr_zones;
	unsigned long long zslba;
	int i, fd, ret = 0;

	/* If the file is not yet opened, open it for this function. */
	fd = f->fd;
	if (fd < 0) {
		fd = open(f->file_name, O_RDWR | O_LARGEFILE);
		if (fd < 0)
			return -errno;
	}

	zslba = offset >> data->lba_shift;
	nr_zones = (length + td->o.zone_size - 1) / td->o.zone_size;

	for (i = 0; i < nr_zones; i++, zslba += (td->o.zone_size >> data->lba_shift)) {
		struct nvme_passthru_cmd cmd = {
			.opcode         = nvme_zns_cmd_mgmt_send,
			.nsid           = data->nsid,
			.cdw10          = zslba & 0xffffffff,
			.cdw11          = zslba >> 32,
			.cdw13          = NVME_ZNS_ZSA_RESET,
			.addr           = (__u64)(uintptr_t)NULL,
			.data_len       = 0,
			.timeout_ms     = NVME_DEFAULT_IOCTL_TIMEOUT,
		};

		ret = ioctl(fd, NVME_IOCTL_IO_CMD, &cmd);
	}

	if (f->fd < 0)
		close(fd);
	return -ret;
}

int fio_nvme_get_max_open_zones(struct thread_data *td, struct fio_file *f,
				unsigned int *max_open_zones)
{
	struct nvme_data *data = FILE_ENG_DATA(f);
	struct nvme_zns_id_ns zns_ns;
	int fd, ret = 0;

	fd = open(f->file_name, O_RDONLY | O_LARGEFILE);
	if (fd < 0)
		return -errno;

	ret = nvme_identify(fd, data->nsid, NVME_IDENTIFY_CNS_CSI_NS,
				NVME_CSI_ZNS, &zns_ns);
	if (ret) {
		log_err("%s: nvme_zns_identify_ns failed, err=%d\n",
			f->file_name, ret);
		goto out;
	}

	*max_open_zones = zns_ns.mor + 1;
out:
	close(fd);
	return ret;
}

static inline int nvme_fdp_reclaim_unit_handle_status(int fd, __u32 nsid,
						      __u32 data_len, void *data)
{
	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_cmd_io_mgmt_recv,
		.nsid		= nsid,
		.addr		= (__u64)(uintptr_t)data,
		.data_len 	= data_len,
		.cdw10		= 1,
		.cdw11		= (data_len >> 2) - 1,
	};

	return ioctl(fd, NVME_IOCTL_IO_CMD, &cmd);
}

int fio_nvme_iomgmt_ruhs(struct thread_data *td, struct fio_file *f,
			 struct nvme_fdp_ruh_status *ruhs, __u32 bytes)
{
	struct nvme_data *data = FILE_ENG_DATA(f);
	int fd, ret;

	fd = open(f->file_name, O_RDONLY | O_LARGEFILE);
	if (fd < 0)
		return -errno;

	ret = nvme_fdp_reclaim_unit_handle_status(fd, data->nsid, bytes, ruhs);
	if (ret) {
		log_err("%s: nvme_fdp_reclaim_unit_handle_status failed, err=%d\n",
			f->file_name, ret);
		errno = ENOTSUP;
	} else
		errno = 0;

	ret = -errno;
	close(fd);
	return ret;
}
