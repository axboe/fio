/*
 * nvme structure declarations and helper functions for the
 * io_uring_cmd engine.
 */

#include "nvme.h"

int fio_nvme_uring_cmd_prep(struct nvme_uring_cmd *cmd, struct io_u *io_u,
			    struct iovec *iov)
{
	struct nvme_data *data = FILE_ENG_DATA(io_u->file);
	__u64 slba;
	__u32 nlb;

	memset(cmd, 0, sizeof(struct nvme_uring_cmd));

	if (io_u->ddir == DDIR_READ)
		cmd->opcode = nvme_cmd_read;
	else if (io_u->ddir == DDIR_WRITE)
		cmd->opcode = nvme_cmd_write;
	else
		return -ENOTSUP;

	slba = io_u->offset >> data->lba_shift;
	nlb = (io_u->xfer_buflen >> data->lba_shift) - 1;

	/* cdw10 and cdw11 represent starting lba */
	cmd->cdw10 = slba & 0xffffffff;
	cmd->cdw11 = slba >> 32;
	/* cdw12 represent number of lba's for read/write */
	cmd->cdw12 = nlb;
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
		      __u64 *nlba)
{
	struct nvme_id_ns ns;
	int namespace_id;
	int fd, err;

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
		log_err("failed to fetch namespace-id");
		close(fd);
		return -errno;
	}

	/*
	 * Identify namespace to get namespace-id, namespace size in LBA's
	 * and LBA data size.
	 */
	err = nvme_identify(fd, namespace_id, NVME_IDENTIFY_CNS_NS,
				NVME_CSI_NVM, &ns);
	if (err) {
		log_err("failed to fetch identify namespace\n");
		close(fd);
		return err;
	}

	*nsid = namespace_id;
	*lba_sz = 1 << ns.lbaf[(ns.flbas & 0x0f)].ds;
	*nlba = ns.nsze;

	close(fd);
	return 0;
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
					f->file_name, desc->zslba);
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
