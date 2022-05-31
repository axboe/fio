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
	unsigned int namespace_id;
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
