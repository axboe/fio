#include "bsg.h"

int fio_bsg_uring_cmd_read_capacity(struct thread_data *td, unsigned int *bs,
				    unsigned long long *max_lba)
{
	struct sg_io_v4 hdr = { 0 };
	unsigned long long hlba;
	unsigned int blksz = 0;
	unsigned char cmd[16];
	unsigned char sb[64];
	unsigned char buf[32];
	int ret;
	int fd = -1;

	struct fio_file *f = td->files[0];

	/* open file independent of rest of application */
	fd = open(f->file_name, O_RDONLY);
	if (fd < 0)
		return -errno;

	memset(cmd, 0, sizeof(cmd));
	memset(sb, 0, sizeof(sb));
	memset(buf, 0, sizeof(buf));

	cmd[0] = bsg_cmd_read_capacity_10;
	hdr.guard = 'Q';
	hdr.protocol = 0;
	hdr.subprotocol = 0;
	hdr.response = (__u64)(uintptr_t) sb;
	hdr.max_response_len = sizeof(sb);
	hdr.request_len = sizeof(cmd);
	hdr.request = (__u64)(uintptr_t) cmd;
	hdr.din_xferp = (__u64)(uintptr_t) (buf);
	hdr.din_xfer_len = sizeof(buf);

	ret = ioctl(fd, SG_IO, &hdr);
	if (ret < 0) {
		close(fd);
		return ret;
	}

	blksz = sgio_get_be32(&buf[4]);
	hlba = sgio_get_be32(buf);

	if (blksz) {
		*bs = blksz;
		*max_lba = hlba;
		ret = 0;
	} else {
		ret = -EIO;
	}

	close(fd);
	return ret;
}

int fio_bsg_uring_cmd_get_file_size(struct thread_data *td, struct fio_file *f)
{
	unsigned int bs = 0;
	unsigned long long max_lba = 0;
	int ret;

	if (fio_file_size_known(f))
		return 0;

	if (f->filetype != FIO_TYPE_CHAR) {
		td_verror(td, EINVAL, "wrong file type");
		log_err("ioengine io_uring_cmd only works on character devices\n");
		return 1;
	}

	ret = fio_bsg_uring_cmd_read_capacity(td, &bs, &max_lba);
	if (ret) {
		td_verror(td, td->error, "fio_bsg_uring_cmd_read_capacity");
		log_err("ioengine io_uring_cmd unable to successfully execute "
			"read capacity to get block size and maximum lba\n");
		return 1;
	}

	f->real_file_size = (max_lba + 1) * bs;
	fio_file_set_size_known(f);
	return 0;
}

void fio_bsg_uring_cmd_init(struct bsg_uring_cmd *cmd, struct bsg_cmd *bc,
			    struct io_u *io_u, int dxfer_dir)
{
	memset(cmd, 0, sizeof(*cmd));
	memset(bc->cdb, 0, sizeof(bc->cdb));

	cmd->request = (uint64_t)(uintptr_t) bc->cdb;
	cmd->request_len = sizeof(bc->cdb);
	cmd->response = (uint64_t)(uintptr_t) bc->sb;
	cmd->max_response_len = sizeof(bc->sb);

	if (dxfer_dir == SG_DXFER_TO_DEV) {
		cmd->dout_xferp = (uint64_t)(uintptr_t) io_u->xfer_buf;
		cmd->dout_xfer_len = io_u->xfer_buflen;
	} else {
		cmd->din_xferp = (uint64_t)(uintptr_t) io_u->xfer_buf;
		cmd->din_xfer_len = io_u->xfer_buflen;
	}
}

static int fio_bsg_uring_cmd_rw_lba(struct bsg_cmd *bc, unsigned long long lba,
				    unsigned long long nlb)
{
	if (lba > MAX_10CDB_LBA || nlb > MAX_10CDB_NLB) {
		log_err("offset or nlb is larger than the "
			"maximum value of a field within CDB (10)\n");
		return -EINVAL;
	}
	sgio_set_be32((uint32_t) lba, &bc->cdb[2]);
	sgio_set_be16((uint16_t) nlb, &bc->cdb[7]);

	return 0;
}

int fio_bsg_uring_cmd_prep(struct bsg_uring_cmd *cmd, struct io_u *io_u,
			   struct bsg_cmd *bc, bool fua)
{
	struct bsg_data *data = FILE_ENG_DATA(io_u->file);
	unsigned long long offset, nlb;
	int data_len;

	if (io_u->xfer_buflen & (data->bs - 1)) {
		log_err("read/write not sector aligned\n");
		return -EINVAL;
	}

	offset = io_u->offset / data->bs;
	nlb = io_u->xfer_buflen / data->bs;

	switch (io_u->ddir) {
	case DDIR_READ:
		fio_bsg_uring_cmd_init(cmd, bc, io_u, SG_DXFER_FROM_DEV);
		bc->cdb[0] = bsg_cmd_read_10;
		if (fua)
			bc->cdb[1] |= 1 << 3;
		break;
	case DDIR_WRITE:
		fio_bsg_uring_cmd_init(cmd, bc, io_u, SG_DXFER_TO_DEV);
		bc->cdb[0] = bsg_cmd_write_10;
		if (fua)
			bc->cdb[1] |= 1 << 3;
		break;
	case DDIR_TRIM:
		fio_bsg_uring_cmd_init(cmd, bc, io_u, SG_DXFER_TO_DEV);
		bc->cdb[0] = bsg_cmd_unmap;
		data_len = sizeof(bc->unmap_param) / sizeof(bc->unmap_param[0]);
		sgio_set_be16((uint16_t) data_len, &bc->cdb[7]);
		sgio_set_be16((uint16_t) data_len - 2, &bc->unmap_param[0]);
		sgio_set_be16((uint16_t) data_len - 8, &bc->unmap_param[2]);
		sgio_set_be64(offset, &bc->unmap_param[8]);
		sgio_set_be32((uint32_t) nlb, &bc->unmap_param[16]);
		cmd->dout_xferp = (uint64_t)(uintptr_t) bc->unmap_param;
		cmd->dout_xfer_len = data_len;
		return 0;
	case DDIR_SYNC:
		fio_bsg_uring_cmd_init(cmd, bc, io_u, SG_DXFER_NONE);
		bc->cdb[0] = bsg_cmd_sync_cache_10;
		return 0;
	default:
		return -ENOTSUP;
	}

	return fio_bsg_uring_cmd_rw_lba(bc, offset, nlb);
}
