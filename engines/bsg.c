/*
 * Copyright 2026 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * For conditions of distribution and use, see the accompanying COPYING file.
 *
 */
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
			    struct io_u *io_u, int dxfer_dir,
			    unsigned int cdb_len)
{
	memset(cmd, 0, sizeof(*cmd));
	memset(bc->cdb, 0, sizeof(bc->cdb));

	cmd->request = (uint64_t)(uintptr_t) bc->cdb;
	cmd->request_len = cdb_len;
	cmd->response = (uint64_t)(uintptr_t) bc->sb;
	cmd->max_response_len = sizeof(bc->sb);

	if (dxfer_dir == SG_DXFER_TO_DEV) {
		cmd->dout_xferp = (uint64_t)(uintptr_t) io_u->xfer_buf;
		cmd->dout_xfer_len = io_u->xfer_buflen;
	} else if (dxfer_dir == SG_DXFER_FROM_DEV) {
		cmd->din_xferp = (uint64_t)(uintptr_t) io_u->xfer_buf;
		cmd->din_xfer_len = io_u->xfer_buflen;
	}
}

static int fio_bsg_uring_cmd_rw_lba(struct bsg_cmd *bc, unsigned long long lba,
				    unsigned long long nlb,
				    unsigned int cdb_len)
{
	switch (cdb_len) {
	case 10:
		if (lba > MAX_10CDB_LBA || nlb > MAX_10CDB_NLB) {
			log_err("offset or nlb is larger than the "
				"maximum value of a field within CDB (10)\n");
			return -EINVAL;
		}
		sgio_set_be32((uint32_t) lba, &bc->cdb[2]);
		sgio_set_be16((uint16_t) nlb, &bc->cdb[7]);
		return 0;
	case 16:
		if (lba > MAX_16CDB_LBA || nlb > MAX_16CDB_NLB) {
			log_err("offset or nlb is larger than the "
				"maximum value of a field within CDB (16)\n");
			return -EINVAL;
		}
		sgio_set_be64((uint64_t) lba, &bc->cdb[2]);
		sgio_set_be32((uint32_t) nlb, &bc->cdb[10]);
		return 0;
	case 32:
		if (lba > MAX_32CDB_LBA || nlb > MAX_32CDB_NLB) {
			log_err("offset or nlb is larger than the "
				"maximum value of a field within CDB (32)\n");
			return -EINVAL;
		}
		sgio_set_be64((uint64_t) lba, &bc->cdb[12]);
		sgio_set_be32((uint32_t) nlb, &bc->cdb[28]);
		return 0;
	default:
		log_err("unsupported CDB length: %u\n", cdb_len);
		return -EINVAL;
	}
}

static void fio_bsg_varlen_cdb_header(struct bsg_cmd *bc, uint16_t sa)
{
	bc->cdb[0] = bsg_cmd_varlen;
	sgio_set_be16(sa, &bc->cdb[8]);
	bc->cdb[7] = BSG_VARLEN_CDB_ADDITIONAL_LEN;
}

static void fio_bsg_set_verify_bytchk(struct bsg_cmd *bc, unsigned int cdb_len,
				      unsigned int verify_bytchk)
{
	/*
	 * BYTCHK occupies bits 2-1 of byte 1 for VERIFY(10)/(16) and byte 10
	 * for the 32-byte variable-length VERIFY. BYTCHK=0 leaves the field
	 * cleared (medium verification only).
	 */
	if (cdb_len == 32)
		bc->cdb[10] |= verify_bytchk << 1;
	else
		bc->cdb[1] |= verify_bytchk << 1;
}

int fio_bsg_uring_cmd_prep(struct bsg_uring_cmd *cmd, struct io_u *io_u,
			   struct bsg_cmd *bc, bool fua, unsigned int cdb_len,
			   enum bsg_write_mode wmode,
			   unsigned int verify_bytchk,
			   enum bsg_read_mode rmode)
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

	/*
	 * cdb_len == 0 selects auto-escalation: pick the smallest CDB whose
	 * LBA and transfer-length fields can hold this request, mirroring the
	 * sg engine. READ(10)/WRITE(10) cover a 32-bit LBA and 16-bit length;
	 * anything larger uses READ(16)/WRITE(16). The 32-byte CDB shares the
	 * same 64-bit LBA / 32-bit length field widths as the 16-byte CDB, so
	 * it is never reached by auto-escalation and remains opt-in only.
	 */
	if (cdb_len == 0) {
		if (offset > MAX_10CDB_LBA || nlb > MAX_10CDB_NLB)
			cdb_len = 16;
		else
			cdb_len = 10;
	}

	switch (io_u->ddir) {
	case DDIR_READ:
		if (rmode == BSG_READ_MODE_PREFETCH) {
			/*
			 * PREFETCH pulls the requested blocks from the medium
			 * into the device read cache. No host data transfer.
			 */
			fio_bsg_uring_cmd_init(cmd, bc, io_u, SG_DXFER_NONE,
					       cdb_len);
			switch (cdb_len) {
			case 10:
				bc->cdb[0] = bsg_cmd_prefetch_10;
				break;
			case 16:
				bc->cdb[0] = bsg_cmd_prefetch_16;
				break;
			}
			break;
		}
		fio_bsg_uring_cmd_init(cmd, bc, io_u, SG_DXFER_FROM_DEV, cdb_len);
		switch (cdb_len) {
		case 10:
			bc->cdb[0] = bsg_cmd_read_10;
			if (fua)
				bc->cdb[1] |= 1 << 3;
			break;
		case 16:
			bc->cdb[0] = bsg_cmd_read_16;
			if (fua)
				bc->cdb[1] |= 1 << 3;
			break;
		case 32:
			fio_bsg_varlen_cdb_header(bc, BSG_SA_READ_32);
			if (fua)
				bc->cdb[10] |= 1 << 3;
			break;
		}
		break;
	case DDIR_WRITE:
		if (wmode == BSG_WRITE_MODE_VERIFY) {
			/*
			 * VERIFY data direction depends on BYTCHK:
			 *   0  medium verification only, no host data transfer
			 *   1  compare the whole transfer against the medium
			 *   3  compare a single block against the whole range
			 * BYTCHK 1 and 3 send data to the device.
			 */
			int dxfer = verify_bytchk ? SG_DXFER_TO_DEV :
						    SG_DXFER_NONE;

			fio_bsg_uring_cmd_init(cmd, bc, io_u, dxfer, cdb_len);
			switch (cdb_len) {
			case 10:
				bc->cdb[0] = bsg_cmd_verify_10;
				break;
			case 16:
				bc->cdb[0] = bsg_cmd_verify_16;
				break;
			case 32:
				fio_bsg_varlen_cdb_header(bc, BSG_SA_VERIFY_32);
				break;
			}
			fio_bsg_set_verify_bytchk(bc, cdb_len, verify_bytchk);
			/*
			 * BYTCHK=3 compares one block against the entire
			 * range, so only a single block is transferred while
			 * the CDB still carries the full block count.
			 */
			if (verify_bytchk == 3)
				cmd->dout_xfer_len = data->bs;
			break;
		}
		fio_bsg_uring_cmd_init(cmd, bc, io_u, SG_DXFER_TO_DEV, cdb_len);
		switch (cdb_len) {
		case 10:
			bc->cdb[0] = bsg_cmd_write_10;
			if (fua)
				bc->cdb[1] |= 1 << 3;
			break;
		case 16:
			bc->cdb[0] = bsg_cmd_write_16;
			if (fua)
				bc->cdb[1] |= 1 << 3;
			break;
		case 32:
			fio_bsg_varlen_cdb_header(bc, BSG_SA_WRITE_32);
			if (fua)
				bc->cdb[10] |= 1 << 3;
			break;
		}
		break;
	case DDIR_TRIM:
		/* UNMAP CDB has fixed 10-byte length regardless of cdb_len */
		fio_bsg_uring_cmd_init(cmd, bc, io_u, SG_DXFER_TO_DEV, 10);
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
		/*
		 * SYNCHRONIZE CACHE has 10-byte (0x35) and 16-byte (0x91)
		 * CDB only; no 32-byte service action is defined by
		 * SBC. When cdb_len=32 is requested, fall back to the
		 * 16-byte CDB.
		 */
		if (cdb_len == 10) {
			fio_bsg_uring_cmd_init(cmd, bc, io_u, SG_DXFER_NONE, 10);
			bc->cdb[0] = bsg_cmd_sync_cache_10;
		} else {
			fio_bsg_uring_cmd_init(cmd, bc, io_u, SG_DXFER_NONE, 16);
			bc->cdb[0] = bsg_cmd_sync_cache_16;
		}
		return 0;
	default:
		return -ENOTSUP;
	}

	return fio_bsg_uring_cmd_rw_lba(bc, offset, nlb, cdb_len);
}
