// SPDX-License-Identifier: GPL-2.0
/*
 * nvme structure declarations and helper functions for the
 * io_uring_cmd engine.
 */

#include "nvme.h"
#include "../crc/crc-t10dif.h"
#include "../crc/crc64.h"

static void fio_nvme_generate_pi_16b_guard(struct nvme_data *data,
					   struct io_u *io_u,
					   struct nvme_cmd_ext_io_opts *opts)
{
	struct nvme_pi_data *pi_data = io_u->engine_data;
	struct nvme_16b_guard_pif *pi;
	unsigned char *buf = io_u->xfer_buf;
	unsigned char *md_buf = io_u->mmap_data;
	__u64 slba = get_slba(data, io_u->offset);
	__u32 nlb = get_nlb(data, io_u->xfer_buflen) + 1;
	__u32 lba_num = 0;
	__u16 guard = 0;

	if (data->pi_loc) {
		if (data->lba_ext)
			pi_data->interval = data->lba_ext - data->ms;
		else
			pi_data->interval = 0;
	} else {
		if (data->lba_ext)
			pi_data->interval = data->lba_ext - sizeof(struct nvme_16b_guard_pif);
		else
			pi_data->interval = data->ms - sizeof(struct nvme_16b_guard_pif);
	}

	if (io_u->ddir != DDIR_WRITE)
		return;

	while (lba_num < nlb) {
		if (data->lba_ext)
			pi = (struct nvme_16b_guard_pif *)(buf + pi_data->interval);
		else
			pi = (struct nvme_16b_guard_pif *)(md_buf + pi_data->interval);

		if (opts->io_flags & NVME_IO_PRINFO_PRCHK_GUARD) {
			if (data->lba_ext) {
				guard = fio_crc_t10dif(0, buf, pi_data->interval);
			} else {
				guard = fio_crc_t10dif(0, buf, data->lba_size);
				guard = fio_crc_t10dif(guard, md_buf, pi_data->interval);
			}
			pi->guard = cpu_to_be16(guard);
		}

		if (opts->io_flags & NVME_IO_PRINFO_PRCHK_APP)
			pi->apptag = cpu_to_be16(pi_data->apptag);

		if (opts->io_flags & NVME_IO_PRINFO_PRCHK_REF) {
			switch (data->pi_type) {
			case NVME_NS_DPS_PI_TYPE1:
			case NVME_NS_DPS_PI_TYPE2:
				pi->srtag = cpu_to_be32((__u32)slba + lba_num);
				break;
			case NVME_NS_DPS_PI_TYPE3:
				break;
			}
		}
		if (data->lba_ext) {
			buf += data->lba_ext;
		} else {
			buf += data->lba_size;
			md_buf += data->ms;
		}
		lba_num++;
	}
}

static int fio_nvme_verify_pi_16b_guard(struct nvme_data *data,
					struct io_u *io_u)
{
	struct nvme_pi_data *pi_data = io_u->engine_data;
	struct nvme_16b_guard_pif *pi;
	struct fio_file *f = io_u->file;
	unsigned char *buf = io_u->xfer_buf;
	unsigned char *md_buf = io_u->mmap_data;
	__u64 slba = get_slba(data, io_u->offset);
	__u32 nlb = get_nlb(data, io_u->xfer_buflen) + 1;
	__u32 lba_num = 0;
	__u16 unmask_app, unmask_app_exp, guard = 0;

	while (lba_num < nlb) {
		if (data->lba_ext)
			pi = (struct nvme_16b_guard_pif *)(buf + pi_data->interval);
		else
			pi = (struct nvme_16b_guard_pif *)(md_buf + pi_data->interval);

		if (data->pi_type == NVME_NS_DPS_PI_TYPE3) {
			if (pi->apptag == NVME_PI_APP_DISABLE &&
			    pi->srtag == NVME_PI_REF_DISABLE)
				goto next;
		} else if (data->pi_type == NVME_NS_DPS_PI_TYPE1 ||
			   data->pi_type == NVME_NS_DPS_PI_TYPE2) {
			if (pi->apptag == NVME_PI_APP_DISABLE)
				goto next;
		}

		if (pi_data->io_flags & NVME_IO_PRINFO_PRCHK_GUARD) {
			if (data->lba_ext) {
				guard = fio_crc_t10dif(0, buf, pi_data->interval);
			} else {
				guard = fio_crc_t10dif(0, buf, data->lba_size);
				guard = fio_crc_t10dif(guard, md_buf, pi_data->interval);
			}
			if (be16_to_cpu(pi->guard) != guard) {
				log_err("%s: Guard compare error: LBA: %llu Expected=%x, Actual=%x\n",
					f->file_name, (unsigned long long)slba,
					guard, be16_to_cpu(pi->guard));
				return -EIO;
			}
		}

		if (pi_data->io_flags & NVME_IO_PRINFO_PRCHK_APP) {
			unmask_app = be16_to_cpu(pi->apptag) & pi_data->apptag_mask;
			unmask_app_exp = pi_data->apptag & pi_data->apptag_mask;
			if (unmask_app != unmask_app_exp) {
				log_err("%s: APPTAG compare error: LBA: %llu Expected=%x, Actual=%x\n",
					f->file_name, (unsigned long long)slba,
					unmask_app_exp, unmask_app);
				return -EIO;
			}
		}

		if (pi_data->io_flags & NVME_IO_PRINFO_PRCHK_REF) {
			switch (data->pi_type) {
			case NVME_NS_DPS_PI_TYPE1:
			case NVME_NS_DPS_PI_TYPE2:
				if (be32_to_cpu(pi->srtag) !=
				    ((__u32)slba + lba_num)) {
					log_err("%s: REFTAG compare error: LBA: %llu Expected=%x, Actual=%x\n",
						f->file_name, (unsigned long long)slba,
						(__u32)slba + lba_num,
						be32_to_cpu(pi->srtag));
					return -EIO;
				}
				break;
			case NVME_NS_DPS_PI_TYPE3:
				break;
			}
		}
next:
		if (data->lba_ext) {
			buf += data->lba_ext;
		} else {
			buf += data->lba_size;
			md_buf += data->ms;
		}
		lba_num++;
	}

	return 0;
}

static void fio_nvme_generate_pi_64b_guard(struct nvme_data *data,
					   struct io_u *io_u,
					   struct nvme_cmd_ext_io_opts *opts)
{
	struct nvme_pi_data *pi_data = io_u->engine_data;
	struct nvme_64b_guard_pif *pi;
	unsigned char *buf = io_u->xfer_buf;
	unsigned char *md_buf = io_u->mmap_data;
	uint64_t guard = 0;
	__u64 slba = get_slba(data, io_u->offset);
	__u32 nlb = get_nlb(data, io_u->xfer_buflen) + 1;
	__u32 lba_num = 0;

	if (data->pi_loc) {
		if (data->lba_ext)
			pi_data->interval = data->lba_ext - data->ms;
		else
			pi_data->interval = 0;
	} else {
		if (data->lba_ext)
			pi_data->interval = data->lba_ext - sizeof(struct nvme_64b_guard_pif);
		else
			pi_data->interval = data->ms - sizeof(struct nvme_64b_guard_pif);
	}

	if (io_u->ddir != DDIR_WRITE)
		return;

	while (lba_num < nlb) {
		if (data->lba_ext)
			pi = (struct nvme_64b_guard_pif *)(buf + pi_data->interval);
		else
			pi = (struct nvme_64b_guard_pif *)(md_buf + pi_data->interval);

		if (opts->io_flags & NVME_IO_PRINFO_PRCHK_GUARD) {
			if (data->lba_ext) {
				guard = fio_crc64_nvme(0, buf, pi_data->interval);
			} else {
				guard = fio_crc64_nvme(0, buf, data->lba_size);
				guard = fio_crc64_nvme(guard, md_buf, pi_data->interval);
			}
			pi->guard = cpu_to_be64(guard);
		}

		if (opts->io_flags & NVME_IO_PRINFO_PRCHK_APP)
			pi->apptag = cpu_to_be16(pi_data->apptag);

		if (opts->io_flags & NVME_IO_PRINFO_PRCHK_REF) {
			switch (data->pi_type) {
			case NVME_NS_DPS_PI_TYPE1:
			case NVME_NS_DPS_PI_TYPE2:
				put_unaligned_be48(slba + lba_num, pi->srtag);
				break;
			case NVME_NS_DPS_PI_TYPE3:
				break;
			}
		}
		if (data->lba_ext) {
			buf += data->lba_ext;
		} else {
			buf += data->lba_size;
			md_buf += data->ms;
		}
		lba_num++;
	}
}

static int fio_nvme_verify_pi_64b_guard(struct nvme_data *data,
					struct io_u *io_u)
{
	struct nvme_pi_data *pi_data = io_u->engine_data;
	struct nvme_64b_guard_pif *pi;
	struct fio_file *f = io_u->file;
	unsigned char *buf = io_u->xfer_buf;
	unsigned char *md_buf = io_u->mmap_data;
	__u64 slba = get_slba(data, io_u->offset);
	__u64 ref, ref_exp, guard = 0;
	__u32 nlb = get_nlb(data, io_u->xfer_buflen) + 1;
	__u32 lba_num = 0;
	__u16 unmask_app, unmask_app_exp;

	while (lba_num < nlb) {
		if (data->lba_ext)
			pi = (struct nvme_64b_guard_pif *)(buf + pi_data->interval);
		else
			pi = (struct nvme_64b_guard_pif *)(md_buf + pi_data->interval);

		if (data->pi_type == NVME_NS_DPS_PI_TYPE3) {
			if (pi->apptag == NVME_PI_APP_DISABLE &&
			    fio_nvme_pi_ref_escape(pi->srtag))
				goto next;
		} else if (data->pi_type == NVME_NS_DPS_PI_TYPE1 ||
			   data->pi_type == NVME_NS_DPS_PI_TYPE2) {
			if (pi->apptag == NVME_PI_APP_DISABLE)
				goto next;
		}

		if (pi_data->io_flags & NVME_IO_PRINFO_PRCHK_GUARD) {
			if (data->lba_ext) {
				guard = fio_crc64_nvme(0, buf, pi_data->interval);
			} else {
				guard = fio_crc64_nvme(0, buf, data->lba_size);
				guard = fio_crc64_nvme(guard, md_buf, pi_data->interval);
			}
			if (be64_to_cpu((uint64_t)pi->guard) != guard) {
				log_err("%s: Guard compare error: LBA: %llu Expected=%llx, Actual=%llx\n",
					f->file_name, (unsigned long long)slba,
					guard, be64_to_cpu((uint64_t)pi->guard));
				return -EIO;
			}
		}

		if (pi_data->io_flags & NVME_IO_PRINFO_PRCHK_APP) {
			unmask_app = be16_to_cpu(pi->apptag) & pi_data->apptag_mask;
			unmask_app_exp = pi_data->apptag & pi_data->apptag_mask;
			if (unmask_app != unmask_app_exp) {
				log_err("%s: APPTAG compare error: LBA: %llu Expected=%x, Actual=%x\n",
					f->file_name, (unsigned long long)slba,
					unmask_app_exp, unmask_app);
				return -EIO;
			}
		}

		if (pi_data->io_flags & NVME_IO_PRINFO_PRCHK_REF) {
			switch (data->pi_type) {
			case NVME_NS_DPS_PI_TYPE1:
			case NVME_NS_DPS_PI_TYPE2:
				ref = get_unaligned_be48(pi->srtag);
				ref_exp = (slba + lba_num) & ((1ULL << 48) - 1);
				if (ref != ref_exp) {
					log_err("%s: REFTAG compare error: LBA: %llu Expected=%llx, Actual=%llx\n",
						f->file_name, (unsigned long long)slba,
						ref_exp, ref);
					return -EIO;
				}
				break;
			case NVME_NS_DPS_PI_TYPE3:
				break;
			}
		}
next:
		if (data->lba_ext) {
			buf += data->lba_ext;
		} else {
			buf += data->lba_size;
			md_buf += data->ms;
		}
		lba_num++;
	}

	return 0;
}
static void fio_nvme_uring_cmd_trim_prep(struct nvme_uring_cmd *cmd, struct io_u *io_u,
					 struct nvme_dsm *dsm)
{
	struct nvme_data *data = FILE_ENG_DATA(io_u->file);
	struct trim_range *range;
	uint8_t *buf_point;
	int i;

	cmd->opcode = nvme_cmd_dsm;
	cmd->nsid = data->nsid;
	cmd->cdw11 = NVME_ATTRIBUTE_DEALLOCATE;
	cmd->addr = (__u64) (uintptr_t) (&dsm->range[0]);

	if (dsm->nr_ranges == 1) {
		dsm->range[0].slba = get_slba(data, io_u->offset);
		/* nlb is a 1-based value for deallocate */
		dsm->range[0].nlb = get_nlb(data, io_u->xfer_buflen) + 1;
		cmd->cdw10 = 0;
		cmd->data_len = sizeof(struct nvme_dsm_range);
	} else {
		buf_point = io_u->xfer_buf;
		for (i = 0; i < io_u->number_trim; i++) {
			range = (struct trim_range *)buf_point;
			dsm->range[i].slba = get_slba(data, range->start);
			/* nlb is a 1-based value for deallocate */
			dsm->range[i].nlb = get_nlb(data, range->len) + 1;
			buf_point += sizeof(struct trim_range);
		}
		cmd->cdw10 = io_u->number_trim - 1;
		cmd->data_len = io_u->number_trim * sizeof(struct nvme_dsm_range);
	}
}

int fio_nvme_uring_cmd_prep(struct nvme_uring_cmd *cmd, struct io_u *io_u,
			    struct iovec *iov, struct nvme_dsm *dsm,
			    uint8_t read_opcode, uint8_t write_opcode,
			    unsigned int cdw12_flags)
{
	struct nvme_data *data = FILE_ENG_DATA(io_u->file);
	__u64 slba;
	__u32 nlb;

	memset(cmd, 0, sizeof(struct nvme_uring_cmd));

	switch (io_u->ddir) {
	case DDIR_READ:
		cmd->opcode = read_opcode;
		break;
	case DDIR_WRITE:
		cmd->opcode = write_opcode;
		break;
	case DDIR_TRIM:
		fio_nvme_uring_cmd_trim_prep(cmd, io_u, dsm);
		return 0;
	case DDIR_SYNC:
	case DDIR_DATASYNC:
		cmd->opcode = nvme_cmd_flush;
		cmd->nsid = data->nsid;
		return 0;
	default:
		return -ENOTSUP;
	}

	slba = get_slba(data, io_u->offset);
	nlb = get_nlb(data, io_u->xfer_buflen);

	/* cdw10 and cdw11 represent starting lba */
	cmd->cdw10 = slba & 0xffffffff;
	cmd->cdw11 = slba >> 32;
	/* cdw12 represent number of lba's for read/write */
	cmd->cdw12 = nlb | (io_u->dtype << 20) | cdw12_flags;
	cmd->cdw13 = io_u->dspec << 16;
	if (iov) {
		iov->iov_base = io_u->xfer_buf;
		iov->iov_len = io_u->xfer_buflen;
		cmd->addr = (__u64)(uintptr_t)iov;
		cmd->data_len = 1;
	} else {
		/* no buffer for write zeroes */
		if (cmd->opcode != nvme_cmd_write_zeroes)
			cmd->addr = (__u64)(uintptr_t)io_u->xfer_buf;
		else
			cmd->addr = (__u64)(uintptr_t)NULL;
		cmd->data_len = io_u->xfer_buflen;
	}
	if (data->lba_shift && data->ms) {
		cmd->metadata = (__u64)(uintptr_t)io_u->mmap_data;
		cmd->metadata_len = (nlb + 1) * data->ms;
	}
	cmd->nsid = data->nsid;
	return 0;
}

void fio_nvme_generate_guard(struct io_u *io_u, struct nvme_cmd_ext_io_opts *opts)
{
	struct nvme_data *data = FILE_ENG_DATA(io_u->file);

	if (data->pi_type && !(opts->io_flags & NVME_IO_PRINFO_PRACT)) {
		if (data->guard_type == NVME_NVM_NS_16B_GUARD)
			fio_nvme_generate_pi_16b_guard(data, io_u, opts);
		else if (data->guard_type == NVME_NVM_NS_64B_GUARD)
			fio_nvme_generate_pi_64b_guard(data, io_u, opts);
	}
}

void fio_nvme_pi_fill(struct nvme_uring_cmd *cmd, struct io_u *io_u,
		      struct nvme_cmd_ext_io_opts *opts)
{
	struct nvme_data *data = FILE_ENG_DATA(io_u->file);
	__u64 slba;

	slba = get_slba(data, io_u->offset);
	cmd->cdw12 |= opts->io_flags;

	fio_nvme_generate_guard(io_u, opts);

	switch (data->pi_type) {
	case NVME_NS_DPS_PI_TYPE1:
	case NVME_NS_DPS_PI_TYPE2:
		switch (data->guard_type) {
		case NVME_NVM_NS_16B_GUARD:
			if (opts->io_flags & NVME_IO_PRINFO_PRCHK_REF)
				cmd->cdw14 = (__u32)slba;
			break;
		case NVME_NVM_NS_64B_GUARD:
			if (opts->io_flags & NVME_IO_PRINFO_PRCHK_REF) {
				cmd->cdw14 = (__u32)slba;
				cmd->cdw3 = ((slba >> 32) & 0xffff);
			}
			break;
		default:
			break;
		}
		if (opts->io_flags & NVME_IO_PRINFO_PRCHK_APP)
			cmd->cdw15 = (opts->apptag_mask << 16 | opts->apptag);
		break;
	case NVME_NS_DPS_PI_TYPE3:
		if (opts->io_flags & NVME_IO_PRINFO_PRCHK_APP)
			cmd->cdw15 = (opts->apptag_mask << 16 | opts->apptag);
		break;
	case NVME_NS_DPS_PI_NONE:
		break;
	}
}

int fio_nvme_pi_verify(struct nvme_data *data, struct io_u *io_u)
{
	int ret = 0;

	switch (data->guard_type) {
	case NVME_NVM_NS_16B_GUARD:
		ret = fio_nvme_verify_pi_16b_guard(data, io_u);
		break;
	case NVME_NVM_NS_64B_GUARD:
		ret = fio_nvme_verify_pi_64b_guard(data, io_u);
		break;
	default:
		break;
	}

	return ret;
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

int fio_nvme_get_info(struct fio_file *f, __u64 *nlba, __u32 pi_act,
		      struct nvme_data *data)
{
	struct nvme_id_ns ns;
	struct nvme_id_ctrl ctrl;
	struct nvme_nvm_id_ns nvm_ns;
	int namespace_id;
	int fd, err;
	__u32 format_idx, elbaf;

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

	err = nvme_identify(fd, 0, NVME_IDENTIFY_CNS_CTRL, NVME_CSI_NVM, &ctrl);
	if (err) {
		log_err("%s: failed to fetch identify ctrl\n", f->file_name);
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
		goto out;
	}

	data->nsid = namespace_id;

	/*
	 * 16 or 64 as maximum number of supported LBA formats.
	 * From flbas bit 0-3 indicates lsb and bit 5-6 indicates msb
	 * of the format index used to format the namespace.
	 */
	if (ns.nlbaf < 16)
		format_idx = ns.flbas & 0xf;
	else
		format_idx = (ns.flbas & 0xf) + (((ns.flbas >> 5) & 0x3) << 4);

	data->lba_size = 1 << ns.lbaf[format_idx].ds;
	data->ms = le16_to_cpu(ns.lbaf[format_idx].ms);

	/* Check for end to end data protection support */
	if (data->ms && (ns.dps & NVME_NS_DPS_PI_MASK))
		data->pi_type = (ns.dps & NVME_NS_DPS_PI_MASK);

	if (!data->pi_type)
		goto check_elba;

	if (ctrl.ctratt & NVME_CTRL_CTRATT_ELBAS) {
		err = nvme_identify(fd, namespace_id, NVME_IDENTIFY_CNS_CSI_NS,
					NVME_CSI_NVM, &nvm_ns);
		if (err) {
			log_err("%s: failed to fetch identify nvm namespace\n",
				f->file_name);
			goto out;
		}

		elbaf = le32_to_cpu(nvm_ns.elbaf[format_idx]);

		/* Currently we don't support storage tags */
		if (elbaf & NVME_ID_NS_NVM_STS_MASK) {
			log_err("%s: Storage tag not supported\n",
				f->file_name);
			err = -ENOTSUP;
			goto out;
		}

		data->guard_type = (elbaf >> NVME_ID_NS_NVM_GUARD_SHIFT) &
				NVME_ID_NS_NVM_GUARD_MASK;

		/* No 32 bit guard, as storage tag is mandatory for it */
		switch (data->guard_type) {
		case NVME_NVM_NS_16B_GUARD:
			data->pi_size = sizeof(struct nvme_16b_guard_pif);
			break;
		case NVME_NVM_NS_64B_GUARD:
			data->pi_size = sizeof(struct nvme_64b_guard_pif);
			break;
		default:
			break;
		}
	} else {
		data->guard_type = NVME_NVM_NS_16B_GUARD;
		data->pi_size = sizeof(struct nvme_16b_guard_pif);
	}

	/*
	 * when PRACT bit is set to 1, and metadata size is equal to protection
	 * information size, controller inserts and removes PI for write and
	 * read commands respectively.
	 */
	if (pi_act && data->ms == data->pi_size)
		data->ms = 0;

	data->pi_loc = (ns.dps & NVME_NS_DPS_PI_FIRST);

check_elba:
	/*
	 * Bit 4 for flbas indicates if metadata is transferred at the end of
	 * logical block creating an extended LBA.
	 */
	if (data->ms && ((ns.flbas >> 4) & 0x1))
		data->lba_ext = data->lba_size + data->ms;
	else
		data->lba_shift = ilog2(data->lba_size);

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
