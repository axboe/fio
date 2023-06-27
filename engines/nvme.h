/*
 * nvme structure declarations and helper functions for the
 * io_uring_cmd engine.
 */

#ifndef FIO_NVME_H
#define FIO_NVME_H

#include <linux/nvme_ioctl.h>
#include "../fio.h"

/*
 * If the uapi headers installed on the system lacks nvme uring command
 * support, use the local version to prevent compilation issues.
 */
#ifndef CONFIG_NVME_URING_CMD
struct nvme_uring_cmd {
	__u8	opcode;
	__u8	flags;
	__u16	rsvd1;
	__u32	nsid;
	__u32	cdw2;
	__u32	cdw3;
	__u64	metadata;
	__u64	addr;
	__u32	metadata_len;
	__u32	data_len;
	__u32	cdw10;
	__u32	cdw11;
	__u32	cdw12;
	__u32	cdw13;
	__u32	cdw14;
	__u32	cdw15;
	__u32	timeout_ms;
	__u32   rsvd2;
};

#define NVME_URING_CMD_IO	_IOWR('N', 0x80, struct nvme_uring_cmd)
#define NVME_URING_CMD_IO_VEC	_IOWR('N', 0x81, struct nvme_uring_cmd)
#endif /* CONFIG_NVME_URING_CMD */

#define NVME_DEFAULT_IOCTL_TIMEOUT 0
#define NVME_IDENTIFY_DATA_SIZE 4096
#define NVME_IDENTIFY_CSI_SHIFT 24

#define NVME_ZNS_ZRA_REPORT_ZONES 0
#define NVME_ZNS_ZRAS_FEAT_ERZ (1 << 16)
#define NVME_ZNS_ZSA_RESET 0x4
#define NVME_ZONE_TYPE_SEQWRITE_REQ 0x2

#define NVME_ATTRIBUTE_DEALLOCATE (1 << 2)

enum nvme_identify_cns {
	NVME_IDENTIFY_CNS_NS		= 0x00,
	NVME_IDENTIFY_CNS_CSI_NS	= 0x05,
	NVME_IDENTIFY_CNS_CSI_CTRL	= 0x06,
};

enum nvme_csi {
	NVME_CSI_NVM			= 0,
	NVME_CSI_KV			= 1,
	NVME_CSI_ZNS			= 2,
};

enum nvme_admin_opcode {
	nvme_admin_identify		= 0x06,
};

enum nvme_io_opcode {
	nvme_cmd_write			= 0x01,
	nvme_cmd_read			= 0x02,
	nvme_cmd_dsm			= 0x09,
	nvme_cmd_io_mgmt_recv		= 0x12,
	nvme_zns_cmd_mgmt_send		= 0x79,
	nvme_zns_cmd_mgmt_recv		= 0x7a,
};

enum nvme_zns_zs {
	NVME_ZNS_ZS_EMPTY		= 0x1,
	NVME_ZNS_ZS_IMPL_OPEN		= 0x2,
	NVME_ZNS_ZS_EXPL_OPEN		= 0x3,
	NVME_ZNS_ZS_CLOSED		= 0x4,
	NVME_ZNS_ZS_READ_ONLY		= 0xd,
	NVME_ZNS_ZS_FULL		= 0xe,
	NVME_ZNS_ZS_OFFLINE		= 0xf,
};

struct nvme_data {
	__u32 nsid;
	__u32 lba_shift;
	__u32 lba_ext;
};

struct nvme_lbaf {
	__le16			ms;
	__u8			ds;
	__u8			rp;
};

struct nvme_id_ns {
	__le64			nsze;
	__le64			ncap;
	__le64			nuse;
	__u8			nsfeat;
	__u8			nlbaf;
	__u8			flbas;
	__u8			mc;
	__u8			dpc;
	__u8			dps;
	__u8			nmic;
	__u8			rescap;
	__u8			fpi;
	__u8			dlfeat;
	__le16			nawun;
	__le16			nawupf;
	__le16			nacwu;
	__le16			nabsn;
	__le16			nabo;
	__le16			nabspf;
	__le16			noiob;
	__u8			nvmcap[16];
	__le16			npwg;
	__le16			npwa;
	__le16			npdg;
	__le16			npda;
	__le16			nows;
	__le16			mssrl;
	__le32			mcl;
	__u8			msrc;
	__u8			rsvd81[11];
	__le32			anagrpid;
	__u8			rsvd96[3];
	__u8			nsattr;
	__le16			nvmsetid;
	__le16			endgid;
	__u8			nguid[16];
	__u8			eui64[8];
	struct nvme_lbaf	lbaf[64];
	__u8			vs[3712];
};

static inline int ilog2(uint32_t i)
{
	int log = -1;

	while (i) {
		i >>= 1;
		log++;
	}
	return log;
}

struct nvme_zns_lbafe {
	__le64	zsze;
	__u8	zdes;
	__u8	rsvd9[7];
};

struct nvme_zns_id_ns {
	__le16			zoc;
	__le16			ozcs;
	__le32			mar;
	__le32			mor;
	__le32			rrl;
	__le32			frl;
	__le32			rrl1;
	__le32			rrl2;
	__le32			rrl3;
	__le32			frl1;
	__le32			frl2;
	__le32			frl3;
	__le32			numzrwa;
	__le16			zrwafg;
	__le16			zrwasz;
	__u8			zrwacap;
	__u8			rsvd53[2763];
	struct nvme_zns_lbafe	lbafe[64];
	__u8			vs[256];
};

struct nvme_zns_desc {
	__u8	zt;
	__u8	zs;
	__u8	za;
	__u8	zai;
	__u8	rsvd4[4];
	__le64	zcap;
	__le64	zslba;
	__le64	wp;
	__u8	rsvd32[32];
};

struct nvme_zone_report {
	__le64			nr_zones;
	__u8			rsvd8[56];
	struct nvme_zns_desc	entries[];
};

struct nvme_fdp_ruh_status_desc {
	__u16 pid;
	__u16 ruhid;
	__u32 earutr;
	__u64 ruamw;
	__u8  rsvd16[16];
};

struct nvme_fdp_ruh_status {
	__u8  rsvd0[14];
	__le16 nruhsd;
	struct nvme_fdp_ruh_status_desc ruhss[];
};

struct nvme_dsm_range {
	__le32	cattr;
	__le32	nlb;
	__le64	slba;
};

int fio_nvme_iomgmt_ruhs(struct thread_data *td, struct fio_file *f,
			 struct nvme_fdp_ruh_status *ruhs, __u32 bytes);

int fio_nvme_get_info(struct fio_file *f, __u32 *nsid, __u32 *lba_sz,
		      __u32 *ms, __u64 *nlba);

int fio_nvme_uring_cmd_prep(struct nvme_uring_cmd *cmd, struct io_u *io_u,
			    struct iovec *iov, struct nvme_dsm_range *dsm);

int fio_nvme_get_zoned_model(struct thread_data *td, struct fio_file *f,
			     enum zbd_zoned_model *model);

int fio_nvme_report_zones(struct thread_data *td, struct fio_file *f,
			  uint64_t offset, struct zbd_zone *zbdz,
			  unsigned int nr_zones);

int fio_nvme_reset_wp(struct thread_data *td, struct fio_file *f,
		      uint64_t offset, uint64_t length);

int fio_nvme_get_max_open_zones(struct thread_data *td, struct fio_file *f,
				unsigned int *max_open_zones);

#endif
