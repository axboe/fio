// SPDX-License-Identifier: GPL-2.0
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
#define NVME_NQN_LENGTH	256

#define NVME_PI_APP_DISABLE 0xFFFF
#define NVME_PI_REF_DISABLE 0xFFFFFFFF

#define NVME_ZNS_ZRA_REPORT_ZONES 0
#define NVME_ZNS_ZRAS_FEAT_ERZ (1 << 16)
#define NVME_ZNS_ZSA_RESET 0x4
#define NVME_ZONE_TYPE_SEQWRITE_REQ 0x2

#define NVME_ATTRIBUTE_DEALLOCATE (1 << 2)

enum nvme_identify_cns {
	NVME_IDENTIFY_CNS_NS		= 0x00,
	NVME_IDENTIFY_CNS_CTRL		= 0x01,
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
	nvme_cmd_flush			= 0x00,
	nvme_cmd_write			= 0x01,
	nvme_cmd_read			= 0x02,
	nvme_cmd_write_uncor		= 0x04,
	nvme_cmd_compare		= 0x05,
	nvme_cmd_write_zeroes		= 0x08,
	nvme_cmd_dsm			= 0x09,
	nvme_cmd_verify			= 0x0c,
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

enum nvme_id_ctrl_ctratt {
	NVME_CTRL_CTRATT_ELBAS		= 1 << 15,
};

enum {
	NVME_ID_NS_NVM_STS_MASK		= 0x7f,
	NVME_ID_NS_NVM_GUARD_SHIFT	= 7,
	NVME_ID_NS_NVM_GUARD_MASK	= 0x3,
};

enum {
	NVME_NVM_NS_16B_GUARD		= 0,
	NVME_NVM_NS_32B_GUARD		= 1,
	NVME_NVM_NS_64B_GUARD		= 2,
};

struct nvme_data {
	__u32 nsid;
	__u32 lba_shift;
	__u32 lba_size;
	__u32 lba_ext;
	__u16 ms;
	__u16 pi_size;
	__u8 pi_type;
	__u8 guard_type;
	__u8 pi_loc;
};

enum nvme_id_ns_dps {
	NVME_NS_DPS_PI_NONE		= 0,
	NVME_NS_DPS_PI_TYPE1		= 1,
	NVME_NS_DPS_PI_TYPE2		= 2,
	NVME_NS_DPS_PI_TYPE3		= 3,
	NVME_NS_DPS_PI_MASK		= 7 << 0,
	NVME_NS_DPS_PI_FIRST		= 1 << 3,
};

enum nvme_io_control_flags {
	NVME_IO_PRINFO_PRCHK_REF	= 1U << 26,
	NVME_IO_PRINFO_PRCHK_APP	= 1U << 27,
	NVME_IO_PRINFO_PRCHK_GUARD	= 1U << 28,
	NVME_IO_PRINFO_PRACT		= 1U << 29,
};

struct nvme_pi_data {
	__u32 interval;
	__u32 io_flags;
	__u16 apptag;
	__u16 apptag_mask;
};

struct nvme_lbaf {
	__le16			ms;
	__u8			ds;
	__u8			rp;
};

/* 16 bit guard protection Information format */
struct nvme_16b_guard_pif {
	__be16 guard;
	__be16 apptag;
	__be32 srtag;
};

/* 64 bit guard protection Information format */
struct nvme_64b_guard_pif {
	__be64 guard;
	__be16 apptag;
	__u8 srtag[6];
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

struct nvme_id_psd {
	__le16			mp;
	__u8			rsvd2;
	__u8			flags;
	__le32			enlat;
	__le32			exlat;
	__u8			rrt;
	__u8			rrl;
	__u8			rwt;
	__u8			rwl;
	__le16			idlp;
	__u8			ips;
	__u8			rsvd19;
	__le16			actp;
	__u8			apws;
	__u8			rsvd23[9];
};

struct nvme_id_ctrl {
	__le16			vid;
	__le16			ssvid;
	char			sn[20];
	char			mn[40];
	char			fr[8];
	__u8			rab;
	__u8			ieee[3];
	__u8			cmic;
	__u8			mdts;
	__le16			cntlid;
	__le32			ver;
	__le32			rtd3r;
	__le32			rtd3e;
	__le32			oaes;
	__le32			ctratt;
	__le16			rrls;
	__u8			rsvd102[9];
	__u8			cntrltype;
	__u8			fguid[16];
	__le16			crdt1;
	__le16			crdt2;
	__le16			crdt3;
	__u8			rsvd134[119];
	__u8			nvmsr;
	__u8			vwci;
	__u8			mec;
	__le16			oacs;
	__u8			acl;
	__u8			aerl;
	__u8			frmw;
	__u8			lpa;
	__u8			elpe;
	__u8			npss;
	__u8			avscc;
	__u8			apsta;
	__le16			wctemp;
	__le16			cctemp;
	__le16			mtfa;
	__le32			hmpre;
	__le32			hmmin;
	__u8			tnvmcap[16];
	__u8			unvmcap[16];
	__le32			rpmbs;
	__le16			edstt;
	__u8			dsto;
	__u8			fwug;
	__le16			kas;
	__le16			hctma;
	__le16			mntmt;
	__le16			mxtmt;
	__le32			sanicap;
	__le32			hmminds;
	__le16			hmmaxd;
	__le16			nsetidmax;
	__le16			endgidmax;
	__u8			anatt;
	__u8			anacap;
	__le32			anagrpmax;
	__le32			nanagrpid;
	__le32			pels;
	__le16			domainid;
	__u8			rsvd358[10];
	__u8			megcap[16];
	__u8			rsvd384[128];
	__u8			sqes;
	__u8			cqes;
	__le16			maxcmd;
	__le32			nn;
	__le16			oncs;
	__le16			fuses;
	__u8			fna;
	__u8			vwc;
	__le16			awun;
	__le16			awupf;
	__u8			icsvscc;
	__u8			nwpc;
	__le16			acwu;
	__le16			ocfs;
	__le32			sgls;
	__le32			mnan;
	__u8			maxdna[16];
	__le32			maxcna;
	__u8			rsvd564[204];
	char			subnqn[NVME_NQN_LENGTH];
	__u8			rsvd1024[768];

	/* Fabrics Only */
	__le32			ioccsz;
	__le32			iorcsz;
	__le16			icdoff;
	__u8			fcatt;
	__u8			msdbd;
	__le16			ofcs;
	__u8			dctype;
	__u8			rsvd1807[241];

	struct nvme_id_psd	psd[32];
	__u8			vs[1024];
};

struct nvme_nvm_id_ns {
	__le64			lbstm;
	__u8			pic;
	__u8			rsvd9[3];
	__le32			elbaf[64];
	__u8			rsvd268[3828];
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

struct nvme_dsm {
	__u32 nr_ranges;
	struct nvme_dsm_range range[];
};

struct nvme_cmd_ext_io_opts {
	__u32 io_flags;
	__u16 apptag;
	__u16 apptag_mask;
};

int fio_nvme_iomgmt_ruhs(struct thread_data *td, struct fio_file *f,
			 struct nvme_fdp_ruh_status *ruhs, __u32 bytes);

int fio_nvme_get_info(struct fio_file *f, __u64 *nlba, __u32 pi_act,
		      struct nvme_data *data);

int fio_nvme_uring_cmd_prep(struct nvme_uring_cmd *cmd, struct io_u *io_u,
			    struct iovec *iov, struct nvme_dsm *dsm,
			    uint8_t read_opcode, uint8_t write_opcode,
			    unsigned int cdw12_flags);

void fio_nvme_pi_fill(struct nvme_uring_cmd *cmd, struct io_u *io_u,
		      struct nvme_cmd_ext_io_opts *opts);

void fio_nvme_generate_guard(struct io_u *io_u, struct nvme_cmd_ext_io_opts *opts);

int fio_nvme_pi_verify(struct nvme_data *data, struct io_u *io_u);

int fio_nvme_get_zoned_model(struct thread_data *td, struct fio_file *f,
			     enum zbd_zoned_model *model);

int fio_nvme_report_zones(struct thread_data *td, struct fio_file *f,
			  uint64_t offset, struct zbd_zone *zbdz,
			  unsigned int nr_zones);

int fio_nvme_reset_wp(struct thread_data *td, struct fio_file *f,
		      uint64_t offset, uint64_t length);

int fio_nvme_get_max_open_zones(struct thread_data *td, struct fio_file *f,
				unsigned int *max_open_zones);

static inline void put_unaligned_be48(__u64 val, __u8 *p)
{
	*p++ = val >> 40;
	*p++ = val >> 32;
	*p++ = val >> 24;
	*p++ = val >> 16;
	*p++ = val >> 8;
	*p++ = val;
}

static inline __u64 get_unaligned_be48(__u8 *p)
{
	return (__u64)p[0] << 40 | (__u64)p[1] << 32 | (__u64)p[2] << 24 |
		p[3] << 16 | p[4] << 8 | p[5];
}

static inline bool fio_nvme_pi_ref_escape(__u8 *reftag)
{
	__u8 ref_esc[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	return memcmp(reftag, ref_esc, sizeof(ref_esc)) == 0;
}

static inline __u64 get_slba(struct nvme_data *data, __u64 offset)
{
	if (data->lba_ext)
		return offset / data->lba_ext;

	return offset >> data->lba_shift;
}

static inline __u32 get_nlb(struct nvme_data *data, __u64 len)
{
	if (data->lba_ext)
		return len / data->lba_ext - 1;

	return (len >> data->lba_shift) - 1;
}

#endif
