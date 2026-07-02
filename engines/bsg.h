/*
 * bsg structure declarations and helper functions for the
 * io_uring_cmd engine.
 *
 * Copyright 2026 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * For conditions of distribution and use, see the accompanying COPYING file.
 *
 */

#ifndef FIO_BSG_H
#define FIO_BSG_H

#include <linux/bsg.h>
#include <poll.h>
#include "../fio.h"
#include "sg.h"

/*
 * If the uapi headers installed on the system lacks bsg uring command
 * support, use the local version to prevent compilation issues.
 */
#ifndef CONFIG_BSG_URING_CMD
struct bsg_uring_cmd {
	__u64 request;
	__u32 request_len;
	__u32 protocol;
	__u32 subprotocol;
	__u32 max_response_len;
	__u64 response;
	__u64 dout_xferp;
	__u32 dout_xfer_len;
	__u32 dout_iovec_count;
	__u64 din_xferp;
	__u32 din_xfer_len;
	__u32 din_iovec_count;
	__u32 timeout_ms;
	__u8  reserved[12];
};
#endif /* CONFIG_BSG_URING_CMD */

#define MAX_SB 64
#define MAX_CDB_LEN 32

#define MAX_10CDB_LBA  0xFFFFFFFFULL
#define MAX_10CDB_NLB  0xFFFFU
#define MAX_16CDB_LBA  0xFFFFFFFFFFFFFFFFULL
#define MAX_16CDB_NLB  0xFFFFFFFFU
#define MAX_32CDB_LBA  MAX_16CDB_LBA
#define MAX_32CDB_NLB  MAX_16CDB_NLB

/* Variable-length CDB (opcode 0x7F) service actions for 32-byte CDBs */
#define BSG_VARLEN_CDB_OPCODE		0x7F
#define BSG_VARLEN_CDB_ADDITIONAL_LEN	0x18	/* 24 -> total 32 bytes */
#define BSG_SA_READ_32			0x0009
#define BSG_SA_WRITE_32			0x000B
#define BSG_SA_VERIFY_32		0x000A

/* SAM status byte returned in bits [0..7] of the BSG uring_cmd big_cqe[0] */
#define BSG_STAT_CONDITION_MET         0x04

enum bsg_io_opcode {
	bsg_cmd_read_10			= 0x28,
	bsg_cmd_read_16			= 0x88,
	bsg_cmd_read_capacity_10	= 0x25,
	bsg_cmd_sync_cache_10		= 0x35,
	bsg_cmd_sync_cache_16		= 0x91,
	bsg_cmd_unmap			= 0x42,
	bsg_cmd_write_10		= 0x2A,
	bsg_cmd_write_16		= 0x8A,
	bsg_cmd_verify_10		= 0x2F,
	bsg_cmd_verify_16		= 0x8F,
	bsg_cmd_prefetch_10		= 0x34,
	bsg_cmd_prefetch_16		= 0x90,
	bsg_cmd_varlen			= BSG_VARLEN_CDB_OPCODE,
};

/* Which command mode to issue for DDIR_WRITE ddir. */
enum bsg_write_mode {
	BSG_WRITE_MODE_WRITE = 0,
	BSG_WRITE_MODE_VERIFY,
};

/* Which command mode to issue for DDIR_READ ddir. */
enum bsg_read_mode {
	BSG_READ_MODE_READ = 0,
	BSG_READ_MODE_PREFETCH,
};

struct bsg_cmd {
	unsigned char cdb[MAX_CDB_LEN];
	unsigned char sb[MAX_SB];
	uint8_t unmap_param[24];
};

struct bsg_data {
	unsigned int bs;
};

int fio_bsg_uring_cmd_read_capacity(struct thread_data *td, unsigned int *bs,
				    unsigned long long *max_lba);

int fio_bsg_uring_cmd_get_file_size(struct thread_data *td, struct fio_file *f);

int fio_bsg_uring_cmd_prep(struct bsg_uring_cmd *cmd, struct io_u *io_u,
			   struct bsg_cmd *bc, bool fua, unsigned int cdb_len,
			   enum bsg_write_mode wmode,
			   unsigned int verify_bytchk,
			   enum bsg_read_mode rmode);

#endif /* FIO_BSG_H */
