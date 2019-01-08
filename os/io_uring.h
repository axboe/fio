/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Header file for the io_uring interface.
 *
 * Copyright (C) 2019 Jens Axboe
 * Copyright (C) 2019 Christoph Hellwig
 */
#ifndef LINUX_IO_URING_H
#define LINUX_IO_URING_H

#include <linux/fs.h>
#include <linux/types.h>

/*
 * IO submission data structure
 */
struct io_uring_iocb {
	__u8	opcode;
	__u8	flags;
	__u16	ioprio;
	__s32	fd;
	__u64	off;
	union {
		void	*addr;
		__u64	__pad;
	};
	__u32	len;
	union {
		__kernel_rwf_t	rw_flags;
		__u32		__resv;
	};
};

/*
 * io_uring_setup() flags
 */
#define IORING_SETUP_IOPOLL	(1 << 0)	/* io_context is polled */
#define IORING_SETUP_FIXEDBUFS	(1 << 1)	/* IO buffers are fixed */
#define IORING_SETUP_SQTHREAD	(1 << 2)	/* Use SQ thread */
#define IORING_SETUP_SQWQ	(1 << 3)	/* Use SQ workqueue */
#define IORING_SETUP_SQPOLL	(1 << 4)	/* SQ thread polls */

#define IORING_OP_READ		1
#define IORING_OP_WRITE		2
#define IORING_OP_FSYNC		3
#define IORING_OP_FDSYNC	4
#define IORING_OP_READ_FIXED	5
#define IORING_OP_WRITE_FIXED	6

/*
 * IO completion data structure
 */
struct io_uring_event {
	__u64	index;		/* what iocb this event came from */
	__s32	res;		/* result code for this event */
	__u32	flags;
};

/*
 * io_uring_event->flags
 */
#define IOEV_FLAG_CACHEHIT	(1 << 0)	/* IO did not hit media */

/*
 * Magic offsets for the application to mmap the data it needs
 */
#define IORING_OFF_SQ_RING		0ULL
#define IORING_OFF_CQ_RING		0x8000000ULL
#define IORING_OFF_IOCB			0x10000000ULL

/*
 * Filled with the offset for mmap(2)
 */
struct io_sqring_offsets {
	__u32 head;
	__u32 tail;
	__u32 ring_mask;
	__u32 ring_entries;
	__u32 flags;
	__u32 dropped;
	__u32 array;
	__u32 resv[3];
};

#define IORING_SQ_NEED_WAKEUP	(1 << 0) /* needs io_uring_enter wakeup */

struct io_cqring_offsets {
	__u32 head;
	__u32 tail;
	__u32 ring_mask;
	__u32 ring_entries;
	__u32 overflow;
	__u32 events;
	__u32 resv[4];
};

/*
 * io_uring_enter(2) flags
 */
#define IORING_ENTER_GETEVENTS	(1 << 0)

/*
 * Passed in for io_uring_setup(2). Copied back with updated info on success
 */
struct io_uring_params {
	__u32 sq_entries;
	__u32 cq_entries;
	__u32 flags;
	__u16 sq_thread_cpu;
	__u16 resv[9];
	struct io_sqring_offsets sq_off;
	struct io_cqring_offsets cq_off;
};

#endif
