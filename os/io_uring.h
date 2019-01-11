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
 * IO submission data structure (Submission Queue Entry)
 */
struct io_uring_sqe {
	__u8	opcode;		/* type of operation for this sqe */
	__u8	flags;		/* IOSQE_ flags below */
	__u16	ioprio;		/* ioprio for the request */
	__s32	fd;		/* file descriptor to do IO on */
	__u64	off;		/* offset into file */
	union {
		void	*addr;	/* buffer or iovecs */
		__u64	__pad;
	};
	__u32	len;		/* buffer size or number of iovecs */
	union {
		__kernel_rwf_t	rw_flags;
		__u32		__resv;
	};
	__u16	buf_index;	/* index into fixed buffers, if used */
	__u16	__pad2[3];
	__u64	data;		/* data to be passed back at completion time */
};

/*
 * sqe->flags
 */
#define IOSQE_FIXED_BUFFER	(1 << 0)	/* use fixed buffer */
#define IOSQE_FIXED_FILE	(1 << 1)	/* use fixed fileset */

/*
 * io_uring_setup() flags
 */
#define IORING_SETUP_IOPOLL	(1 << 0)	/* io_context is polled */
#define IORING_SETUP_SQPOLL	(1 << 1)	/* SQ poll thread */
#define IORING_SETUP_SQ_AFF	(1 << 2)	/* sq_thread_cpu is valid */

#define IORING_OP_READV		1
#define IORING_OP_WRITEV	2
#define IORING_OP_FSYNC		3
#define IORING_OP_FDSYNC	4

/*
 * IO completion data structure (Completion Queue Entry)
 */
struct io_uring_cqe {
	__u64	data;		/* sqe->data submission passed back */
	__s32	res;		/* result code for this event */
	__u32	flags;
};

/*
 * io_uring_event->flags
 */
#define IOCQE_FLAG_CACHEHIT	(1 << 0)	/* IO did not hit media */

/*
 * Magic offsets for the application to mmap the data it needs
 */
#define IORING_OFF_SQ_RING		0ULL
#define IORING_OFF_CQ_RING		0x8000000ULL
#define IORING_OFF_SQES			0x10000000ULL

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
	__u32 cqes;
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

/*
 * io_uring_register(2) opcodes and arguments
 */
#define IORING_REGISTER_BUFFERS		0
#define IORING_UNREGISTER_BUFFERS	1
#define IORING_REGISTER_FILES		2
#define IORING_UNREGISTER_FILES		3

struct io_uring_register_buffers {
	struct iovec *iovecs;
	unsigned nr_iovecs;
};

struct io_uring_register_files {
	int *fds;
	unsigned nr_fds;
};

#endif
