#ifndef IO_URING_H
#define IO_URING_H

#include <linux/fs.h>

/*
 * IO submission data structure
 */
struct io_uring_iocb {
	u8	opcode;
	u8	flags;
	u16	ioprio;
	s32	fd;
	u64	off;
	union {
		void	*addr;
		u64	__pad;
	};
	u32	len;
	union {
		__kernel_rwf_t	rw_flags;
		u32		__resv;
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
	s32	res;		/* result code for this event */
	u32	flags;
};

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
	u32 head;
	u32 tail;
	u32 ring_mask;
	u32 ring_entries;
	u32 flags;
	u32 dropped;
	u32 array;
	u32 resv[3];
};

#define IORING_SQ_NEED_WAKEUP	(1 << 0) /* needs io_uring_enter wakeup */

struct io_cqring_offsets {
	u32 head;
	u32 tail;
	u32 ring_mask;
	u32 ring_entries;
	u32 overflow;
	u32 events;
	u32 resv[4];
};

#define IORING_ENTER_GETEVENTS	(1 << 0)

/*
 * Passed in for io_uring_setup(2). Copied back with updated info on success
 */
struct io_uring_params {
	u32 sq_entries;
	u32 cq_entries;
	u32 flags;
	u16 sq_thread_cpu;
	u16 resv[9];
	struct io_sqring_offsets sq_off;
	struct io_cqring_offsets cq_off;
};

#endif
