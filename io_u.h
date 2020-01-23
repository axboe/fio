#ifndef FIO_IO_U
#define FIO_IO_U

#include "compiler/compiler.h"
#include "os/os.h"
#include "io_ddir.h"
#include "debug.h"
#include "file.h"
#include "workqueue.h"

#ifdef CONFIG_LIBAIO
#include <libaio.h>
#endif
#ifdef CONFIG_GUASI
#include <guasi.h>
#endif

enum {
	IO_U_F_FREE		= 1 << 0,
	IO_U_F_FLIGHT		= 1 << 1,
	IO_U_F_NO_FILE_PUT	= 1 << 2,
	IO_U_F_IN_CUR_DEPTH	= 1 << 3,
	IO_U_F_BUSY_OK		= 1 << 4,
	IO_U_F_TRIMMED		= 1 << 5,
	IO_U_F_BARRIER		= 1 << 6,
	IO_U_F_VER_LIST		= 1 << 7,
	IO_U_F_PRIORITY		= 1 << 8,
};

/*
 * The io unit
 */
struct io_u {
	struct timespec start_time;
	struct timespec issue_time;

	struct fio_file *file;
	unsigned int flags;
	enum fio_ddir ddir;

	/*
	 * For replay workloads, we may want to account as a different
	 * IO type than what is being submitted.
	 */
	enum fio_ddir acct_ddir;

	/*
	 * Write generation
	 */
	unsigned short numberio;

	/*
	 * Allocated/set buffer and length
	 */
	unsigned long long buflen;
	unsigned long long offset;
	void *buf;

	/*
	 * Initial seed for generating the buffer contents
	 */
	uint64_t rand_seed;

	/*
	 * IO engine state, may be different from above when we get
	 * partial transfers / residual data counts
	 */
	void *xfer_buf;
	unsigned long long xfer_buflen;

	/*
	 * Parameter related to pre-filled buffers and
	 * their size to handle variable block sizes.
	 */
	unsigned long long buf_filled_len;

	struct io_piece *ipo;

	unsigned long long resid;
	unsigned int error;

	/*
	 * io engine private data
	 */
	union {
		unsigned int index;
		unsigned int seen;
		void *engine_data;
	};

	union {
		struct flist_head verify_list;
		struct workqueue_work work;
	};

#ifdef CONFIG_LINUX_BLKZONED
	/*
	 * ZBD mode zbd_queue_io callback: called after engine->queue operation
	 * to advance a zone write pointer and eventually unlock the I/O zone.
	 * @q indicates the I/O queue status (busy, queued or completed).
	 * @success == true means that the I/O operation has been queued or
	 * completed successfully.
	 */
	void (*zbd_queue_io)(struct io_u *, int q, bool success);

	/*
	 * ZBD mode zbd_put_io callback: called in after completion of an I/O
	 * or commit of an async I/O to unlock the I/O target zone.
	 */
	void (*zbd_put_io)(const struct io_u *);
#endif

	/*
	 * Callback for io completion
	 */
	int (*end_io)(struct thread_data *, struct io_u **);

	union {
#ifdef CONFIG_LIBAIO
		struct iocb iocb;
#endif
#ifdef CONFIG_POSIXAIO
		os_aiocb_t aiocb;
#endif
#ifdef FIO_HAVE_SGIO
		struct sg_io_hdr hdr;
#endif
#ifdef CONFIG_GUASI
		guasi_req_t greq;
#endif
#ifdef CONFIG_SOLARISAIO
		aio_result_t resultp;
#endif
#ifdef CONFIG_RDMA
		struct ibv_mr *mr;
#endif
		void *mmap_data;
	};
};

/*
 * io unit handling
 */
extern struct io_u *__get_io_u(struct thread_data *);
extern struct io_u *get_io_u(struct thread_data *);
extern void put_io_u(struct thread_data *, struct io_u *);
extern void clear_io_u(struct thread_data *, struct io_u *);
extern void requeue_io_u(struct thread_data *, struct io_u **);
extern int __must_check io_u_sync_complete(struct thread_data *, struct io_u *);
extern int __must_check io_u_queued_complete(struct thread_data *, int);
extern void io_u_queued(struct thread_data *, struct io_u *);
extern int io_u_quiesce(struct thread_data *);
extern void io_u_log_error(struct thread_data *, struct io_u *);
extern void io_u_mark_depth(struct thread_data *, unsigned int);
extern void fill_io_buffer(struct thread_data *, void *, unsigned long long, unsigned long long);
extern void io_u_fill_buffer(struct thread_data *td, struct io_u *, unsigned long long, unsigned long long);
void io_u_mark_complete(struct thread_data *, unsigned int);
void io_u_mark_submit(struct thread_data *, unsigned int);
bool queue_full(const struct thread_data *);

int do_io_u_sync(const struct thread_data *, struct io_u *);
int do_io_u_trim(const struct thread_data *, struct io_u *);

#ifdef FIO_INC_DEBUG
static inline void dprint_io_u(struct io_u *io_u, const char *p)
{
	struct fio_file *f = io_u->file;

	if (f)
		dprint(FD_IO, "%s: io_u %p: off=0x%llx,len=0x%llx,ddir=%d,file=%s\n",
				p, io_u,
				(unsigned long long) io_u->offset,
				io_u->buflen, io_u->ddir,
				f->file_name);
	else
		dprint(FD_IO, "%s: io_u %p: off=0x%llx,len=0x%llx,ddir=%d\n",
				p, io_u,
				(unsigned long long) io_u->offset,
				io_u->buflen, io_u->ddir);
}
#else
#define dprint_io_u(io_u, p)
#endif

static inline enum fio_ddir acct_ddir(struct io_u *io_u)
{
	if (io_u->acct_ddir != -1)
		return io_u->acct_ddir;

	return io_u->ddir;
}

#define io_u_clear(td, io_u, val)	\
	td_flags_clear((td), &(io_u->flags), (val))
#define io_u_set(td, io_u, val)		\
	td_flags_set((td), &(io_u)->flags, (val))
#define io_u_is_prio(io_u)	\
	(io_u->flags & (unsigned int) IO_U_F_PRIORITY) != 0

#endif
