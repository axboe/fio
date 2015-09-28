#ifndef FIO_IOENGINE_H
#define FIO_IOENGINE_H

#include "compiler/compiler.h"
#include "os/os.h"
#include "log.h"
#include "io_ddir.h"
#include "debug.h"
#include "file.h"

#ifdef CONFIG_LIBAIO
#include <libaio.h>
#endif
#ifdef CONFIG_GUASI
#include <guasi.h>
#endif

#define FIO_IOOPS_VERSION	21

enum {
	IO_U_F_FREE		= 1 << 0,
	IO_U_F_FLIGHT		= 1 << 1,
	IO_U_F_NO_FILE_PUT	= 1 << 2,
	IO_U_F_IN_CUR_DEPTH	= 1 << 3,
	IO_U_F_BUSY_OK		= 1 << 4,
	IO_U_F_TRIMMED		= 1 << 5,
	IO_U_F_BARRIER		= 1 << 6,
	IO_U_F_VER_LIST		= 1 << 7,
};

/*
 * The io unit
 */
struct io_u {
	struct timeval start_time;
	struct timeval issue_time;

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
	unsigned long buflen;
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
	unsigned long xfer_buflen;

	/*
	 * Parameter related to pre-filled buffers and
	 * their size to handle variable block sizes.
	 */
	unsigned long buf_filled_len;

	struct io_piece *ipo;

	unsigned int resid;
	unsigned int error;

	/*
	 * io engine private data
	 */
	union {
		unsigned int index;
		unsigned int seen;
		void *engine_data;
	};

	struct flist_head verify_list;

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
#ifdef FIO_HAVE_BINJECT
		struct b_user_cmd buc;
#endif
#ifdef CONFIG_RDMA
		struct ibv_mr *mr;
#endif
		void *mmap_data;
		uint64_t null;
	};
};

/*
 * io_ops->queue() return values
 */
enum {
	FIO_Q_COMPLETED	= 0,		/* completed sync */
	FIO_Q_QUEUED	= 1,		/* queued, will complete async */
	FIO_Q_BUSY	= 2,		/* no more room, call ->commit() */
};

struct ioengine_ops {
	struct flist_head list;
	char name[16];
	int version;
	int flags;
	int (*setup)(struct thread_data *);
	int (*init)(struct thread_data *);
	int (*prep)(struct thread_data *, struct io_u *);
	int (*queue)(struct thread_data *, struct io_u *);
	int (*commit)(struct thread_data *);
	int (*getevents)(struct thread_data *, unsigned int, unsigned int, const struct timespec *);
	struct io_u *(*event)(struct thread_data *, int);
	const char *(*errdetails)(struct io_u *);  // null when not supported by engine
	int (*cancel)(struct thread_data *, struct io_u *);
	void (*cleanup)(struct thread_data *);
	int (*open_file)(struct thread_data *, struct fio_file *);
	int (*close_file)(struct thread_data *, struct fio_file *);
	int (*invalidate)(struct thread_data *, struct fio_file *);
	int (*unlink_file)(struct thread_data *, struct fio_file *);
	int (*get_file_size)(struct thread_data *, struct fio_file *);
	void (*terminate)(struct thread_data *);
	int (*io_u_init)(struct thread_data *, struct io_u *);
	void (*io_u_free)(struct thread_data *, struct io_u *);
	int option_struct_size;
	struct fio_option *options;
	void *data;
	void *dlhandle;
};

enum fio_ioengine_flags {
	FIO_SYNCIO	= 1 << 0,	/* io engine has synchronous ->queue */
	FIO_RAWIO	= 1 << 1,	/* some sort of direct/raw io */
	FIO_DISKLESSIO	= 1 << 2,	/* no disk involved */
	FIO_NOEXTEND	= 1 << 3,	/* engine can't extend file */
	FIO_NODISKUTIL  = 1 << 4,	/* diskutil can't handle filename */
	FIO_UNIDIR	= 1 << 5,	/* engine is uni-directional */
	FIO_NOIO	= 1 << 6,	/* thread does only pseudo IO */
	FIO_PIPEIO	= 1 << 7,	/* input/output no seekable */
	FIO_BARRIER	= 1 << 8,	/* engine supports barriers */
	FIO_MEMALIGN	= 1 << 9,	/* engine wants aligned memory */
	FIO_BIT_BASED	= 1 << 10,	/* engine uses a bit base (e.g. uses Kbit as opposed to KB) */
	FIO_FAKEIO	= 1 << 11,	/* engine pretends to do IO */
};

/*
 * External engine defined symbol to fill in the engine ops structure
 */
typedef void (*get_ioengine_t)(struct ioengine_ops **);

/*
 * io engine entry points
 */
extern int __must_check td_io_init(struct thread_data *);
extern int __must_check td_io_prep(struct thread_data *, struct io_u *);
extern int __must_check td_io_queue(struct thread_data *, struct io_u *);
extern int __must_check td_io_sync(struct thread_data *, struct fio_file *);
extern int __must_check td_io_getevents(struct thread_data *, unsigned int, unsigned int, const struct timespec *);
extern int __must_check td_io_commit(struct thread_data *);
extern int __must_check td_io_open_file(struct thread_data *, struct fio_file *);
extern int td_io_close_file(struct thread_data *, struct fio_file *);
extern int td_io_unlink_file(struct thread_data *, struct fio_file *);
extern int __must_check td_io_get_file_size(struct thread_data *, struct fio_file *);

extern struct ioengine_ops *load_ioengine(struct thread_data *, const char *);
extern void register_ioengine(struct ioengine_ops *);
extern void unregister_ioengine(struct ioengine_ops *);
extern void free_ioengine(struct thread_data *);
extern void close_ioengine(struct thread_data *);

extern int fio_show_ioengine_help(const char *engine);

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
extern void io_u_quiesce(struct thread_data *);
extern void io_u_log_error(struct thread_data *, struct io_u *);
extern void io_u_mark_depth(struct thread_data *, unsigned int);
extern void fill_io_buffer(struct thread_data *, void *, unsigned int, unsigned int);
extern void io_u_fill_buffer(struct thread_data *td, struct io_u *, unsigned int, unsigned int);
void io_u_mark_complete(struct thread_data *, unsigned int);
void io_u_mark_submit(struct thread_data *, unsigned int);
int queue_full(const struct thread_data *);

int do_io_u_sync(const struct thread_data *, struct io_u *);
int do_io_u_trim(const struct thread_data *, struct io_u *);

#ifdef FIO_INC_DEBUG
static inline void dprint_io_u(struct io_u *io_u, const char *p)
{
	struct fio_file *f = io_u->file;

	dprint(FD_IO, "%s: io_u %p: off=%llu/len=%lu/ddir=%d", p, io_u,
					(unsigned long long) io_u->offset,
					io_u->buflen, io_u->ddir);
	if (fio_debug & (1 << FD_IO)) {
		if (f)
			log_info("/%s", f->file_name);

		log_info("\n");
	}
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

static inline void io_u_clear(struct io_u *io_u, unsigned int flags)
{
	__sync_fetch_and_and(&io_u->flags, ~flags);
}

static inline void io_u_set(struct io_u *io_u, unsigned int flags)
{
	__sync_fetch_and_or(&io_u->flags, flags);
}

#endif
