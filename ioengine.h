#ifndef FIO_IOENGINE_H
#define FIO_IOENGINE_H

#define FIO_IOOPS_VERSION	10

enum {
	IO_U_F_FREE	= 1 << 0,
	IO_U_F_FLIGHT	= 1 << 1,
};

/*
 * The io unit
 */
struct io_u {
	union {
#ifdef FIO_HAVE_LIBAIO
		struct iocb iocb;
#endif
#ifdef FIO_HAVE_POSIXAIO
		struct aiocb aiocb;
#endif
#ifdef FIO_HAVE_SGIO
		struct sg_io_hdr hdr;
#endif
#ifdef FIO_HAVE_GUASI
		guasi_req_t greq;
#endif
#ifdef FIO_HAVE_SOLARISAIO
		aio_result_t resultp;
#endif
		void *mmap_data;
	};
	struct timeval start_time;
	struct timeval issue_time;

	/*
	 * Allocated/set buffer and length
	 */
	void *buf;
	unsigned long buflen;
	unsigned long long offset;

	/*
	 * IO engine state, may be different from above when we get
	 * partial transfers / residual data counts
	 */
	void *xfer_buf;
	unsigned long xfer_buflen;

	unsigned int resid;
	unsigned int error;

	enum fio_ddir ddir;

	/*
	 * io engine private data
	 */
	union {
		unsigned int index;
		unsigned int seen;
		void *engine_data;
	};

	unsigned int flags;

	struct fio_file *file;

	struct flist_head list;

	/*
	 * Callback for io completion
	 */
	int (*end_io)(struct thread_data *, struct io_u *);
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
	int (*getevents)(struct thread_data *, unsigned int, unsigned int, struct timespec *);
	struct io_u *(*event)(struct thread_data *, int);
	int (*cancel)(struct thread_data *, struct io_u *);
	void (*cleanup)(struct thread_data *);
	int (*open_file)(struct thread_data *, struct fio_file *);
	int (*close_file)(struct thread_data *, struct fio_file *);
	int (*get_file_size)(struct thread_data *, struct fio_file *);
	void *data;
	void *dlhandle;
};


/*
 * io engine entry points
 */
extern int __must_check td_io_init(struct thread_data *);
extern int __must_check td_io_prep(struct thread_data *, struct io_u *);
extern int __must_check td_io_queue(struct thread_data *, struct io_u *);
extern int __must_check td_io_sync(struct thread_data *, struct fio_file *);
extern int __must_check td_io_getevents(struct thread_data *, unsigned int, unsigned int, struct timespec *);
extern int __must_check td_io_commit(struct thread_data *);
extern int __must_check td_io_open_file(struct thread_data *, struct fio_file *);
extern int td_io_close_file(struct thread_data *, struct fio_file *);
extern int __must_check td_io_get_file_size(struct thread_data *, struct fio_file *);

extern struct ioengine_ops *load_ioengine(struct thread_data *, const char *);
extern void register_ioengine(struct ioengine_ops *);
extern void unregister_ioengine(struct ioengine_ops *);
extern void close_ioengine(struct thread_data *);

/*
 * io unit handling
 */
#define queue_full(td)	flist_empty(&(td)->io_u_freelist)
extern struct io_u *__get_io_u(struct thread_data *);
extern struct io_u *get_io_u(struct thread_data *);
extern void put_io_u(struct thread_data *, struct io_u *);
extern void requeue_io_u(struct thread_data *, struct io_u **);
extern long __must_check io_u_sync_complete(struct thread_data *, struct io_u *);
extern long __must_check io_u_queued_complete(struct thread_data *, int);
extern void io_u_queued(struct thread_data *, struct io_u *);
extern void io_u_log_error(struct thread_data *, struct io_u *);
extern void io_u_mark_depth(struct thread_data *, unsigned int);
extern void io_u_fill_buffer(struct thread_data *td, struct io_u *, unsigned int);
void io_u_mark_complete(struct thread_data *, unsigned int);
void io_u_mark_submit(struct thread_data *, unsigned int);

#endif
