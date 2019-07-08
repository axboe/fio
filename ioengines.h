#ifndef FIO_IOENGINE_H
#define FIO_IOENGINE_H

#include <stddef.h>

#include "compiler/compiler.h"
#include "flist.h"
#include "io_u.h"

#define FIO_IOOPS_VERSION	25

/*
 * io_ops->queue() return values
 */
enum fio_q_status {
	FIO_Q_COMPLETED	= 0,		/* completed sync */
	FIO_Q_QUEUED	= 1,		/* queued, will complete async */
	FIO_Q_BUSY	= 2,		/* no more room, call ->commit() */
};

struct ioengine_ops {
	struct flist_head list;
	const char *name;
	int version;
	int flags;
	int (*setup)(struct thread_data *);
	int (*init)(struct thread_data *);
	int (*post_init)(struct thread_data *);
	int (*prep)(struct thread_data *, struct io_u *);
	enum fio_q_status (*queue)(struct thread_data *, struct io_u *);
	int (*commit)(struct thread_data *);
	int (*getevents)(struct thread_data *, unsigned int, unsigned int, const struct timespec *);
	struct io_u *(*event)(struct thread_data *, int);
	char *(*errdetails)(struct io_u *);
	int (*cancel)(struct thread_data *, struct io_u *);
	void (*cleanup)(struct thread_data *);
	int (*open_file)(struct thread_data *, struct fio_file *);
	int (*close_file)(struct thread_data *, struct fio_file *);
	int (*invalidate)(struct thread_data *, struct fio_file *);
	int (*unlink_file)(struct thread_data *, struct fio_file *);
	int (*get_file_size)(struct thread_data *, struct fio_file *);
	void (*terminate)(struct thread_data *);
	int (*iomem_alloc)(struct thread_data *, size_t);
	void (*iomem_free)(struct thread_data *);
	int (*io_u_init)(struct thread_data *, struct io_u *);
	void (*io_u_free)(struct thread_data *, struct io_u *);
	int option_struct_size;
	struct fio_option *options;
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
	FIO_NOSTATS	= 1 << 12,	/* don't do IO stats */
	FIO_NOFILEHASH	= 1 << 13,	/* doesn't hash the files for lookup later. */
	FIO_ASYNCIO_SYNC_TRIM
			= 1 << 14	/* io engine has async ->queue except for trim */
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
extern enum fio_q_status __must_check td_io_queue(struct thread_data *, struct io_u *);
extern int __must_check td_io_getevents(struct thread_data *, unsigned int, unsigned int, const struct timespec *);
extern void td_io_commit(struct thread_data *);
extern int __must_check td_io_open_file(struct thread_data *, struct fio_file *);
extern int td_io_close_file(struct thread_data *, struct fio_file *);
extern int td_io_unlink_file(struct thread_data *, struct fio_file *);
extern int __must_check td_io_get_file_size(struct thread_data *, struct fio_file *);

extern struct ioengine_ops *load_ioengine(struct thread_data *);
extern void register_ioengine(struct ioengine_ops *);
extern void unregister_ioengine(struct ioengine_ops *);
extern void free_ioengine(struct thread_data *);
extern void close_ioengine(struct thread_data *);

extern int fio_show_ioengine_help(const char *engine);

#endif
