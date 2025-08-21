#ifndef FIO_IOENGINE_H
#define FIO_IOENGINE_H

#include <stddef.h>

#include "compiler/compiler.h"
#include "flist.h"
#include "io_u.h"
#include "zbd_types.h"
#include "dataplacement.h"

#define FIO_IOOPS_VERSION	39

#ifndef CONFIG_DYNAMIC_ENGINES
#define FIO_STATIC	static
#else
#define FIO_STATIC
#endif

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
	void *dlhandle;
	int (*setup)(struct thread_data *);
	int (*init)(struct thread_data *);
	int (*post_init)(struct thread_data *);
	int (*prep)(struct thread_data *, struct io_u *);
	enum fio_q_status (*queue)(struct thread_data *, struct io_u *);
	int (*commit)(struct thread_data *);
	int (*getevents)(struct thread_data *, unsigned int, unsigned int, const struct timespec *);
	struct io_u *(*event)(struct thread_data *, int);
	char *(*errdetails)(struct thread_data *, struct io_u *);
	void (*cleanup)(struct thread_data *);
	int (*open_file)(struct thread_data *, struct fio_file *);
	int (*close_file)(struct thread_data *, struct fio_file *);
	int (*invalidate)(struct thread_data *, struct fio_file *);
	int (*unlink_file)(struct thread_data *, struct fio_file *);
	int (*get_file_size)(struct thread_data *, struct fio_file *);
	int (*prepopulate_file)(struct thread_data *, struct fio_file *);
	void (*terminate)(struct thread_data *);
	int (*iomem_alloc)(struct thread_data *, size_t);
	void (*iomem_free)(struct thread_data *);
	int (*io_u_init)(struct thread_data *, struct io_u *);
	void (*io_u_free)(struct thread_data *, struct io_u *);
	int (*get_zoned_model)(struct thread_data *td,
			       struct fio_file *f, enum zbd_zoned_model *);
	int (*report_zones)(struct thread_data *, struct fio_file *,
			    uint64_t, struct zbd_zone *, unsigned int);
	int (*reset_wp)(struct thread_data *, struct fio_file *,
			uint64_t, uint64_t);
	int (*move_zone_wp)(struct thread_data *, struct fio_file *,
			    struct zbd_zone *, uint64_t, const char *);
	int (*get_max_open_zones)(struct thread_data *, struct fio_file *,
				  unsigned int *);
	int (*get_max_active_zones)(struct thread_data *, struct fio_file *,
				    unsigned int *);
	int (*finish_zone)(struct thread_data *, struct fio_file *,
			   uint64_t, uint64_t);
	int (*fdp_fetch_ruhs)(struct thread_data *, struct fio_file *,
			      struct fio_ruhs_info *);
	int option_struct_size;
	struct fio_option *options;
};

enum {
	__FIO_SYNCIO = 0,		/* io engine has synchronous ->queue */
	__FIO_RAWIO,			/* some sort of direct/raw io */
	__FIO_DISKLESSIO,		/* no disk involved */
	__FIO_NOEXTEND,			/* engine can't extend file */
	__FIO_NODISKUTIL,		/* diskutil can't handle filename */
	__FIO_UNIDIR,			/* engine is uni-directional */
	__FIO_NOIO,			/* thread does only pseudo IO */
	__FIO_PIPEIO,			/* input/output no seekable */
	__FIO_BARRIER,			/* engine supports barriers */
	__FIO_MEMALIGN,			/* engine wants aligned memory */
	__FIO_BIT_BASED,		/* engine uses a bit base (e.g. uses Kbit as opposed to
					   KB) */
	__FIO_FAKEIO,			/* engine pretends to do IO */
	__FIO_NOSTATS,			/* don't do IO stats */
	__FIO_NOFILEHASH,		/* doesn't hash the files for lookup later. */
	__FIO_ASYNCIO_SYNC_TRIM,	/* io engine has async ->queue except for trim */
	__FIO_NO_OFFLOAD,		/* no async offload */
	__FIO_ASYNCIO_SETS_ISSUE_TIME,	/* async ioengine with commit function that sets
					   issue_time */
	__FIO_SKIPPABLE_IOMEM_ALLOC,	/* skip iomem_alloc & iomem_free if job sets mem/iomem */
	__FIO_RO_NEEDS_RW_OPEN,		/* open files in rw mode even if we have a read job; only
					   affects ioengines using generic_open_file */
	__FIO_MULTI_RANGE_TRIM,		/* ioengine supports trim with more than one range */
	__FIO_ATOMICWRITES,		/* ioengine supports atomic writes */
	__FIO_IOENGINE_F_LAST,		/* not a real bit; used to count number of bits */
};

enum fio_ioengine_flags {
	FIO_SYNCIO			= 1 << __FIO_SYNCIO,
	FIO_RAWIO			= 1 << __FIO_RAWIO,
	FIO_DISKLESSIO			= 1 << __FIO_DISKLESSIO,
	FIO_NOEXTEND			= 1 << __FIO_NOEXTEND,
	FIO_NODISKUTIL  		= 1 << __FIO_NODISKUTIL,
	FIO_UNIDIR			= 1 << __FIO_UNIDIR,
	FIO_NOIO			= 1 << __FIO_NOIO,
	FIO_PIPEIO			= 1 << __FIO_PIPEIO,
	FIO_BARRIER			= 1 << __FIO_BARRIER,
	FIO_MEMALIGN			= 1 << __FIO_MEMALIGN,
	FIO_BIT_BASED			= 1 << __FIO_BIT_BASED,
	FIO_FAKEIO			= 1 << __FIO_FAKEIO,
	FIO_NOSTATS			= 1 << __FIO_NOSTATS,
	FIO_NOFILEHASH			= 1 << __FIO_NOFILEHASH,
	FIO_ASYNCIO_SYNC_TRIM		= 1 << __FIO_ASYNCIO_SYNC_TRIM,
	FIO_NO_OFFLOAD			= 1 << __FIO_NO_OFFLOAD,
	FIO_ASYNCIO_SETS_ISSUE_TIME	= 1 << __FIO_ASYNCIO_SETS_ISSUE_TIME,
	FIO_SKIPPABLE_IOMEM_ALLOC	= 1 << __FIO_SKIPPABLE_IOMEM_ALLOC,
	FIO_RO_NEEDS_RW_OPEN		= 1 << __FIO_RO_NEEDS_RW_OPEN,
	FIO_MULTI_RANGE_TRIM		= 1 << __FIO_MULTI_RANGE_TRIM,
	FIO_ATOMICWRITES		= 1 << __FIO_ATOMICWRITES,
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
