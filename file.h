#ifndef FIO_FILE_H
#define FIO_FILE_H

#include <string.h>
#include "compiler/compiler.h"
#include "io_ddir.h"
#include "flist.h"
#include "lib/zipf.h"
#include "lib/axmap.h"
#include "lib/lfsr.h"
#include "lib/gauss.h"

/* Forward declarations */
struct zoned_block_device_info;
struct fdp_ruh_info;

/*
 * The type of object we are working on
 */
enum fio_filetype {
	FIO_TYPE_FILE = 1,		/* plain file */
	FIO_TYPE_BLOCK,			/* block device */
	FIO_TYPE_CHAR,			/* character device */
	FIO_TYPE_PIPE,			/* pipe */
};

enum fio_file_flags {
	FIO_FILE_open		= 1 << 0,	/* file is open */
	FIO_FILE_closing	= 1 << 1,	/* file being closed */
	FIO_FILE_extend		= 1 << 2,	/* needs extend */
	FIO_FILE_done		= 1 << 3,	/* io completed to this file */
	FIO_FILE_size_known	= 1 << 4,	/* size has been set */
	FIO_FILE_hashed		= 1 << 5,	/* file is on hash */
	FIO_FILE_partial_mmap	= 1 << 6,	/* can't do full mmap */
	FIO_FILE_axmap		= 1 << 7,	/* uses axmap */
	FIO_FILE_lfsr		= 1 << 8,	/* lfsr is used */
	FIO_FILE_smalloc	= 1 << 9,	/* smalloc file/file_name */
};

enum file_lock_mode {
	FILE_LOCK_NONE,
	FILE_LOCK_EXCLUSIVE,
	FILE_LOCK_READWRITE,
};

/*
 * How fio chooses what file to service next. Choice of uniformly random, or
 * some skewed random variants, or just sequentially go through them or
 * roundrobing.
 */
enum {
	FIO_FSERVICE_RANDOM		= 1,
	FIO_FSERVICE_RR			= 2,
	FIO_FSERVICE_SEQ		= 3,
	__FIO_FSERVICE_NONUNIFORM	= 0x100,
	FIO_FSERVICE_ZIPF		= __FIO_FSERVICE_NONUNIFORM | 4,
	FIO_FSERVICE_PARETO		= __FIO_FSERVICE_NONUNIFORM | 5,
	FIO_FSERVICE_GAUSS		= __FIO_FSERVICE_NONUNIFORM | 6,

	FIO_FSERVICE_SHIFT		= 10,
};

/*
 * No pre-allocation when laying down files, or call posix_fallocate(), or
 * call fallocate() with FALLOC_FL_KEEP_SIZE set.
 */
enum fio_fallocate_mode {
	FIO_FALLOCATE_NONE	= 1,
	FIO_FALLOCATE_POSIX	= 2,
	FIO_FALLOCATE_KEEP_SIZE	= 3,
	FIO_FALLOCATE_NATIVE	= 4,
	FIO_FALLOCATE_TRUNCATE	= 5,
};

/*
 * Each thread_data structure has a number of files associated with it,
 * this structure holds state information for a single file.
 */
struct fio_file {
	struct flist_head hash_list;
	enum fio_filetype filetype;

	int fd;
	int shadow_fd;
#ifdef WIN32
	HANDLE hFile;
	HANDLE ioCP;
#endif

	/*
	 * filename and possible memory mapping
	 */
	unsigned int major, minor;
	int fileno;
	char *file_name;

	/*
	 * size of the file, offset into file, and io size from that offset
	 * (be aware io_size is different from thread_options::io_size)
	 */
	uint64_t real_file_size;
	uint64_t file_offset;
	uint64_t io_size;

	struct fio_ruhs_info *ruhs_info;
	struct fio_ruhs_scheme *ruhs_scheme;

	/*
	 * Zoned block device information. See also zonemode=zbd.
	 */
	struct zoned_block_device_info *zbd_info;
	/* zonemode=zbd working area */
	uint32_t min_zone;	/* inclusive */
	uint32_t max_zone;	/* exclusive */

	/* SP Random Info */
	struct sprandom_info *spr_info;

	/*
	 * Track last end and last start of IO for a given data direction
	 */
	uint64_t last_pos[DDIR_RWDIR_CNT];
	uint64_t last_start[DDIR_RWDIR_CNT];

	uint64_t first_write;
	uint64_t last_write;

	/*
	 * For use by the io engine to store offset
	 */
	uint64_t engine_pos;

	/*
	 * For use by the io engine for private data storage
	 */
	void *engine_data;

	/*
	 * if io is protected by a semaphore, this is set
	 */
	union {
		struct fio_sem *lock;
		struct fio_rwlock *rwlock;
	};

	/*
	 * block map or LFSR for random io
	 */
	union {
		struct axmap *io_axmap;
		struct fio_lfsr lfsr;
	};

	/*
	 * Used for zipf random distribution
	 */
	union {
		struct zipf_state zipf;
		struct gauss_state gauss;
	};

	int references;
	enum fio_file_flags flags;

	struct disk_util *du;
};

#define FILE_ENG_DATA(f)		((f)->engine_data)
#define FILE_SET_ENG_DATA(f, data)	((f)->engine_data = (data))

#define FILE_FLAG_FNS(name)						\
static inline void fio_file_set_##name(struct fio_file *f)		\
{									\
	(f)->flags = (enum fio_file_flags) ((f)->flags | FIO_FILE_##name);	\
}									\
static inline void fio_file_clear_##name(struct fio_file *f)		\
{									\
	(f)->flags = (enum fio_file_flags) ((f)->flags & ~FIO_FILE_##name);	\
}									\
static inline int fio_file_##name(struct fio_file *f)			\
{									\
	return ((f)->flags & FIO_FILE_##name) != 0;			\
}

FILE_FLAG_FNS(open);
FILE_FLAG_FNS(closing);
FILE_FLAG_FNS(extend);
FILE_FLAG_FNS(done);
FILE_FLAG_FNS(size_known);
FILE_FLAG_FNS(hashed);
FILE_FLAG_FNS(partial_mmap);
FILE_FLAG_FNS(axmap);
FILE_FLAG_FNS(lfsr);
FILE_FLAG_FNS(smalloc);
#undef FILE_FLAG_FNS

/*
 * File setup/shutdown
 */
struct thread_data;
extern void close_files(struct thread_data *);
extern void close_and_free_files(struct thread_data *);
extern uint64_t get_start_offset(struct thread_data *, struct fio_file *);
extern int __must_check setup_files(struct thread_data *);
extern int __must_check file_invalidate_cache(struct thread_data *, struct fio_file *);
#ifdef __cplusplus
extern "C" {
#endif
extern int __must_check generic_open_file(struct thread_data *, struct fio_file *);
extern int __must_check generic_close_file(struct thread_data *, struct fio_file *);
extern int __must_check generic_get_file_size(struct thread_data *, struct fio_file *);
extern int __must_check generic_prepopulate_file(struct thread_data *, struct fio_file *);
#ifdef __cplusplus
}
#endif
extern int __must_check file_lookup_open(struct fio_file *f, int flags);
extern bool __must_check pre_read_files(struct thread_data *);
extern unsigned long long get_rand_file_size(struct thread_data *td);
extern int add_file(struct thread_data *, const char *, int, int);
extern int add_file_exclusive(struct thread_data *, const char *);
extern void get_file(struct fio_file *);
extern int __must_check put_file(struct thread_data *, struct fio_file *);
extern void put_file_log(struct thread_data *, struct fio_file *);
extern void lock_file(struct thread_data *, struct fio_file *, enum fio_ddir);
extern void unlock_file(struct thread_data *, struct fio_file *);
extern void unlock_file_all(struct thread_data *, struct fio_file *);
extern int add_dir_files(struct thread_data *, const char *);
extern bool init_random_map(struct thread_data *);
extern void dup_files(struct thread_data *, struct thread_data *);
extern int get_fileno(struct thread_data *, const char *);
extern void free_release_files(struct thread_data *);
extern void filesetup_mem_free(void);
extern void fio_file_reset(struct thread_data *, struct fio_file *);
extern bool fio_files_done(struct thread_data *);
extern bool exists_and_not_regfile(const char *);
extern int fio_set_directio(struct thread_data *, struct fio_file *);
extern void fio_file_free(struct fio_file *);

#endif
