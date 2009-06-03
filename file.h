#ifndef FIO_FILE_H
#define FIO_FILE_H

#include "io_ddir.h"

/*
 * The type of object we are working on
 */
enum fio_filetype {
	FIO_TYPE_FILE = 1,		/* plain file */
	FIO_TYPE_BD,			/* block device */
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
};

enum file_lock_mode {
	FILE_LOCK_NONE,
	FILE_LOCK_EXCLUSIVE,
	FILE_LOCK_READWRITE,
};

/*
 * roundrobin available files, or choose one at random, or do each one
 * serially.
 */
enum {
	FIO_FSERVICE_RANDOM	= 1,
	FIO_FSERVICE_RR		= 2,
	FIO_FSERVICE_SEQ	= 3,
};

/*
 * Each thread_data structure has a number of files associated with it,
 * this structure holds state information for a single file.
 */
struct fio_file {
	struct flist_head hash_list;
	enum fio_filetype filetype;

	/*
	 * A file may not be a file descriptor, let the io engine decide
	 */
	union {
		unsigned long file_data;
		int fd;
	};

	/*
	 * filename and possible memory mapping
	 */
	char *file_name;
	unsigned int major, minor;

	void *mmap_ptr;
	size_t mmap_sz;
	off_t mmap_off;

	/*
	 * size of the file, offset into file, and io size from that offset
	 */
	unsigned long long real_file_size;
	unsigned long long file_offset;
	unsigned long long io_size;

	unsigned long long last_pos;

	/*
	 * if io is protected by a semaphore, this is set
	 */
	struct fio_mutex *lock;
	void *lock_owner;
	unsigned int lock_batch;
	enum fio_ddir lock_ddir;

	/*
	 * block map for random io
	 */
	unsigned int *file_map;
	unsigned int num_maps;
	unsigned int last_free_lookup;

	int references;
	enum fio_file_flags flags;

	struct disk_util *du;
};

#define FILE_FLAG_FNS(name)						\
static inline void fio_file_set_##name(struct fio_file *f)		\
{									\
	(f)->flags |= FIO_FILE_##name;					\
}									\
static inline void fio_file_clear_##name(struct fio_file *f)		\
{									\
	(f)->flags &= ~FIO_FILE_##name;					\
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
#undef FILE_FLAG_FNS

/*
 * File setup/shutdown
 */
struct thread_data;
extern void close_files(struct thread_data *);
extern void close_and_free_files(struct thread_data *);
extern int __must_check setup_files(struct thread_data *);
extern int __must_check file_invalidate_cache(struct thread_data *, struct fio_file *);
extern int __must_check generic_open_file(struct thread_data *, struct fio_file *);
extern int __must_check generic_close_file(struct thread_data *, struct fio_file *);
extern int __must_check generic_get_file_size(struct thread_data *, struct fio_file *);
extern int __must_check pre_read_files(struct thread_data *);
extern int add_file(struct thread_data *, const char *);
extern void get_file(struct fio_file *);
extern int __must_check put_file(struct thread_data *, struct fio_file *);
extern void lock_file(struct thread_data *, struct fio_file *, enum fio_ddir);
extern void unlock_file(struct thread_data *, struct fio_file *);
extern void unlock_file_all(struct thread_data *, struct fio_file *);
extern int add_dir_files(struct thread_data *, const char *);
extern int init_random_map(struct thread_data *);
extern void dup_files(struct thread_data *, struct thread_data *);
extern int get_fileno(struct thread_data *, const char *);
extern void free_release_files(struct thread_data *);

#endif
