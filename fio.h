#ifndef FIO_H
#define FIO_H

#include <sched.h>
#include <limits.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>

#include "compiler/compiler.h"
#include "list.h"
#include "fifo.h"
#include "rbtree.h"
#include "md5.h"
#include "crc32.h"
#include "arch/arch.h"
#include "os/os.h"
#include "mutex.h"

#ifdef FIO_HAVE_SYSLET
#include "syslet.h"
#endif

#ifdef FIO_HAVE_GUASI
#include <guasi.h>
#endif

enum fio_ddir {
	DDIR_READ = 0,
	DDIR_WRITE,
	DDIR_SYNC,
};

enum td_ddir {
	TD_DDIR_READ		= 1 << 0,
	TD_DDIR_WRITE		= 1 << 1,
	TD_DDIR_RAND		= 1 << 2,
	TD_DDIR_RW		= TD_DDIR_READ | TD_DDIR_WRITE,
	TD_DDIR_RANDREAD	= TD_DDIR_READ | TD_DDIR_RAND,
	TD_DDIR_RANDWRITE	= TD_DDIR_WRITE | TD_DDIR_RAND,
	TD_DDIR_RANDRW		= TD_DDIR_RW | TD_DDIR_RAND,
};

/*
 * Use for maintaining statistics
 */
struct io_stat {
	unsigned long max_val;
	unsigned long min_val;
	unsigned long samples;

	double mean;
	double S;
};

/*
 * A single data sample
 */
struct io_sample {
	unsigned long time;
	unsigned long val;
	enum fio_ddir ddir;
};

/*
 * Dynamically growing data sample log
 */
struct io_log {
	unsigned long nr_samples;
	unsigned long max_samples;
	struct io_sample *log;
};

/*
 * When logging io actions, this matches a single sent io_u
 */
struct io_piece {
	union {
		struct rb_node rb_node;
		struct list_head list;
	};
	struct fio_file *file;
	unsigned long long offset;
	unsigned long len;
	enum fio_ddir ddir;
	unsigned long delay;
};

#ifdef FIO_HAVE_SYSLET
struct syslet_req {
	struct syslet_uatom atom;	/* the atom to submit */
	struct syslet_uatom *head;	/* head of the sequence */
	long ret;			/* syscall return value */
};
#endif

enum {
	IO_U_F_FREE	= 1 << 0,
	IO_U_F_FLIGHT	= 1 << 1,
};

struct thread_data;

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
#ifdef FIO_HAVE_SYSLET
		struct syslet_req req;
#endif
#ifdef FIO_HAVE_GUASI
		guasi_req_t greq;
#endif
	};
	struct timeval start_time;
	struct timeval issue_time;

	/*
	 * Allocated/set buffer and length
	 */
	void *buf;
	unsigned long buflen;
	unsigned long long offset;
	unsigned long long endpos;

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
	};

	unsigned int flags;

	struct fio_file *file;

	struct list_head list;

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

#define FIO_HDR_MAGIC	0xf00baaef

enum {
	VERIFY_NONE = 0,		/* no verification */
	VERIFY_MD5,			/* md5 sum data blocks */
	VERIFY_CRC32,			/* crc32 sum data blocks */
	VERIFY_NULL,			/* pretend to verify */
};

/*
 * A header structure associated with each checksummed data block
 */
struct verify_header {
	unsigned int fio_magic;
	unsigned int len;
	unsigned int verify_type;
	union {
		char md5_digest[MD5_HASH_WORDS * 4];
		unsigned long crc32;
	};
};

struct group_run_stats {
	unsigned long long max_run[2], min_run[2];
	unsigned long long max_bw[2], min_bw[2];
	unsigned long long io_kb[2];
	unsigned long long agg[2];
};

/*
 * What type of allocation to use for io buffers
 */
enum fio_memtype {
	MEM_MALLOC = 0,	/* ordinary malloc */
	MEM_SHM,	/* use shared memory segments */
	MEM_SHMHUGE,	/* use shared memory segments with huge pages */
	MEM_MMAP,	/* use anonynomous mmap */
	MEM_MMAPHUGE,	/* memory mapped huge file */
};

/*
 * The type of object we are working on
 */
enum fio_filetype {
	FIO_TYPE_FILE = 1,		/* plain file */
	FIO_TYPE_BD,			/* block device */
	FIO_TYPE_CHAR,			/* character device */
	FIO_TYPE_PIPE,			/* pipe */
};

enum fio_ioengine_flags {
	FIO_SYNCIO	= 1 << 0,	/* io engine has synchronous ->queue */
	FIO_RAWIO	= 1 << 1,	/* some sort of direct/raw io */
	FIO_DISKLESSIO	= 1 << 2,	/* no disk involved */
	FIO_NOEXTEND	= 1 << 3,	/* engine can't extend file */
	FIO_NODISKUTIL  = 1 << 4,       /* diskutil can't handle filename */
};

enum fio_file_flags {
	FIO_FILE_OPEN		= 1 << 0,	/* file is open */
	FIO_FILE_CLOSING	= 1 << 1,	/* file being closed */
	FIO_FILE_EXISTS		= 1 << 2,	/* file there */
	FIO_FILE_EXTEND		= 1 << 3,	/* needs extend */
	FIO_FILE_NOSORT		= 1 << 4,	/* don't sort verify blocks */
	FIO_FILE_DONE		= 1 << 5,	/* io completed to this file */
	FIO_SIZE_KNOWN		= 1 << 6,	/* size has been set */
};

/*
 * Each thread_data structure has a number of files associated with it,
 * this structure holds state information for a single file.
 */
struct fio_file {
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
	void *mmap;

	/*
	 * size of the file, offset into file, and io size from that offset
	 */
	unsigned long long real_file_size;
	unsigned long long file_offset;
	unsigned long long io_size;

	unsigned long long last_pos;
	unsigned long long last_completed_pos;

	/*
	 * block map for random io
	 */
	unsigned long *file_map;
	unsigned int num_maps;
	unsigned int last_free_lookup;

	int references;
	enum fio_file_flags flags;
};

/*
 * How many depth levels to log
 */
#define FIO_IO_U_MAP_NR	8
#define FIO_IO_U_LAT_NR 12

struct thread_stat {
	char *name;
	char *verror;
	int error;
	int groupid;
	pid_t pid;
	char *description;
	int members;

	struct io_log *slat_log;
	struct io_log *clat_log;
	struct io_log *bw_log;

	/*
	 * bandwidth and latency stats
	 */
	struct io_stat clat_stat[2];		/* completion latency */
	struct io_stat slat_stat[2];		/* submission latency */
	struct io_stat bw_stat[2];		/* bandwidth stats */

	unsigned long long stat_io_bytes[2];
	struct timeval stat_sample_time[2];

	/*
	 * fio system usage accounting
	 */
	struct rusage ru_start;
	struct rusage ru_end;
	unsigned long usr_time;
	unsigned long sys_time;
	unsigned long ctx;

	/*
	 * IO depth and latency stats
	 */
	unsigned int io_u_map[FIO_IO_U_MAP_NR];
	unsigned int io_u_lat[FIO_IO_U_LAT_NR];
	unsigned long total_io_u[2];
	unsigned long short_io_u[2];

	unsigned long long io_bytes[2];
	unsigned long runtime[2];
	unsigned long total_run_time;
};

struct thread_options {
	int pad;
	char *description;
	char *name;
	char *directory;
	char *filename;
	char *opendir;
	char *ioengine;
	enum td_ddir td_ddir;
	unsigned int ddir_nr;
	unsigned int iodepth;
	unsigned int iodepth_low;
	unsigned int iodepth_batch;

	unsigned long long size;
	unsigned long long file_size_low;
	unsigned long long file_size_high;
	unsigned long long start_offset;

	unsigned int bs[2];
	unsigned int min_bs[2];
	unsigned int max_bs[2];

	unsigned int nr_files;
	unsigned int open_files;

	unsigned int odirect;
	unsigned int invalidate_cache;
	unsigned int create_serialize;
	unsigned int create_fsync;
	unsigned int end_fsync;
	unsigned int sync_io;
	unsigned int verify;
	unsigned int verifysort;
	unsigned int use_thread;
	unsigned int unlink;
	unsigned int do_disk_util;
	unsigned int override_sync;
	unsigned int rand_repeatable;
	unsigned int write_lat_log;
	unsigned int write_bw_log;
	unsigned int norandommap;
	unsigned int bs_unaligned;
	unsigned int fsync_on_close;

	unsigned int hugepage_size;
	unsigned int rw_min_bs;
	unsigned int thinktime;
	unsigned int thinktime_spin;
	unsigned int thinktime_blocks;
	unsigned int fsync_blocks;
	unsigned int start_delay;
	unsigned long timeout;
	unsigned int overwrite;
	unsigned int bw_avg_time;
	unsigned int loops;
	unsigned long long zone_size;
	unsigned long long zone_skip;
	enum fio_memtype mem_type;

	unsigned int stonewall;
	unsigned int new_group;
	unsigned int numjobs;
	os_cpu_mask_t cpumask;
	unsigned int iolog;
	unsigned int rwmixcycle;
	unsigned int rwmix[2];
	unsigned int nice;
	unsigned int file_service_type;
	unsigned int group_reporting;
	unsigned int fadvise_hint;
	unsigned int zero_buffers;
	unsigned int time_based;

	char *read_iolog_file;
	char *write_iolog_file;

	/*
	 * Pre-run and post-run shell
	 */
	char *exec_prerun;
	char *exec_postrun;

	unsigned int rate;
	unsigned int ratemin;
	unsigned int ratecycle;
	unsigned int rate_iops;
	unsigned int rate_iops_min;

	char *ioscheduler;

	/*
	 * CPU "io" cycle burner
	 */
	unsigned int cpuload;
	unsigned int cpucycle;
};

#define FIO_VERROR_SIZE	128

/*
 * This describes a single thread/process executing a fio job.
 */
struct thread_data {
	struct thread_options o;
	char verror[FIO_VERROR_SIZE];
	pthread_t thread;
	int thread_number;
	int groupid;
	struct thread_stat ts;
	struct fio_file *files;
	unsigned int files_index;
	unsigned int nr_open_files;
	unsigned int nr_done_files;
	unsigned int nr_normal_files;
	union {
		unsigned int next_file;
		os_random_state_t next_file_state;
	};
	int error;
	pid_t pid;
	char *orig_buffer;
	size_t orig_buffer_size;
	volatile int terminate;
	volatile int runstate;
	unsigned int ioprio;
	unsigned int last_was_sync;

	char *mmapfile;
	int mmapfd;

	void *iolog_buf;
	FILE *iolog_f;

	char *sysfs_root;

	os_random_state_t bsrange_state;
	os_random_state_t verify_state;

	int shm_id;

	/*
	 * IO engine hooks, contains everything needed to submit an io_u
	 * to any of the available IO engines.
	 */
	struct ioengine_ops *io_ops;

	/*
	 * Current IO depth and list of free and busy io_u's.
	 */
	unsigned int cur_depth;
	struct list_head io_u_freelist;
	struct list_head io_u_busylist;
	struct list_head io_u_requeues;
	unsigned int io_u_queued;

	/*
	 * Rate state
	 */
	unsigned long rate_usec_cycle;
	long rate_pending_usleep;
	unsigned long rate_bytes;
	unsigned long rate_blocks;
	struct timeval lastrate;

	unsigned long long total_io_size;

	unsigned long io_issues[2];
	unsigned long long io_blocks[2];
	unsigned long long io_bytes[2];
	unsigned long long this_io_bytes[2];
	unsigned long long zone_bytes;
	struct fio_sem *mutex;

	/*
	 * State for random io, a bitmap of blocks done vs not done
	 */
	os_random_state_t random_state;

	struct timeval start;	/* start of this loop */
	struct timeval epoch;	/* time job was started */
	struct timeval rw_end[2];
	struct timeval last_issue;
	unsigned int rw_end_set[2];

	/*
	 * read/write mixed workload state
	 */
	os_random_state_t rwmix_state;
	unsigned long long rwmix_bytes;
	struct timeval rwmix_switch;
	enum fio_ddir rwmix_ddir;
	unsigned int ddir_nr;

	/*
	 * IO history logs for verification. We use a tree for sorting,
	 * if we are overwriting. Otherwise just use a fifo.
	 */
	struct rb_root io_hist_tree;
	struct list_head io_hist_list;

	/*
	 * For IO replaying
	 */
	struct list_head io_log_list;

	/*
	 * timeout handling
	 */
	struct timeval timeout_end;
	struct itimerval timer;

	/*
	 * for fileservice, how often to switch to a new file
	 */
	unsigned int file_service_nr;
	unsigned int file_service_left;
	struct fio_file *file_service_file;

	/*
	 * For generating file sizes
	 */
	os_random_state_t file_size_state;
};

/*
 * roundrobin available files, or choose one at random.
 */
enum {
	FIO_FSERVICE_RANDOM	= 1,
	FIO_FSERVICE_RR		= 2,
};

/*
 * 30 second per-io_u timeout, with 5 second intervals to avoid resetting
 * the timer on each queue operation.
 */
#define IO_U_TIMEOUT_INC	5
#define IO_U_TIMEOUT		30

#define __td_verror(td, err, msg, func)					\
	do {								\
		if ((td)->error)					\
			break;						\
		int e = (err);						\
		(td)->error = e;					\
		snprintf(td->verror, sizeof(td->verror) - 1, "file:%s:%d, func=%s, error=%s", __FILE__, __LINE__, (func), (msg));	\
	} while (0)


#define td_verror(td, err, func)	\
	__td_verror((td), (err), strerror((err)), (func))
#define td_vmsg(td, err, msg, func)	\
	__td_verror((td), (err), (msg), (func))

extern int exitall_on_terminate;
extern int thread_number;
extern int nr_process, nr_thread;
extern int shm_id;
extern int groupid;
extern int terse_output;
extern FILE *f_out;
extern FILE *f_err;
extern int temp_stall_ts;
extern unsigned long long mlock_size;
extern unsigned long page_mask, page_size;

extern struct thread_data *threads;

#define td_read(td)		((td)->o.td_ddir & TD_DDIR_READ)
#define td_write(td)		((td)->o.td_ddir & TD_DDIR_WRITE)
#define td_rw(td)		(((td)->o.td_ddir & TD_DDIR_RW) == TD_DDIR_RW)
#define td_random(td)		((td)->o.td_ddir & TD_DDIR_RAND)

#define BLOCKS_PER_MAP		(8 * sizeof(long))
#define TO_MAP_BLOCK(td, f, b)	((b) - ((f)->file_offset / (td)->o.rw_min_bs))
#define RAND_MAP_IDX(td, f, b)	(TO_MAP_BLOCK(td, f, b) / BLOCKS_PER_MAP)
#define RAND_MAP_BIT(td, f, b)	(TO_MAP_BLOCK(td, f, b) & (BLOCKS_PER_MAP - 1))

#define MAX_JOBS	(1024)

static inline int should_fsync(struct thread_data *td)
{
	if (td->last_was_sync)
		return 0;
	if (td->o.odirect)
		return 0;
	if (td_write(td) || td_rw(td) || td->o.override_sync)
		return 1;

	return 0;
}

/*
 * Disk utils as read in /sys/block/<dev>/stat
 */
struct disk_util_stat {
	unsigned ios[2];
	unsigned merges[2];
	unsigned long long sectors[2];
	unsigned ticks[2];
	unsigned io_ticks;
	unsigned time_in_queue;
};

/*
 * Per-device disk util management
 */
struct disk_util {
	struct list_head list;

	char *name;
	char *sysfs_root;
	char path[256];
	int major, minor;

	struct disk_util_stat dus;
	struct disk_util_stat last_dus;

	unsigned long msec;
	struct timeval time;
};

#define DISK_UTIL_MSEC	(250)

/*
 * Log exports
 */
extern int __must_check read_iolog_get(struct thread_data *, struct io_u *);
extern void write_iolog_put(struct thread_data *, struct io_u *);
extern int __must_check init_iolog(struct thread_data *td);
extern void log_io_piece(struct thread_data *, struct io_u *);
extern void prune_io_piece_log(struct thread_data *);
extern void write_iolog_close(struct thread_data *);

/*
 * Logging
 */
extern void add_clat_sample(struct thread_data *, enum fio_ddir, unsigned long);
extern void add_slat_sample(struct thread_data *, enum fio_ddir, unsigned long);
extern void add_bw_sample(struct thread_data *, enum fio_ddir, struct timeval *);
extern void show_run_stats(void);
extern void init_disk_util(struct thread_data *);
extern void update_rusage_stat(struct thread_data *);
extern void update_io_ticks(void);
extern void disk_util_timer_arm(void);
extern void setup_log(struct io_log **);
extern void finish_log(struct thread_data *, struct io_log *, const char *);
extern void __finish_log(struct io_log *, const char *);
extern struct io_log *agg_io_log[2];
extern int write_bw_log;
extern void add_agg_sample(unsigned long, enum fio_ddir);

/*
 * Time functions
 */
extern unsigned long utime_since(struct timeval *, struct timeval *);
extern unsigned long utime_since_now(struct timeval *);
extern unsigned long mtime_since(struct timeval *, struct timeval *);
extern unsigned long mtime_since_now(struct timeval *);
extern unsigned long time_since_now(struct timeval *);
extern unsigned long mtime_since_genesis(void);
extern void __usec_sleep(unsigned int);
extern void usec_sleep(struct thread_data *, unsigned long);
extern void rate_throttle(struct thread_data *, unsigned long, unsigned int);
extern void fill_start_time(struct timeval *);
extern void fio_gettime(struct timeval *, void *);
extern void set_genesis_time(void);

/*
 * Init/option functions
 */
extern int __must_check parse_options(int, char **);
extern int fio_option_parse(struct thread_data *, const char *);
extern int fio_cmd_option_parse(struct thread_data *, const char *, char *);
extern void fio_fill_default_options(struct thread_data *);
extern int fio_show_option_help(const char *);
extern void fio_options_dup_and_init(struct option *);
extern void options_mem_dupe(struct thread_data *);
extern void options_mem_free(struct thread_data *);
#define FIO_GETOPT_JOB		0x89988998
#define FIO_NR_OPTIONS		128

/*
 * File setup/shutdown
 */
extern void close_files(struct thread_data *);
extern int __must_check setup_files(struct thread_data *);
extern int __must_check open_files(struct thread_data *);
extern int __must_check file_invalidate_cache(struct thread_data *, struct fio_file *);
extern int __must_check generic_open_file(struct thread_data *, struct fio_file *);
extern void generic_close_file(struct thread_data *, struct fio_file *);
extern void add_file(struct thread_data *, const char *);
extern void get_file(struct fio_file *);
extern void put_file(struct thread_data *, struct fio_file *);
extern int add_dir_files(struct thread_data *, const char *);
extern int init_random_map(struct thread_data *);
extern void dup_files(struct thread_data *, struct thread_data *);

/*
 * ETA/status stuff
 */
extern void print_thread_status(void);
extern void print_status_init(int);

/*
 * disk util stuff
 */
#ifdef FIO_HAVE_DISK_UTIL
extern void show_disk_util(void);
extern void disk_util_timer_arm(void);
extern void init_disk_util(struct thread_data *);
extern void update_io_ticks(void);
#else
#define show_disk_util()
#define disk_util_timer_arm()
#define init_disk_util(td)
#define update_io_ticks()
#endif

/*
 * Thread life cycle. Once a thread has a runstate beyond TD_INITIALIZED, it
 * will never back again. It may cycle between running/verififying/fsyncing.
 * Once the thread reaches TD_EXITED, it is just waiting for the core to
 * reap it.
 */
enum {
	TD_NOT_CREATED = 0,
	TD_CREATED,
	TD_INITIALIZED,
	TD_RUNNING,
	TD_VERIFYING,
	TD_FSYNCING,
	TD_EXITED,
	TD_REAPED,
};

/*
 * Verify helpers
 */
extern void populate_verify_io_u(struct thread_data *, struct io_u *);
extern int __must_check get_next_verify(struct thread_data *td, struct io_u *);
extern int __must_check verify_io_u(struct thread_data *, struct io_u *);

/*
 * Memory helpers
 */
extern int __must_check fio_pin_memory(void);
extern void fio_unpin_memory(void);
extern int __must_check allocate_io_mem(struct thread_data *);
extern void free_io_mem(struct thread_data *);

/*
 * io unit handling
 */
#define queue_full(td)	list_empty(&(td)->io_u_freelist)
extern struct io_u *__get_io_u(struct thread_data *);
extern struct io_u *get_io_u(struct thread_data *);
extern void put_io_u(struct thread_data *, struct io_u *);
extern void requeue_io_u(struct thread_data *, struct io_u **);
extern long __must_check io_u_sync_complete(struct thread_data *, struct io_u *);
extern long __must_check io_u_queued_complete(struct thread_data *, int);
extern void io_u_queued(struct thread_data *, struct io_u *);
extern void io_u_log_error(struct thread_data *, struct io_u *);
extern void io_u_init_timeout(void);
extern void io_u_set_timeout(struct thread_data *);
extern void io_u_mark_depth(struct thread_data *, struct io_u *);

/*
 * io engine entry points
 */
extern int __must_check td_io_init(struct thread_data *);
extern int __must_check td_io_prep(struct thread_data *, struct io_u *);
extern int __must_check td_io_queue(struct thread_data *, struct io_u *);
extern int __must_check td_io_sync(struct thread_data *, struct fio_file *);
extern int __must_check td_io_getevents(struct thread_data *, int, int, struct timespec *);
extern int __must_check td_io_commit(struct thread_data *);
extern int __must_check td_io_open_file(struct thread_data *, struct fio_file *);
extern void td_io_close_file(struct thread_data *, struct fio_file *);

/*
 * blktrace support
 */
extern int is_blktrace(const char *);
extern int load_blktrace(struct thread_data *, const char *);

/*
 * If logging output to a file, stderr should go to both stderr and f_err
 */
#define log_err(args...)	do {		\
	fprintf(f_err, ##args);			\
	if (f_err != stderr)			\
		fprintf(stderr, ##args);	\
	} while (0)

#define log_info(args...)	fprintf(f_out, ##args)

FILE *get_f_out(void);
FILE *get_f_err(void);

struct ioengine_ops {
	struct list_head list;
	char name[16];
	int version;
	int flags;
	int (*setup)(struct thread_data *);
	int (*init)(struct thread_data *);
	int (*prep)(struct thread_data *, struct io_u *);
	int (*queue)(struct thread_data *, struct io_u *);
	int (*commit)(struct thread_data *);
	int (*getevents)(struct thread_data *, int, int, struct timespec *);
	struct io_u *(*event)(struct thread_data *, int);
	int (*cancel)(struct thread_data *, struct io_u *);
	void (*cleanup)(struct thread_data *);
	int (*open_file)(struct thread_data *, struct fio_file *);
	void (*close_file)(struct thread_data *, struct fio_file *);
	void *data;
	void *dlhandle;
};

#define FIO_IOOPS_VERSION	7

extern struct ioengine_ops *load_ioengine(struct thread_data *, const char *);
extern void register_ioengine(struct ioengine_ops *);
extern void unregister_ioengine(struct ioengine_ops *);
extern void close_ioengine(struct thread_data *);

/*
 * Mark unused variables passed to ops functions as unused, to silence gcc
 */
#define fio_unused	__attribute((__unused__))
#define fio_init	__attribute__((constructor))
#define fio_exit	__attribute__((destructor))

#define for_each_td(td, i)	\
	for ((i) = 0, (td) = &threads[0]; (i) < (int) thread_number; (i)++, (td)++)
#define for_each_file(td, f, i)	\
	for ((i) = 0, (f) = &(td)->files[0]; (i) < (td)->o.nr_files; (i)++, (f)++)

#define fio_assert(td, cond)	do {	\
	if (!(cond)) {			\
		int *__foo = NULL;	\
		fprintf(stderr, "file:%s:%d, assert %s failed\n", __FILE__, __LINE__, #cond);	\
		(td)->runstate = TD_EXITED;	\
		(td)->error = EFAULT;		\
		*__foo = 0;			\
	}	\
} while (0)

static inline void clear_error(struct thread_data *td)
{
	td->error = 0;
	td->verror[0] = '\0';
}

#endif
