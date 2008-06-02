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
#include <inttypes.h>
#include <assert.h>

#include "compiler/compiler.h"
#include "flist.h"
#include "fifo.h"
#include "rbtree.h"
#include "arch/arch.h"
#include "os/os.h"
#include "mutex.h"
#include "log.h"
#include "debug.h"

#ifdef FIO_HAVE_GUASI
#include <guasi.h>
#endif

#ifdef FIO_HAVE_SOLARISAIO
#include <sys/asynch.h>
#endif

enum fio_ddir {
	DDIR_READ = 0,
	DDIR_WRITE,
	DDIR_SYNC,
	DDIR_INVAL = -1,
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

enum file_lock_mode {
	FILE_LOCK_NONE,
	FILE_LOCK_EXCLUSIVE,
	FILE_LOCK_READWRITE,
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
		struct flist_head list;
	};
	union {
		int fileno;
		struct fio_file *file;
	};
	unsigned long long offset;
	unsigned long len;
	enum fio_ddir ddir;
	union {
		unsigned long delay;
		unsigned int file_action;
	};
};

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
#ifdef FIO_HAVE_GUASI
		guasi_req_t greq;
#endif
#ifdef FIO_HAVE_SOLARISAIO
		aio_result_t resultp;
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

#define FIO_HDR_MAGIC	0xf00baaef

enum {
	VERIFY_NONE = 0,		/* no verification */
	VERIFY_MD5,			/* md5 sum data blocks */
	VERIFY_CRC64,			/* crc64 sum data blocks */
	VERIFY_CRC32,			/* crc32 sum data blocks */
	VERIFY_CRC16,			/* crc16 sum data blocks */
	VERIFY_CRC7,			/* crc7 sum data blocks */
	VERIFY_SHA256,			/* sha256 sum data blocks */
	VERIFY_SHA512,			/* sha512 sum data blocks */
	VERIFY_META,			/* block_num, timestamp etc. */
	VERIFY_NULL,			/* pretend to verify */
};

/*
 * A header structure associated with each checksummed data block. It is
 * followed by a checksum specific header that contains the verification
 * data.
 */
struct verify_header {
	unsigned int fio_magic;
	unsigned int len;
	unsigned int verify_type;
};

struct vhdr_md5 {
	uint32_t md5_digest[16];
};
struct vhdr_sha512 {
	uint8_t sha512[128];
};
struct vhdr_sha256 {
	uint8_t sha256[128];
};
struct vhdr_crc64 {
	uint64_t crc64;
};
struct vhdr_crc32 {
	uint32_t crc32;
};
struct vhdr_crc16 {
	uint16_t crc16;
};
struct vhdr_crc7 {
	uint8_t crc7;
};
struct vhdr_meta {
	uint64_t offset;
	unsigned char thread;
	unsigned short numberio;
	unsigned long time_sec;
	unsigned long time_usec;
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
	FIO_UNIDIR	= 1 << 5,	/* engine is uni-directional */
	FIO_NOIO	= 1 << 6,	/* thread does only pseudo IO */
	FIO_SIGQUIT	= 1 << 7,	/* needs SIGQUIT to exit */
};

enum fio_file_flags {
	FIO_FILE_OPEN		= 1 << 0,	/* file is open */
	FIO_FILE_CLOSING	= 1 << 1,	/* file being closed */
	FIO_FILE_EXTEND		= 1 << 2,	/* needs extend */
	FIO_FILE_DONE		= 1 << 3,	/* io completed to this file */
	FIO_SIZE_KNOWN		= 1 << 4,	/* size has been set */
	FIO_FILE_HASHED		= 1 << 5,	/* file is on hash */
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
	void *mmap;
	unsigned int major, minor;

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
};

/*
 * How many depth levels to log
 */
#define FIO_IO_U_MAP_NR	8
#define FIO_IO_U_LAT_U_NR 10
#define FIO_IO_U_LAT_M_NR 12

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
	unsigned long minf, majf;

	/*
	 * IO depth and latency stats
	 */
	unsigned int io_u_map[FIO_IO_U_MAP_NR];
	unsigned int io_u_submit[FIO_IO_U_MAP_NR];
	unsigned int io_u_complete[FIO_IO_U_MAP_NR];
	unsigned int io_u_lat_u[FIO_IO_U_LAT_U_NR];
	unsigned int io_u_lat_m[FIO_IO_U_LAT_M_NR];
	unsigned long total_io_u[2];
	unsigned long short_io_u[2];
	unsigned long total_submit;
	unsigned long total_complete;

	unsigned long long io_bytes[2];
	unsigned long runtime[2];
	unsigned long total_run_time;
};

struct bssplit {
	unsigned int bs;
	unsigned char perc;
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
	unsigned int fill_device;
	unsigned long long file_size_low;
	unsigned long long file_size_high;
	unsigned long long start_offset;

	unsigned int bs[2];
	unsigned int min_bs[2];
	unsigned int max_bs[2];
	struct bssplit *bssplit;
	unsigned int bssplit_nr;

	unsigned int nr_files;
	unsigned int open_files;
	enum file_lock_mode file_lock_mode;
	unsigned int lockfile_batch;

	unsigned int odirect;
	unsigned int invalidate_cache;
	unsigned int create_serialize;
	unsigned int create_fsync;
	unsigned int end_fsync;
	unsigned int sync_io;
	unsigned int verify;
	unsigned int do_verify;
	unsigned int verifysort;
	unsigned int verify_interval;
	unsigned int verify_offset;
	unsigned int verify_pattern;
	unsigned int verify_pattern_bytes;
	unsigned int verify_fatal;
	unsigned int use_thread;
	unsigned int unlink;
	unsigned int do_disk_util;
	unsigned int override_sync;
	unsigned int rand_repeatable;
	unsigned int write_lat_log;
	unsigned int write_bw_log;
	unsigned int norandommap;
	unsigned int softrandommap;
	unsigned int bs_unaligned;
	unsigned int fsync_on_close;

	unsigned int hugepage_size;
	unsigned int rw_min_bs;
	unsigned int thinktime;
	unsigned int thinktime_spin;
	unsigned int thinktime_blocks;
	unsigned int fsync_blocks;
	unsigned int start_delay;
	unsigned long long timeout;
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
	unsigned int cpumask_set;
	unsigned int iolog;
	unsigned int rwmixcycle;
	unsigned int rwmix[2];
	unsigned int nice;
	unsigned int file_service_type;
	unsigned int group_reporting;
	unsigned int fadvise_hint;
	unsigned int zero_buffers;
	unsigned int refill_buffers;
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
	struct fio_file **files;
	unsigned int files_index;
	unsigned int nr_open_files;
	unsigned int nr_done_files;
	unsigned int nr_normal_files;
	union {
		unsigned int next_file;
		os_random_state_t next_file_state;
	};
	int error;
	int done;
	pid_t pid;
	char *orig_buffer;
	size_t orig_buffer_size;
	volatile int terminate;
	volatile int runstate;
	unsigned int ioprio;
	unsigned int ioprio_set;
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
	unsigned int io_u_queued;
	struct flist_head io_u_freelist;
	struct flist_head io_u_busylist;
	struct flist_head io_u_requeues;

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
	unsigned long long io_skip_bytes;
	unsigned long long this_io_bytes[2];
	unsigned long long zone_bytes;
	struct fio_mutex *mutex;

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
	unsigned long rwmix_issues;
	enum fio_ddir rwmix_ddir;
	unsigned int ddir_nr;

	/*
	 * IO history logs for verification. We use a tree for sorting,
	 * if we are overwriting. Otherwise just use a fifo.
	 */
	struct rb_root io_hist_tree;
	struct flist_head io_hist_list;

	/*
	 * For IO replaying
	 */
	struct flist_head io_log_list;

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
 * when should interactive ETA output be generated
 */
enum {
	FIO_ETA_AUTO,
	FIO_ETA_ALWAYS,
	FIO_ETA_NEVER,
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
extern int temp_stall_ts;
extern unsigned long long mlock_size;
extern unsigned long page_mask, page_size;
extern int read_only;
extern int eta_print;
extern unsigned long done_secs;
extern char *job_section;

extern struct thread_data *threads;

#define td_read(td)		((td)->o.td_ddir & TD_DDIR_READ)
#define td_write(td)		((td)->o.td_ddir & TD_DDIR_WRITE)
#define td_rw(td)		(((td)->o.td_ddir & TD_DDIR_RW) == TD_DDIR_RW)
#define td_random(td)		((td)->o.td_ddir & TD_DDIR_RAND)
#define file_randommap(td, f)	(!(td)->o.norandommap && (f)->file_map)

static inline void fio_ro_check(struct thread_data *td, struct io_u *io_u)
{
	assert(!(io_u->ddir == DDIR_WRITE && !td_write(td)));
}

#define BLOCKS_PER_MAP		(8 * sizeof(int))
#define TO_MAP_BLOCK(f, b)	(b)
#define RAND_MAP_IDX(f, b)	(TO_MAP_BLOCK(f, b) / BLOCKS_PER_MAP)
#define RAND_MAP_BIT(f, b)	(TO_MAP_BLOCK(f, b) & (BLOCKS_PER_MAP - 1))

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
	struct flist_head list;

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
enum file_log_act {
	FIO_LOG_ADD_FILE,
	FIO_LOG_OPEN_FILE,
	FIO_LOG_CLOSE_FILE,
	FIO_LOG_UNLINK_FILE,
};

extern int __must_check read_iolog_get(struct thread_data *, struct io_u *);
extern void log_io_u(struct thread_data *, struct io_u *);
extern void log_file(struct thread_data *, struct fio_file *, enum file_log_act);
extern int __must_check init_iolog(struct thread_data *td);
extern void log_io_piece(struct thread_data *, struct io_u *);
extern void queue_io_piece(struct thread_data *, struct io_piece *);
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
extern void setup_log(struct io_log **);
extern void finish_log(struct thread_data *, struct io_log *, const char *);
extern void __finish_log(struct io_log *, const char *);
extern struct io_log *agg_io_log[2];
extern int write_bw_log;
extern void add_agg_sample(unsigned long, enum fio_ddir);

/*
 * Time functions
 */
extern unsigned long long utime_since(struct timeval *, struct timeval *);
extern unsigned long long utime_since_now(struct timeval *);
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
extern void close_and_free_files(struct thread_data *);
extern int __must_check setup_files(struct thread_data *);
extern int __must_check open_files(struct thread_data *);
extern int __must_check file_invalidate_cache(struct thread_data *, struct fio_file *);
extern int __must_check generic_open_file(struct thread_data *, struct fio_file *);
extern int __must_check generic_close_file(struct thread_data *, struct fio_file *);
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
extern void init_disk_util(struct thread_data *);
extern void update_io_ticks(void);
#else
#define show_disk_util()
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
#define queue_full(td)	flist_empty(&(td)->io_u_freelist)
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
extern void io_u_mark_depth(struct thread_data *, unsigned int);
extern void io_u_fill_buffer(struct thread_data *td, struct io_u *, unsigned int);
void io_u_mark_complete(struct thread_data *, unsigned int);
void io_u_mark_submit(struct thread_data *, unsigned int);

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

/*
 * blktrace support
 */
#ifdef FIO_HAVE_BLKTRACE
extern int is_blktrace(const char *);
extern int load_blktrace(struct thread_data *, const char *);
#endif

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
	void *data;
	void *dlhandle;
};

#define FIO_IOOPS_VERSION	9

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
	if ((td)->files_index)						\
		for ((i) = 0, (f) = (td)->files[0];			\
	    	 (i) < (td)->o.nr_files && ((f) = (td)->files[i]) != NULL; \
		 (i)++)

#define fio_assert(td, cond)	do {	\
	if (!(cond)) {			\
		int *__foo = NULL;	\
		fprintf(stderr, "file:%s:%d, assert %s failed\n", __FILE__, __LINE__, #cond);	\
		(td)->runstate = TD_EXITED;	\
		(td)->error = EFAULT;		\
		*__foo = 0;			\
	}	\
} while (0)

static inline void fio_file_reset(struct fio_file *f)
{
	f->last_free_lookup = 0;
	f->last_pos = f->file_offset;
}

static inline void clear_error(struct thread_data *td)
{
	td->error = 0;
	td->verror[0] = '\0';
}

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

#endif
