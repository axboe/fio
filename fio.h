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

#include "list.h"
#include "md5.h"
#include "crc32.h"
#include "arch.h"
#include "os.h"

enum fio_ddir {
	DDIR_READ = 0,
	DDIR_WRITE,
	DDIR_SYNC,
};

struct io_stat {
	unsigned long val;
	unsigned long val_sq;
	unsigned long max_val;
	unsigned long min_val;
	unsigned long samples;
};

struct io_sample {
	unsigned long time;
	unsigned long val;
	enum fio_ddir ddir;
};

struct io_log {
	unsigned long nr_samples;
	unsigned long max_samples;
	struct io_sample *log;
};

struct io_piece {
	struct list_head list;
	struct fio_file *file;
	unsigned long long offset;
	unsigned int len;
	enum fio_ddir ddir;
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
	};
	struct timeval start_time;
	struct timeval issue_time;

	void *buf;
	unsigned int buflen;
	unsigned long long offset;

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

	struct fio_file *file;

	struct list_head list;
};

#define FIO_HDR_MAGIC	0xf00baaef

enum {
	VERIFY_NONE = 0,
	VERIFY_MD5,
	VERIFY_CRC32,
};

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
	FIO_TYPE_FILE = 1,
	FIO_TYPE_BD,
	FIO_TYPE_CHAR,
};

enum fio_ioengine_flags {
	FIO_SYNCIO	= 1 << 0,
	FIO_CPUIO	= 1 << 1,
	FIO_MMAPIO	= 1 << 2,
	FIO_RAWIO	= 1 << 3,
};

struct fio_file {
	/*
	 * A file may not be a file descriptor, let the io engine decide
	 */
	union {
		unsigned long file_data;
		int fd;
	};
	char *file_name;
	void *mmap;
	unsigned long long file_size;
	unsigned long long real_file_size;
	unsigned long long file_offset;
	unsigned long long last_pos;
	unsigned long long last_completed_pos;

	unsigned long *file_map;
	unsigned int num_maps;

	unsigned int unlink;
};

/*
 * This describes a single thread/process executing a fio job.
 */
struct thread_data {
	char *name;
	char *directory;
	char *filename;
	char verror[80];
	pthread_t thread;
	int thread_number;
	int groupid;
	enum fio_filetype filetype;
	struct fio_file *files;
	unsigned int nr_files;
	unsigned int nr_uniq_files;
	unsigned int next_file;
	int error;
	pid_t pid;
	char *orig_buffer;
	size_t orig_buffer_size;
	volatile int terminate;
	volatile int runstate;
	enum fio_ddir ddir;
	unsigned int iomix;
	unsigned int ioprio;
	unsigned int last_was_sync;

	unsigned int sequential;
	unsigned int odirect;
	unsigned int invalidate_cache;
	unsigned int create_serialize;
	unsigned int create_fsync;
	unsigned int end_fsync;
	unsigned int sync_io;
	unsigned int verify;
	unsigned int use_thread;
	unsigned int unlink;
	unsigned int do_disk_util;
	unsigned int override_sync;
	unsigned int rand_repeatable;
	unsigned int write_lat_log;
	unsigned int write_bw_log;
	unsigned int norandommap;
	unsigned int bs_unaligned;

	unsigned int bs[2];
	unsigned int min_bs[2];
	unsigned int max_bs[2];
	unsigned int hugepage_size;
	unsigned int rw_min_bs;
	unsigned int thinktime;
	unsigned int fsync_blocks;
	unsigned int start_delay;
	unsigned long timeout;
	unsigned int overwrite;
	unsigned int bw_avg_time;
	unsigned int loops;
	unsigned long long zone_size;
	unsigned long long zone_skip;
	enum fio_memtype mem_type;
	char *mmapfile;
	int mmapfd;
	unsigned int stonewall;
	unsigned int numjobs;
	unsigned int iodepth;
	os_cpu_mask_t cpumask;
	unsigned int iolog;
	unsigned int read_iolog;
	unsigned int rwmixcycle;
	unsigned int rwmixread;
	unsigned int rwmixwrite;
	unsigned int nice;

	char *read_iolog_file;
	char *write_iolog_file;
	void *iolog_buf;
	FILE *iolog_f;

	char *sysfs_root;
	char *ioscheduler;

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

	/*
	 * Rate state
	 */
	unsigned int rate;
	unsigned int ratemin;
	unsigned int ratecycle;
	unsigned long rate_usec_cycle;
	long rate_pending_usleep;
	unsigned long rate_bytes;
	struct timeval lastrate;

	unsigned long runtime[2];		/* msec */
	unsigned long long io_size;
	unsigned long long total_file_size;
	unsigned long long start_offset;
	unsigned long long total_io_size;

	unsigned long long io_blocks[2];
	unsigned long long io_bytes[2];
	unsigned long long zone_bytes;
	unsigned long long this_io_bytes[2];
	volatile int mutex;

	/*
	 * State for random io, a bitmap of blocks done vs not done
	 */
	os_random_state_t random_state;

	/*
	 * CPU "io" cycle burner
	 */
	unsigned int cpuload;
	unsigned int cpucycle;

	/*
	 * bandwidth and latency stats
	 */
	struct io_stat clat_stat[2];		/* completion latency */
	struct io_stat slat_stat[2];		/* submission latency */
	struct io_stat bw_stat[2];		/* bandwidth stats */

	unsigned long long stat_io_bytes[2];
	struct timeval stat_sample_time[2];

	struct io_log *slat_log;
	struct io_log *clat_log;
	struct io_log *bw_log;

	struct timeval start;	/* start of this loop */
	struct timeval epoch;	/* time job was started */
	struct timeval end_time;/* time job ended */

	/*
	 * fio system usage accounting
	 */
	struct rusage ru_start;
	struct rusage ru_end;
	unsigned long usr_time;
	unsigned long sys_time;
	unsigned long ctx;

	/*
	 * read/write mixed workload state
	 */
	os_random_state_t rwmix_state;
	struct timeval rwmix_switch;
	enum fio_ddir rwmix_ddir;

	/*
	 * Pre-run and post-run shell
	 */
	char *exec_prerun;
	char *exec_postrun;

	/*
	 * IO historic logs
	 */
	struct list_head io_hist_list;
	struct list_head io_log_list;
};

#define __td_verror(td, err, msg)					\
	do {								\
		int e = (err);						\
		(td)->error = e;					\
		snprintf(td->verror, sizeof(td->verror) - 1, "file:%s:%d, error=%s", __FILE__, __LINE__, (msg));	\
	} while (0)


#define td_verror(td, err)	__td_verror((td), (err), strerror((err)))
#define td_vmsg(td, err, msg)	__td_verror((td), (err), (msg))

extern int exitall_on_terminate;
extern int thread_number;
extern int shm_id;
extern int groupid;
extern int terse_output;
extern FILE *f_out;
extern FILE *f_err;
extern int temp_stall_ts;
extern unsigned long long mlock_size;

extern struct thread_data *threads;

#define td_read(td)		((td)->ddir == DDIR_READ)
#define td_write(td)		((td)->ddir == DDIR_WRITE)
#define td_rw(td)		((td)->iomix != 0)

#define BLOCKS_PER_MAP		(8 * sizeof(long))
#define TO_MAP_BLOCK(td, f, b)	((b) - ((f)->file_offset / (td)->rw_min_bs))
#define RAND_MAP_IDX(td, f, b)	(TO_MAP_BLOCK(td, f, b) / BLOCKS_PER_MAP)
#define RAND_MAP_BIT(td, f, b)	(TO_MAP_BLOCK(td, f, b) & (BLOCKS_PER_MAP - 1))

#define MAX_JOBS	(1024)

static inline int should_fsync(struct thread_data *td)
{
	if (td->last_was_sync)
		return 0;
	if (td->odirect)
		return 0;
	if (td_write(td) || td_rw(td) || td->override_sync)
		return 1;

	return 0;
}

struct disk_util_stat {
	unsigned ios[2];
	unsigned merges[2];
	unsigned long long sectors[2];
	unsigned ticks[2];
	unsigned io_ticks;
	unsigned time_in_queue;
};

struct disk_util {
	struct list_head list;

	char *name;
	char path[256];
	dev_t dev;

	struct disk_util_stat dus;
	struct disk_util_stat last_dus;

	unsigned long msec;
	struct timeval time;
};

struct io_completion_data {
	int nr;				/* input */

	int error;			/* output */
	unsigned long bytes_done[2];	/* output */
	struct timeval time;		/* output */
};

#define DISK_UTIL_MSEC	(250)

#ifndef min
#define min(a, b)	((a) < (b) ? (a) : (b))
#endif
#ifndef max
#define max(a, b)	((a) > (b) ? (a) : (b))
#endif

/*
 * Log exports
 */
extern int read_iolog_get(struct thread_data *, struct io_u *);
extern void write_iolog_put(struct thread_data *, struct io_u *);
extern int init_iolog(struct thread_data *td);
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
extern int setup_rate(struct thread_data *);

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
extern void rate_throttle(struct thread_data *, unsigned long, unsigned int, int);
extern void fill_start_time(struct timeval *);
extern void fio_gettime(struct timeval *, void *);

/*
 * Init functions
 */
extern int parse_options(int, char **);
extern int init_random_state(struct thread_data *);

/*
 * File setup/shutdown
 */
extern void close_files(struct thread_data *);
extern int setup_files(struct thread_data *);
extern int open_files(struct thread_data *);
extern int file_invalidate_cache(struct thread_data *, struct fio_file *);

/*
 * ETA/status stuff
 */
extern void print_thread_status(void);
extern void print_status_init(int);

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
extern int get_next_verify(struct thread_data *td, struct io_u *);
extern int do_io_u_verify(struct thread_data *, struct io_u **);

/*
 * Memory helpers
 */
extern int fio_pin_memory(void);
extern void fio_unpin_memory(void);
extern int allocate_io_mem(struct thread_data *);
extern void free_io_mem(struct thread_data *);

/*
 * io unit handling
 */
#define queue_full(td)	list_empty(&(td)->io_u_freelist)
extern struct io_u *__get_io_u(struct thread_data *);
extern struct io_u *get_io_u(struct thread_data *, struct fio_file *);
extern void put_io_u(struct thread_data *, struct io_u *);
extern void ios_completed(struct thread_data *, struct io_completion_data *);
extern void io_completed(struct thread_data *, struct io_u *, struct io_completion_data *);

/*
 * io engine entry points
 */
extern int td_io_init(struct thread_data *);
extern int td_io_prep(struct thread_data *, struct io_u *);
extern int td_io_queue(struct thread_data *, struct io_u *);
extern int td_io_sync(struct thread_data *, struct fio_file *);
extern int td_io_getevents(struct thread_data *, int, int, struct timespec *);

/*
 * This is a pretty crappy semaphore implementation, but with the use that fio
 * has (just signalling start/go conditions), it doesn't have to be better.
 * Naturally this would not work for any type of contended semaphore or
 * for real locking.
 */
static inline void fio_sem_init(volatile int *sem, int val)
{
	*sem = val;
}

static inline void fio_sem_down(volatile int *sem)
{
	while (*sem == 0)
		usleep(10000);

	(*sem)--;
}

static inline void fio_sem_up(volatile int *sem)
{
	(*sem)++;
}

/*
 * If logging output to a file, stderr should go to both stderr and f_err
 */
#define log_err(args...)	do {		\
	fprintf(f_err, ##args);			\
	if (f_err != stderr)			\
		fprintf(stderr, ##args);	\
	} while (0)

struct ioengine_ops {
	struct list_head list;
	char name[16];
	int version;
	int flags;
	int (*setup)(struct thread_data *);
	int (*init)(struct thread_data *);
	int (*prep)(struct thread_data *, struct io_u *);
	int (*queue)(struct thread_data *, struct io_u *);
	int (*getevents)(struct thread_data *, int, int, struct timespec *);
	struct io_u *(*event)(struct thread_data *, int);
	int (*cancel)(struct thread_data *, struct io_u *);
	void (*cleanup)(struct thread_data *);
	void *data;
	void *dlhandle;
};

#define FIO_IOOPS_VERSION	3

extern struct ioengine_ops *load_ioengine(struct thread_data *, const char *);
extern int register_ioengine(struct ioengine_ops *);
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
	for ((i) = 0, (f) = &(td)->files[0]; (i) < (int) (td)->nr_files; (i)++, (f)++)

#endif
