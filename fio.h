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

#include "list.h"
#include "md5.h"
#include "crc32.h"
#include "arch.h"
#include "os.h"

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
	unsigned int ddir;
};

struct io_log {
	unsigned long nr_samples;
	unsigned long max_samples;
	struct io_sample *log;
};

struct io_piece {
	struct list_head list;
	unsigned long long offset;
	unsigned int len;
	int ddir;
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

	char *buf;
	unsigned int buflen;
	unsigned long long offset;
	unsigned int index;

	unsigned int resid;
	unsigned int error;

	unsigned char seen;
	unsigned char ddir;

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

enum fio_ddir {
	DDIR_READ = 0,
	DDIR_WRITE,
};

/*
 * What type of allocation to use for io buffers
 */
enum fio_memtype {
	MEM_MALLOC = 0,	/* ordinary malloc */
	MEM_SHM,	/* use shared memory segments */
	MEM_MMAP,	/* use anonynomous mmap */
};

/*
 * The type of object we are working on
 */
enum fio_filetype {
	FIO_TYPE_FILE = 1,
	FIO_TYPE_BD,
	FIO_TYPE_CHAR,
};

enum fio_iotype {
	FIO_SYNCIO	= 1 << 0,
	FIO_MMAPIO	= 1 << 1 | FIO_SYNCIO,
	FIO_LIBAIO	= 1 << 2,
	FIO_POSIXAIO	= 1 << 3,
	FIO_SGIO	= 1 << 4,
	FIO_SPLICEIO	= 1 << 5 | FIO_SYNCIO,
};

/*
 * This describes a single thread/process executing a fio job.
 */
struct thread_data {
	char name[32];
	char *file_name;
	char *directory;
	char verror[80];
	pthread_t thread;
	int thread_number;
	int groupid;
	enum fio_filetype filetype;
	int error;
	int fd;
	void *mmap;
	pid_t pid;
	char *orig_buffer;
	size_t orig_buffer_size;
	volatile int terminate;
	volatile int runstate;
	enum fio_ddir ddir;
	unsigned int iomix;
	unsigned int ioprio;

	unsigned char sequential;
	unsigned char odirect;
	unsigned char create_file;
	unsigned char invalidate_cache;
	unsigned char create_serialize;
	unsigned char create_fsync;
	unsigned char end_fsync;
	unsigned char sync_io;
	unsigned char verify;
	unsigned char use_thread;
	unsigned char do_disk_util;
	unsigned char override_sync;

	unsigned int bs;
	unsigned int min_bs;
	unsigned int max_bs;
	unsigned int thinktime;
	unsigned int fsync_blocks;
	unsigned int start_delay;
	unsigned int timeout;
	enum fio_iotype io_engine;
	unsigned int overwrite;
	unsigned int bw_avg_time;
	unsigned int loops;
	unsigned long long file_size;
	unsigned long long real_file_size;
	unsigned long long file_offset;
	unsigned long long zone_size;
	unsigned long long zone_skip;
	enum fio_memtype mem_type;
	unsigned int stonewall;
	unsigned int numjobs;
	unsigned int iodepth;
	os_cpu_mask_t cpumask;
	unsigned int jobnum;
	unsigned int iolog;
	unsigned int read_iolog;
	unsigned int write_iolog;
	unsigned int rwmixcycle;
	unsigned int rwmixread;
	unsigned int nice;

	char *iolog_file;
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
	void *io_data;
	char io_engine_name[16];
	int (*io_prep)(struct thread_data *, struct io_u *);
	int (*io_queue)(struct thread_data *, struct io_u *);
	int (*io_getevents)(struct thread_data *, int, int, struct timespec *);
	struct io_u *(*io_event)(struct thread_data *, int);
	int (*io_cancel)(struct thread_data *, struct io_u *);
	void (*io_cleanup)(struct thread_data *);
	int (*io_sync)(struct thread_data *);

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
	unsigned long long total_io_size;

	unsigned long long io_blocks[2];
	unsigned long long io_bytes[2];
	unsigned long long zone_bytes;
	unsigned long long this_io_bytes[2];
	unsigned long long last_pos;
	volatile int mutex;

	/*
	 * State for random io, a bitmap of blocks done vs not done
	 */
	os_random_state_t random_state;
	unsigned long *file_map;
	unsigned int num_maps;

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

#define td_verror(td, err)						\
	do {								\
		int e = (err);						\
		(td)->error = e;					\
		snprintf(td->verror, sizeof(td->verror) - 1, "file:%s:%d, error=%s", __FILE__, __LINE__, strerror(e));	\
	} while (0)

extern struct io_u *__get_io_u(struct thread_data *);
extern void put_io_u(struct thread_data *, struct io_u *);

extern int rate_quit;
extern int write_lat_log;
extern int write_bw_log;
extern int exitall_on_terminate;
extern int thread_number;
extern int shm_id;
extern int groupid;
extern FILE *f_out;
extern FILE *f_err;

extern struct thread_data *threads;

#define td_read(td)		((td)->ddir == DDIR_READ)
#define td_write(td)		((td)->ddir == DDIR_WRITE)
#define td_rw(td)		((td)->iomix != 0)

#define BLOCKS_PER_MAP		(8 * sizeof(long))
#define TO_MAP_BLOCK(td, b)	((b) - ((td)->file_offset / (td)->min_bs))
#define RAND_MAP_IDX(td, b)	(TO_MAP_BLOCK(td, b) / BLOCKS_PER_MAP)
#define RAND_MAP_BIT(td, b)	(TO_MAP_BLOCK(td, b) & (BLOCKS_PER_MAP - 1))

#define MAX_JOBS	(1024)

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
};

#define DISK_UTIL_MSEC	(250)

#ifndef min
#define min(a, b)	((a) < (b) ? (a) : (b))
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
extern void add_clat_sample(struct thread_data *, int, unsigned long);
extern void add_slat_sample(struct thread_data *, int, unsigned long);
extern void add_bw_sample(struct thread_data *, int);
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
extern unsigned long mtime_since(struct timeval *, struct timeval *);
extern unsigned long mtime_since_now(struct timeval *);
extern unsigned long time_since_now(struct timeval *);
extern void usec_sleep(struct thread_data *, unsigned long);
extern void rate_throttle(struct thread_data *, unsigned long, unsigned int);

/*
 * Init functions
 */
extern int parse_options(int, char **);
extern int init_random_state(struct thread_data *);

/*
 * This is a pretty crappy semaphore implementation, but with the use that fio
 * has (just signalling start/go conditions), it doesn't have to be better.
 * Naturally this would not work for any type of contended semaphore or
 * for real locking.
 */
static inline void fio_sem_init(volatile int volatile *sem, int val)
{
	*sem = val;
}

static inline void fio_sem_down(volatile int volatile *sem)
{
	while (*sem == 0)
		usleep(10000);

	(*sem)--;
}

static inline void fio_sem_up(volatile int volatile *sem)
{
	(*sem)++;
}

#endif
