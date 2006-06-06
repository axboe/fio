#ifndef FIO_H
#define FIO_H

#include <sched.h>
#include <limits.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <semaphore.h>

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
	unsigned long long io_mb[2];
	unsigned long long agg[2];
};

struct thread_data {
	char file_name[256];
	char *directory;
	char verror[80];
	pthread_t thread;
	int thread_number;
	int groupid;
	int filetype;
	int error;
	int fd;
	void *mmap;
	pid_t pid;
	char *orig_buffer;
	size_t orig_buffer_size;
	volatile int terminate;
	volatile int runstate;
	volatile int old_runstate;
	unsigned int ddir;
	unsigned int iomix;
	unsigned int ioprio;
	unsigned int sequential;
	unsigned int bs;
	unsigned int min_bs;
	unsigned int max_bs;
	unsigned int odirect;
	unsigned int thinktime;
	unsigned int fsync_blocks;
	unsigned int start_delay;
	unsigned int timeout;
	unsigned int io_engine;
	unsigned int create_file;
	unsigned int overwrite;
	unsigned int invalidate_cache;
	unsigned int bw_avg_time;
	unsigned int create_serialize;
	unsigned int create_fsync;
	unsigned int end_fsync;
	unsigned int loops;
	unsigned long long file_size;
	unsigned long long real_file_size;
	unsigned long long file_offset;
	unsigned long long zone_size;
	unsigned long long zone_skip;
	unsigned int sync_io;
	unsigned int mem_type;
	unsigned int verify;
	unsigned int stonewall;
	unsigned int numjobs;
	unsigned int use_thread;
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

	struct drand48_data bsrange_state;
	struct drand48_data verify_state;

	int shm_id;

	void *io_data;
	char io_engine_name[16];
	int (*io_prep)(struct thread_data *, struct io_u *);
	int (*io_queue)(struct thread_data *, struct io_u *);
	int (*io_getevents)(struct thread_data *, int, int, struct timespec *);
	struct io_u *(*io_event)(struct thread_data *, int);
	int (*io_cancel)(struct thread_data *, struct io_u *);
	void (*io_cleanup)(struct thread_data *);
	int (*io_sync)(struct thread_data *);

	unsigned int cur_depth;
	struct list_head io_u_freelist;
	struct list_head io_u_busylist;

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
	sem_t mutex;

	struct drand48_data random_state;
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

	struct rusage ru_start;
	struct rusage ru_end;
	unsigned long usr_time;
	unsigned long sys_time;
	unsigned long ctx;

	unsigned int do_disk_util;
	unsigned int override_sync;

	struct drand48_data rwmix_state;
	struct timeval rwmix_switch;
	int rwmix_ddir;

	/*
	 * Pre-run and post-run shell
	 */
	char *exec_prerun;
	char *exec_postrun;

	struct list_head io_hist_list;
	struct list_head io_log_list;
};

#define td_verror(td, err)						\
	do {								\
		int e = (err);						\
		(td)->error = e;					\
		snprintf(td->verror, sizeof(td->verror) - 1, "file:%s:%d, error=%s", __FILE__, __LINE__, strerror(e));	\
	} while (0)

extern int parse_jobs_ini(char *);
extern int parse_options(int, char **);
extern void finish_log(struct thread_data *, struct io_log *, const char *);
extern int init_random_state(struct thread_data *);
extern struct io_u *__get_io_u(struct thread_data *);
extern void put_io_u(struct thread_data *, struct io_u *);

extern int rate_quit;
extern int write_lat_log;
extern int write_bw_log;
extern int exitall_on_terminate;
extern int thread_number;
extern int shm_id;
extern int groupid;

extern struct thread_data *threads;

enum {
	DDIR_READ = 0,
	DDIR_WRITE,
};

/*
 * What type of allocation to use for io buffers
 */
enum {
	MEM_MALLOC,	/* ordinary malloc */
	MEM_SHM,	/* use shared memory segments */
	MEM_MMAP,	/* use anonynomous mmap */
};

/*
 * The type of object we are working on
 */
enum {
	FIO_TYPE_FILE = 1,
	FIO_TYPE_BD,
	FIO_TYPE_CHAR,
};

enum {
	FIO_SYNCIO	= 1 << 0,
	FIO_MMAPIO	= 1 << 1 | FIO_SYNCIO,
	FIO_LIBAIO	= 1 << 2,
	FIO_POSIXAIO	= 1 << 3,
	FIO_SGIO	= 1 << 4,
	FIO_SPLICEIO	= 1 << 5 | FIO_SYNCIO,
};

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

#endif
