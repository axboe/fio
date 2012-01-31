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
#include <inttypes.h>
#include <assert.h>

struct thread_data;

#include "compiler/compiler.h"
#include "flist.h"
#include "fifo.h"
#include "rbtree.h"
#include "arch/arch.h"
#include "os/os.h"
#include "mutex.h"
#include "log.h"
#include "debug.h"
#include "file.h"
#include "io_ddir.h"
#include "ioengine.h"
#include "iolog.h"
#include "helpers.h"
#include "options.h"
#include "profile.h"
#include "time.h"
#include "lib/getopt.h"
#include "lib/rand.h"
#include "server.h"
#include "stat.h"

#ifdef FIO_HAVE_GUASI
#include <guasi.h>
#endif

#ifdef FIO_HAVE_SOLARISAIO
#include <sys/asynch.h>
#endif

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
 * offset generator types
 */
enum {
	RW_SEQ_SEQ	= 0,
	RW_SEQ_IDENT,
};

/*
 * What type of errors to continue on when continue_on_error is used
 */
enum error_type {
        ERROR_TYPE_NONE = 0,
        ERROR_TYPE_READ = 1 << 0,
        ERROR_TYPE_WRITE = 1 << 1,
        ERROR_TYPE_VERIFY = 1 << 2,
        ERROR_TYPE_ANY = 0xffff,
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
	unsigned int rw_seq;
	unsigned int kb_base;
	unsigned int ddir_seq_nr;
	long ddir_seq_add;
	unsigned int iodepth;
	unsigned int iodepth_low;
	unsigned int iodepth_batch;
	unsigned int iodepth_batch_complete;

	unsigned long long size;
	unsigned int size_percent;
	unsigned int fill_device;
	unsigned long long file_size_low;
	unsigned long long file_size_high;
	unsigned long long start_offset;

	unsigned int bs[2];
	unsigned int ba[2];
	unsigned int min_bs[2];
	unsigned int max_bs[2];
	struct bssplit *bssplit[2];
	unsigned int bssplit_nr[2];

	unsigned int nr_files;
	unsigned int open_files;
	enum file_lock_mode file_lock_mode;
	unsigned int lockfile_batch;

	unsigned int odirect;
	unsigned int invalidate_cache;
	unsigned int create_serialize;
	unsigned int create_fsync;
	unsigned int create_on_open;
	unsigned int end_fsync;
	unsigned int pre_read;
	unsigned int sync_io;
	unsigned int verify;
	unsigned int do_verify;
	unsigned int verifysort;
	unsigned int verify_interval;
	unsigned int verify_offset;
	char verify_pattern[MAX_PATTERN_SIZE];
	unsigned int verify_pattern_bytes;
	unsigned int verify_fatal;
	unsigned int verify_dump;
	unsigned int verify_async;
	unsigned long long verify_backlog;
	unsigned int verify_batch;
	unsigned int use_thread;
	unsigned int unlink;
	unsigned int do_disk_util;
	unsigned int override_sync;
	unsigned int rand_repeatable;
	unsigned int use_os_rand;
	unsigned int write_lat_log;
	unsigned int write_bw_log;
	unsigned int write_iops_log;
	unsigned int log_avg_msec;
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
	unsigned int fdatasync_blocks;
	unsigned int barrier_blocks;
	unsigned long long start_delay;
	unsigned long long timeout;
	unsigned long long ramp_time;
	unsigned int overwrite;
	unsigned int bw_avg_time;
	unsigned int iops_avg_time;
	unsigned int loops;
	unsigned long long zone_range;
	unsigned long long zone_size;
	unsigned long long zone_skip;
	enum fio_memtype mem_type;
	unsigned int mem_align;

	unsigned int stonewall;
	unsigned int new_group;
	unsigned int numjobs;
	os_cpu_mask_t cpumask;
	unsigned int cpumask_set;
	os_cpu_mask_t verify_cpumask;
	unsigned int verify_cpumask_set;
	unsigned int iolog;
	unsigned int rwmixcycle;
	unsigned int rwmix[2];
	unsigned int nice;
	unsigned int file_service_type;
	unsigned int group_reporting;
	unsigned int fadvise_hint;
	enum fio_fallocate_mode fallocate_mode;
	unsigned int zero_buffers;
	unsigned int refill_buffers;
	unsigned int scramble_buffers;
	unsigned int time_based;
	unsigned int disable_lat;
	unsigned int disable_clat;
	unsigned int disable_slat;
	unsigned int disable_bw;
	unsigned int gtod_reduce;
	unsigned int gtod_cpu;
	unsigned int gtod_offload;
	enum fio_cs clocksource;
	unsigned int no_stall;
	unsigned int trim_percentage;
	unsigned int trim_batch;
	unsigned int trim_zero;
	unsigned long long trim_backlog;
	unsigned int clat_percentiles;
	unsigned int overwrite_plist;
	fio_fp64_t percentile_list[FIO_IO_U_LIST_MAX_LEN];

	char *read_iolog_file;
	char *write_iolog_file;
	char *bw_log_file;
	char *lat_log_file;
	char *iops_log_file;
	char *replay_redirect;

	/*
	 * Pre-run and post-run shell
	 */
	char *exec_prerun;
	char *exec_postrun;

	unsigned int rate[2];
	unsigned int ratemin[2];
	unsigned int ratecycle;
	unsigned int rate_iops[2];
	unsigned int rate_iops_min[2];

	char *ioscheduler;

	/*
	 * CPU "io" cycle burner
	 */
	unsigned int cpuload;
	unsigned int cpucycle;

	/*
	 * I/O Error handling
	 */
	enum error_type continue_on_error;

	/*
	 * Benchmark profile type
	 */
	char *profile;

	/*
	 * blkio cgroup support
	 */
	char *cgroup;
	unsigned int cgroup_weight;
	unsigned int cgroup_nodelete;

	unsigned int uid;
	unsigned int gid;

	unsigned int sync_file_range;
};

/*
 * This describes a single thread/process executing a fio job.
 */
struct thread_data {
	struct thread_options o;
	void *eo;
	char verror[FIO_VERROR_SIZE];
	pthread_t thread;
	int thread_number;
	int groupid;
	struct thread_stat ts;

	struct io_log *slat_log;
	struct io_log *clat_log;
	struct io_log *lat_log;
	struct io_log *bw_log;
	struct io_log *iops_log;

	uint64_t stat_io_bytes[2];
	struct timeval bw_sample_time;

	uint64_t stat_io_blocks[2];
	struct timeval iops_sample_time;

	struct rusage ru_start;
	struct rusage ru_end;

	struct fio_file **files;
	unsigned int files_size;
	unsigned int files_index;
	unsigned int nr_open_files;
	unsigned int nr_done_files;
	unsigned int nr_normal_files;
	union {
		unsigned int next_file;
		os_random_state_t next_file_state;
		struct frand_state __next_file_state;
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
	enum fio_ddir last_ddir;

	char *mmapfile;
	int mmapfd;

	void *iolog_buf;
	FILE *iolog_f;

	char *sysfs_root;

	unsigned long rand_seeds[8];

	union {
		os_random_state_t bsrange_state;
		struct frand_state __bsrange_state;
	};
	union {
		os_random_state_t verify_state;
		struct frand_state __verify_state;
	};
	union {
		os_random_state_t trim_state;
		struct frand_state __trim_state;
	};

	struct frand_state buf_state;

	unsigned int verify_batch;
	unsigned int trim_batch;

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
	pthread_mutex_t io_u_lock;
	pthread_cond_t free_cond;

	/*
	 * async verify offload
	 */
	struct flist_head verify_list;
	pthread_t *verify_threads;
	unsigned int nr_verify_threads;
	pthread_cond_t verify_cond;
	int verify_thread_exit;

	/*
	 * Rate state
	 */
	unsigned long long rate_bps[2];
	long rate_pending_usleep[2];
	unsigned long rate_bytes[2];
	unsigned long rate_blocks[2];
	struct timeval lastrate[2];

	unsigned long long total_io_size;
	unsigned long long fill_device_size;

	unsigned long io_issues[2];
	unsigned long long io_blocks[2];
	unsigned long long this_io_blocks[2];
	unsigned long long io_bytes[2];
	unsigned long long io_skip_bytes;
	unsigned long long this_io_bytes[2];
	unsigned long long zone_bytes;
	struct fio_mutex *mutex;

	/*
	 * State for random io, a bitmap of blocks done vs not done
	 */
	union {
		os_random_state_t random_state;
		struct frand_state __random_state;
	};

	struct timeval start;	/* start of this loop */
	struct timeval epoch;	/* time job was started */
	struct timeval last_issue;
	struct timeval tv_cache;
	unsigned int tv_cache_nr;
	unsigned int tv_cache_mask;
	unsigned int ramp_time_over;

	/*
	 * read/write mixed workload state
	 */
	union {
		os_random_state_t rwmix_state;
		struct frand_state __rwmix_state;
	};
	unsigned long rwmix_issues;
	enum fio_ddir rwmix_ddir;
	unsigned int ddir_seq_nr;

	/*
	 * IO history logs for verification. We use a tree for sorting,
	 * if we are overwriting. Otherwise just use a fifo.
	 */
	struct rb_root io_hist_tree;
	struct flist_head io_hist_list;
	unsigned long io_hist_len;

	/*
	 * For IO replaying
	 */
	struct flist_head io_log_list;

	/*
	 * For tracking/handling discards
	 */
	struct flist_head trim_list;
	unsigned long trim_entries;

	/*
	 * for fileservice, how often to switch to a new file
	 */
	unsigned int file_service_nr;
	unsigned int file_service_left;
	struct fio_file *file_service_file;

	unsigned int sync_file_range_nr;

	/*
	 * For generating file sizes
	 */
	union {
		os_random_state_t file_size_state;
		struct frand_state __file_size_state;
	};

	/*
	 * Error counts
	 */
	unsigned int total_err_count;
	int first_error;

	/*
	 * Can be overloaded by profiles
	 */
	struct prof_io_ops prof_io_ops;
	void *prof_data;
};

/*
 * when should interactive ETA output be generated
 */
enum {
	FIO_ETA_AUTO,
	FIO_ETA_ALWAYS,
	FIO_ETA_NEVER,
};

#define __td_verror(td, err, msg, func)					\
	do {								\
		if ((td)->error)					\
			break;						\
		int e = (err);						\
		(td)->error = e;					\
		if (!(td)->first_error)					\
			snprintf(td->verror, sizeof(td->verror) - 1, "file:%s:%d, func=%s, error=%s", __FILE__, __LINE__, (func), (msg));		\
	} while (0)


#define td_clear_error(td)		\
	(td)->error = 0;
#define td_verror(td, err, func)	\
	__td_verror((td), (err), strerror((err)), (func))
#define td_vmsg(td, err, msg, func)	\
	__td_verror((td), (err), (msg), (func))

#define __fio_stringify_1(x)	#x
#define __fio_stringify(x)	__fio_stringify_1(x)

extern int exitall_on_terminate;
extern unsigned int thread_number;
extern unsigned int nr_process, nr_thread;
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
extern int fio_gtod_offload;
extern int fio_gtod_cpu;
extern enum fio_cs fio_clock_source;
extern int warnings_fatal;
extern int terse_version;
extern int is_backend;
extern int nr_clients;
extern int log_syslog;
extern const char fio_version_string[];
extern const fio_fp64_t def_percentile_list[FIO_IO_U_LIST_MAX_LEN];

extern struct thread_data *threads;

static inline void fio_ro_check(struct thread_data *td, struct io_u *io_u)
{
	assert(!(io_u->ddir == DDIR_WRITE && !td_write(td)));
}

#define BLOCKS_PER_MAP		(8 * sizeof(unsigned long))
#define TO_MAP_BLOCK(f, b)	(b)
#define RAND_MAP_IDX(f, b)	(TO_MAP_BLOCK(f, b) / BLOCKS_PER_MAP)
#define RAND_MAP_BIT(f, b)	(TO_MAP_BLOCK(f, b) & (BLOCKS_PER_MAP - 1))

#define REAL_MAX_JOBS		2048

#define td_non_fatal_error(e)	((e) == EIO || (e) == EILSEQ)

static inline enum error_type td_error_type(enum fio_ddir ddir, int err)
{
	if (err == EILSEQ)
		return ERROR_TYPE_VERIFY;
	if (ddir == DDIR_READ)
		return ERROR_TYPE_READ;
	return ERROR_TYPE_WRITE;
}

static inline void update_error_count(struct thread_data *td, int err)
{
	td->total_err_count++;
	if (td->total_err_count == 1)
		td->first_error = err;
}

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
 * Init/option functions
 */
extern int __must_check parse_options(int, char **);
extern int parse_jobs_ini(char *, int, int);
extern int parse_cmd_line(int, char **);
extern int exec_run(void);
extern void reset_fio_state(void);
extern int fio_options_parse(struct thread_data *, char **, int);
extern void fio_keywords_init(void);
extern int fio_cmd_option_parse(struct thread_data *, const char *, char *);
extern int fio_cmd_ioengine_option_parse(struct thread_data *, const char *, char *);
extern void fio_fill_default_options(struct thread_data *);
extern int fio_show_option_help(const char *);
extern void fio_options_set_ioengine_opts(struct option *long_options, struct thread_data *td);
extern void fio_options_dup_and_init(struct option *);
extern void fio_options_mem_dupe(struct thread_data *);
extern void options_mem_dupe(void *data, struct fio_option *options);
extern void td_fill_rand_seeds(struct thread_data *);
extern void add_job_opts(const char **);
extern char *num2str(unsigned long, int, int, int);
extern int ioengine_load(struct thread_data *);

#define FIO_GETOPT_JOB		0x89000000
#define FIO_GETOPT_IOENGINE	0x98000000
#define FIO_NR_OPTIONS		(FIO_MAX_OPTS + 128)

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
	TD_RAMP,
	TD_RUNNING,
	TD_PRE_READING,
	TD_VERIFYING,
	TD_FSYNCING,
	TD_EXITED,
	TD_REAPED,
};

extern void td_set_runstate(struct thread_data *, int);
#define TERMINATE_ALL		(-1)
extern void fio_terminate_threads(int);

/*
 * Memory helpers
 */
extern int __must_check fio_pin_memory(void);
extern void fio_unpin_memory(void);
extern int __must_check allocate_io_mem(struct thread_data *);
extern void free_io_mem(struct thread_data *);

/*
 * Reset stats after ramp time completes
 */
extern void reset_all_stats(struct thread_data *);

/*
 * blktrace support
 */
#ifdef FIO_HAVE_BLKTRACE
extern int is_blktrace(const char *);
extern int load_blktrace(struct thread_data *, const char *);
#endif

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
		td_set_runstate((td), TD_EXITED);	\
		(td)->error = EFAULT;		\
		*__foo = 0;			\
	}	\
} while (0)

static inline int fio_fill_issue_time(struct thread_data *td)
{
	if (td->o.read_iolog_file ||
	    !td->o.disable_clat || !td->o.disable_slat || !td->o.disable_bw)
		return 1;

	return 0;
}

static inline int __should_check_rate(struct thread_data *td,
				      enum fio_ddir ddir)
{
	struct thread_options *o = &td->o;

	/*
	 * If some rate setting was given, we need to check it
	 */
	if (o->rate[ddir] || o->ratemin[ddir] || o->rate_iops[ddir] ||
	    o->rate_iops_min[ddir])
		return 1;

	return 0;
}

static inline int should_check_rate(struct thread_data *td,
				    unsigned long *bytes_done)
{
	int ret = 0;

	if (bytes_done[0])
		ret |= __should_check_rate(td, 0);
	if (bytes_done[1])
		ret |= __should_check_rate(td, 1);

	return ret;
}

static inline int is_power_of_2(unsigned int val)
{
	return (val != 0 && ((val & (val - 1)) == 0));
}

/*
 * We currently only need to do locking if we have verifier threads
 * accessing our internal structures too
 */
static inline void td_io_u_lock(struct thread_data *td)
{
	if (td->o.verify_async)
		pthread_mutex_lock(&td->io_u_lock);
}

static inline void td_io_u_unlock(struct thread_data *td)
{
	if (td->o.verify_async)
		pthread_mutex_unlock(&td->io_u_lock);
}

static inline void td_io_u_free_notify(struct thread_data *td)
{
	if (td->o.verify_async)
		pthread_cond_signal(&td->free_cond);
}

extern const char *fio_get_arch_string(int);
extern const char *fio_get_os_string(int);

#endif
