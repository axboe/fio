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

#include "compiler/compiler.h"
#include "thread_options.h"
#include "flist.h"
#include "fifo.h"
#include "arch/arch.h"
#include "os/os.h"
#include "mutex.h"
#include "log.h"
#include "debug.h"
#include "file.h"
#include "io_ddir.h"
#include "ioengines.h"
#include "iolog.h"
#include "helpers.h"
#include "options.h"
#include "profile.h"
#include "fio_time.h"
#include "gettime.h"
#include "oslib/getopt.h"
#include "lib/rand.h"
#include "lib/rbtree.h"
#include "lib/num2str.h"
#include "client.h"
#include "server.h"
#include "stat.h"
#include "flow.h"
#include "io_u.h"
#include "io_u_queue.h"
#include "workqueue.h"
#include "steadystate.h"

#ifdef CONFIG_SOLARISAIO
#include <sys/asynch.h>
#endif

#ifdef CONFIG_LIBNUMA
#include <linux/mempolicy.h>
#include <numa.h>

/*
 * "local" is pseudo-policy
 */
#define MPOL_LOCAL MPOL_MAX
#endif

#ifdef CONFIG_CUDA
#include <cuda.h>
#endif

/*
 * offset generator types
 */
enum {
	RW_SEQ_SEQ	= 0,
	RW_SEQ_IDENT,
};

enum {
	TD_F_VER_BACKLOG	= 1U << 0,
	TD_F_TRIM_BACKLOG	= 1U << 1,
	TD_F_READ_IOLOG		= 1U << 2,
	TD_F_REFILL_BUFFERS	= 1U << 3,
	TD_F_SCRAMBLE_BUFFERS	= 1U << 4,
	TD_F_VER_NONE		= 1U << 5,
	TD_F_PROFILE_OPS	= 1U << 6,
	TD_F_COMPRESS		= 1U << 7,
	TD_F_RESERVED		= 1U << 8, /* not used */
	TD_F_COMPRESS_LOG	= 1U << 9,
	TD_F_VSTATE_SAVED	= 1U << 10,
	TD_F_NEED_LOCK		= 1U << 11,
	TD_F_CHILD		= 1U << 12,
	TD_F_NO_PROGRESS        = 1U << 13,
	TD_F_REGROW_LOGS	= 1U << 14,
};

enum {
	FIO_RAND_BS_OFF		= 0,
	FIO_RAND_VER_OFF,
	FIO_RAND_MIX_OFF,
	FIO_RAND_FILE_OFF,
	FIO_RAND_BLOCK_OFF,
	FIO_RAND_FILE_SIZE_OFF,
	FIO_RAND_TRIM_OFF,
	FIO_RAND_BUF_OFF,
	FIO_RAND_SEQ_RAND_READ_OFF,
	FIO_RAND_SEQ_RAND_WRITE_OFF,
	FIO_RAND_SEQ_RAND_TRIM_OFF,
	FIO_RAND_START_DELAY,
	FIO_DEDUPE_OFF,
	FIO_RAND_POISSON_OFF,
	FIO_RAND_ZONE_OFF,
	FIO_RAND_POISSON2_OFF,
	FIO_RAND_POISSON3_OFF,
	FIO_RAND_NR_OFFS,
};

enum {
	IO_MODE_INLINE = 0,
	IO_MODE_OFFLOAD = 1,

	RATE_PROCESS_LINEAR = 0,
	RATE_PROCESS_POISSON = 1,
};

enum {
	F_ADV_NONE = 0,
	F_ADV_TYPE,
	F_ADV_RANDOM,
	F_ADV_SEQUENTIAL,
};

/*
 * Per-thread/process specific data. Only used for the network client
 * for now.
 */
void sk_out_assign(struct sk_out *);
void sk_out_drop(void);

struct zone_split_index {
	uint8_t size_perc;
	uint8_t size_perc_prev;
};

/*
 * This describes a single thread/process executing a fio job.
 */
struct thread_data {
	struct flist_head opt_list;
	unsigned long flags;
	struct thread_options o;
	void *eo;
	pthread_t thread;
	unsigned int thread_number;
	unsigned int subjob_number;
	unsigned int groupid;
	struct thread_stat ts;

	int client_type;

	struct io_log *slat_log;
	struct io_log *clat_log;
	struct io_log *clat_hist_log;
	struct io_log *lat_log;
	struct io_log *bw_log;
	struct io_log *iops_log;

	struct workqueue log_compress_wq;

	struct thread_data *parent;

	uint64_t stat_io_bytes[DDIR_RWDIR_CNT];
	struct timeval bw_sample_time;

	uint64_t stat_io_blocks[DDIR_RWDIR_CNT];
	struct timeval iops_sample_time;

	volatile int update_rusage;
	struct fio_mutex *rusage_sem;
	struct rusage ru_start;
	struct rusage ru_end;

	struct fio_file **files;
	unsigned char *file_locks;
	unsigned int files_size;
	unsigned int files_index;
	unsigned int nr_open_files;
	unsigned int nr_done_files;
	unsigned int nr_normal_files;
	union {
		unsigned int next_file;
		struct frand_state next_file_state;
	};
	union {
		struct zipf_state next_file_zipf;
		struct gauss_state next_file_gauss;
	};
	union {
		double zipf_theta;
		double pareto_h;
		double gauss_dev;
	};
	int error;
	int sig;
	int done;
	int stop_io;
	pid_t pid;
	char *orig_buffer;
	size_t orig_buffer_size;
	volatile int terminate;
	volatile int runstate;
	unsigned int last_was_sync;
	enum fio_ddir last_ddir;

	int mmapfd;

	void *iolog_buf;
	FILE *iolog_f;

	unsigned long rand_seeds[FIO_RAND_NR_OFFS];

	struct frand_state bsrange_state;
	struct frand_state verify_state;
	struct frand_state trim_state;
	struct frand_state delay_state;

	struct frand_state buf_state;
	struct frand_state buf_state_prev;
	struct frand_state dedupe_state;
	struct frand_state zone_state;

	struct zone_split_index **zone_state_index;

	unsigned int verify_batch;
	unsigned int trim_batch;

	struct thread_io_list *vstate;

	int shm_id;

	/*
	 * IO engine hooks, contains everything needed to submit an io_u
	 * to any of the available IO engines.
	 */
	struct ioengine_ops *io_ops;
	int io_ops_init;

	/*
	 * IO engine private data and dlhandle.
	 */
	void *io_ops_data;
	void *io_ops_dlhandle;

	/*
	 * Queue depth of io_u's that fio MIGHT do
	 */
	unsigned int cur_depth;

	/*
	 * io_u's about to be committed
	 */
	unsigned int io_u_queued;

	/*
	 * io_u's submitted but not completed yet
	 */
	unsigned int io_u_in_flight;

	/*
	 * List of free and busy io_u's
	 */
	struct io_u_ring io_u_requeues;
	struct io_u_queue io_u_freelist;
	struct io_u_queue io_u_all;
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
	uint64_t rate_bps[DDIR_RWDIR_CNT];
	uint64_t rate_next_io_time[DDIR_RWDIR_CNT];
	unsigned long rate_bytes[DDIR_RWDIR_CNT];
	unsigned long rate_blocks[DDIR_RWDIR_CNT];
	unsigned long long rate_io_issue_bytes[DDIR_RWDIR_CNT];
	struct timeval lastrate[DDIR_RWDIR_CNT];
	int64_t last_usec[DDIR_RWDIR_CNT];
	struct frand_state poisson_state[DDIR_RWDIR_CNT];

	/*
	 * Enforced rate submission/completion workqueue
	 */
	struct workqueue io_wq;

	uint64_t total_io_size;
	uint64_t fill_device_size;

	/*
	 * Issue side
	 */
	uint64_t io_issues[DDIR_RWDIR_CNT];
	uint64_t io_issue_bytes[DDIR_RWDIR_CNT];
	uint64_t loops;

	/*
	 * Completions
	 */
	uint64_t io_blocks[DDIR_RWDIR_CNT];
	uint64_t this_io_blocks[DDIR_RWDIR_CNT];
	uint64_t io_bytes[DDIR_RWDIR_CNT];
	uint64_t this_io_bytes[DDIR_RWDIR_CNT];
	uint64_t io_skip_bytes;
	uint64_t zone_bytes;
	struct fio_mutex *mutex;
	uint64_t bytes_done[DDIR_RWDIR_CNT];

	/*
	 * State for random io, a bitmap of blocks done vs not done
	 */
	struct frand_state random_state;

	struct timeval start;	/* start of this loop */
	struct timeval epoch;	/* time job was started */
	unsigned long long unix_epoch; /* Time job was started, unix epoch based. */
	struct timeval last_issue;
	long time_offset;
	struct timeval tv_cache;
	struct timeval terminate_time;
	unsigned int tv_cache_nr;
	unsigned int tv_cache_mask;
	unsigned int ramp_time_over;

	/*
	 * Time since last latency_window was started
	 */
	struct timeval latency_ts;
	unsigned int latency_qd;
	unsigned int latency_qd_high;
	unsigned int latency_qd_low;
	unsigned int latency_failed;
	uint64_t latency_ios;
	int latency_end_run;

	/*
	 * read/write mixed workload state
	 */
	struct frand_state rwmix_state;
	unsigned long rwmix_issues;
	enum fio_ddir rwmix_ddir;
	unsigned int ddir_seq_nr;

	/*
	 * rand/seq mixed workload state
	 */
	struct frand_state seq_rand_state[DDIR_RWDIR_CNT];

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

	struct flist_head next_rand_list;

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
	struct frand_state file_size_state;

	/*
	 * Error counts
	 */
	unsigned int total_err_count;
	int first_error;

	struct fio_flow *flow;

	/*
	 * Can be overloaded by profiles
	 */
	struct prof_io_ops prof_io_ops;
	void *prof_data;

	void *pinned_mem;

	struct steadystate_data ss;

	char verror[FIO_VERROR_SIZE];

#ifdef CONFIG_CUDA
	/*
	 * for GPU memory management
	 */
	int gpu_dev_cnt;
	int gpu_dev_id;
	CUdevice  cu_dev;
	CUcontext cu_ctx;
	CUdeviceptr dev_mem_ptr;
#endif	

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
		unsigned int ____e = (err);				\
		if ((td)->error)					\
			break;						\
		(td)->error = ____e;					\
		if (!(td)->first_error)					\
			snprintf(td->verror, sizeof(td->verror), "file:%s:%d, func=%s, error=%s", __FILE__, __LINE__, (func), (msg));		\
	} while (0)


#define td_clear_error(td)		do {		\
	(td)->error = 0;				\
	if ((td)->parent)				\
		(td)->parent->error = 0;		\
} while (0)

#define td_verror(td, err, func)	do {			\
	__td_verror((td), (err), strerror((err)), (func));	\
	if ((td)->parent)					\
		__td_verror((td)->parent, (err), strerror((err)), (func)); \
} while (0)

#define td_vmsg(td, err, msg, func)	do {			\
	__td_verror((td), (err), (msg), (func));		\
	if ((td)->parent)					\
		__td_verror((td)->parent, (err), (msg), (func));	\
} while (0)

#define __fio_stringify_1(x)	#x
#define __fio_stringify(x)	__fio_stringify_1(x)

extern int exitall_on_terminate;
extern unsigned int thread_number;
extern unsigned int stat_number;
extern int shm_id;
extern int groupid;
extern int output_format;
extern int append_terse_output;
extern int temp_stall_ts;
extern uintptr_t page_mask, page_size;
extern int read_only;
extern int eta_print;
extern int eta_new_line;
extern unsigned long done_secs;
extern int fio_gtod_offload;
extern int fio_gtod_cpu;
extern enum fio_cs fio_clock_source;
extern int fio_clock_source_set;
extern int warnings_fatal;
extern int terse_version;
extern int is_backend;
extern int nr_clients;
extern int log_syslog;
extern int status_interval;
extern const char fio_version_string[];
extern char *trigger_file;
extern char *trigger_cmd;
extern char *trigger_remote_cmd;
extern long long trigger_timeout;
extern char *aux_path;

extern struct thread_data *threads;

static inline void fio_ro_check(const struct thread_data *td, struct io_u *io_u)
{
	assert(!(io_u->ddir == DDIR_WRITE && !td_write(td)));
}

#define REAL_MAX_JOBS		4096

static inline int should_fsync(struct thread_data *td)
{
	if (td->last_was_sync)
		return 0;
	if (td_write(td) || td->o.override_sync)
		return 1;

	return 0;
}

/*
 * Init/option functions
 */
extern int __must_check fio_init_options(void);
extern int __must_check parse_options(int, char **);
extern int parse_jobs_ini(char *, int, int, int);
extern int parse_cmd_line(int, char **, int);
extern int fio_backend(struct sk_out *);
extern void reset_fio_state(void);
extern void clear_io_state(struct thread_data *, int);
extern int fio_options_parse(struct thread_data *, char **, int);
extern void fio_keywords_init(void);
extern void fio_keywords_exit(void);
extern int fio_cmd_option_parse(struct thread_data *, const char *, char *);
extern int fio_cmd_ioengine_option_parse(struct thread_data *, const char *, char *);
extern void fio_fill_default_options(struct thread_data *);
extern int fio_show_option_help(const char *);
extern void fio_options_set_ioengine_opts(struct option *long_options, struct thread_data *td);
extern void fio_options_dup_and_init(struct option *);
extern void fio_options_mem_dupe(struct thread_data *);
extern void td_fill_rand_seeds(struct thread_data *);
extern void td_fill_verify_state_seed(struct thread_data *);
extern void add_job_opts(const char **, int);
extern int ioengine_load(struct thread_data *);
extern bool parse_dryrun(void);
extern int fio_running_or_pending_io_threads(void);
extern int fio_set_fd_nonblocking(int, const char *);
extern void sig_show_status(int sig);
extern struct thread_data *get_global_options(void);

extern uintptr_t page_mask;
extern uintptr_t page_size;
extern int initialize_fio(char *envp[]);
extern void deinitialize_fio(void);

#define FIO_GETOPT_JOB		0x89000000
#define FIO_GETOPT_IOENGINE	0x98000000
#define FIO_NR_OPTIONS		(FIO_MAX_OPTS + 128)

/*
 * ETA/status stuff
 */
extern void print_thread_status(void);
extern void print_status_init(int);
extern char *fio_uint_to_kmg(unsigned int val);

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
	TD_SETTING_UP,
	TD_RUNNING,
	TD_PRE_READING,
	TD_VERIFYING,
	TD_FSYNCING,
	TD_FINISHING,
	TD_EXITED,
	TD_REAPED,
	TD_LAST,
	TD_NR,
};

#define TD_ENG_FLAG_SHIFT	16
#define TD_ENG_FLAG_MASK	((1U << 16) - 1)

static inline enum fio_ioengine_flags td_ioengine_flags(struct thread_data *td)
{
	return (enum fio_ioengine_flags)
		((td->flags >> TD_ENG_FLAG_SHIFT) & TD_ENG_FLAG_MASK);
}

static inline void td_set_ioengine_flags(struct thread_data *td)
{
	td->flags = (~(TD_ENG_FLAG_MASK << TD_ENG_FLAG_SHIFT) & td->flags) |
		    (td->io_ops->flags << TD_ENG_FLAG_SHIFT);
}

static inline bool td_ioengine_flagged(struct thread_data *td,
				       enum fio_ioengine_flags flags)
{
	return ((td->flags >> TD_ENG_FLAG_SHIFT) & flags) != 0;
}

extern void td_set_runstate(struct thread_data *, int);
extern int td_bump_runstate(struct thread_data *, int);
extern void td_restore_runstate(struct thread_data *, int);
extern const char *runstate_to_name(int runstate);

/*
 * Allow 60 seconds for a job to quit on its own, otherwise reap with
 * a vengeance.
 */
#define FIO_REAP_TIMEOUT	300

#define TERMINATE_ALL		(-1U)
extern void fio_terminate_threads(unsigned int);
extern void fio_mark_td_terminate(struct thread_data *);

/*
 * Memory helpers
 */
extern int __must_check fio_pin_memory(struct thread_data *);
extern void fio_unpin_memory(struct thread_data *);
extern int __must_check allocate_io_mem(struct thread_data *);
extern void free_io_mem(struct thread_data *);
extern void free_threads_shm(void);

#ifdef FIO_INTERNAL
#define PTR_ALIGN(ptr, mask)	\
	(char *) (((uintptr_t) (ptr) + (mask)) & ~(mask))
#endif

/*
 * Reset stats after ramp time completes
 */
extern void reset_all_stats(struct thread_data *);

/*
 * blktrace support
 */
#ifdef FIO_HAVE_BLKTRACE
extern int is_blktrace(const char *, int *);
extern int load_blktrace(struct thread_data *, const char *, int);
#endif

extern int io_queue_event(struct thread_data *td, struct io_u *io_u, int *ret,
		   enum fio_ddir ddir, uint64_t *bytes_issued, int from_verify,
		   struct timeval *comp_time);

/*
 * Latency target helpers
 */
extern void lat_target_check(struct thread_data *);
extern void lat_target_init(struct thread_data *);
extern void lat_target_reset(struct thread_data *);

/*
 * Iterates all threads/processes within all the defined jobs
 */
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

static inline bool fio_fill_issue_time(struct thread_data *td)
{
	if (td->o.read_iolog_file ||
	    !td->o.disable_clat || !td->o.disable_slat || !td->o.disable_bw)
		return true;

	return false;
}

static inline bool __should_check_rate(struct thread_data *td,
				       enum fio_ddir ddir)
{
	struct thread_options *o = &td->o;

	/*
	 * If some rate setting was given, we need to check it
	 */
	if (o->rate[ddir] || o->ratemin[ddir] || o->rate_iops[ddir] ||
	    o->rate_iops_min[ddir])
		return true;

	return false;
}

static inline bool should_check_rate(struct thread_data *td)
{
	if (td->bytes_done[DDIR_READ] && __should_check_rate(td, DDIR_READ))
		return true;
	if (td->bytes_done[DDIR_WRITE] && __should_check_rate(td, DDIR_WRITE))
		return true;
	if (td->bytes_done[DDIR_TRIM] && __should_check_rate(td, DDIR_TRIM))
		return true;

	return false;
}

static inline unsigned int td_max_bs(struct thread_data *td)
{
	unsigned int max_bs;

	max_bs = max(td->o.max_bs[DDIR_READ], td->o.max_bs[DDIR_WRITE]);
	return max(td->o.max_bs[DDIR_TRIM], max_bs);
}

static inline unsigned int td_min_bs(struct thread_data *td)
{
	unsigned int min_bs;

	min_bs = min(td->o.min_bs[DDIR_READ], td->o.min_bs[DDIR_WRITE]);
	return min(td->o.min_bs[DDIR_TRIM], min_bs);
}

static inline bool td_async_processing(struct thread_data *td)
{
	return (td->flags & TD_F_NEED_LOCK) != 0;
}

/*
 * We currently only need to do locking if we have verifier threads
 * accessing our internal structures too
 */
static inline void td_io_u_lock(struct thread_data *td)
{
	if (td_async_processing(td))
		pthread_mutex_lock(&td->io_u_lock);
}

static inline void td_io_u_unlock(struct thread_data *td)
{
	if (td_async_processing(td))
		pthread_mutex_unlock(&td->io_u_lock);
}

static inline void td_io_u_free_notify(struct thread_data *td)
{
	if (td_async_processing(td))
		pthread_cond_signal(&td->free_cond);
}

static inline void td_flags_clear(struct thread_data *td, unsigned int *flags,
				  unsigned int value)
{
	if (!td_async_processing(td))
		*flags &= ~value;
	else
		__sync_fetch_and_and(flags, ~value);
}

static inline void td_flags_set(struct thread_data *td, unsigned int *flags,
				unsigned int value)
{
	if (!td_async_processing(td))
		*flags |= value;
	else
		__sync_fetch_and_or(flags, value);
}

extern const char *fio_get_arch_string(int);
extern const char *fio_get_os_string(int);

#ifdef FIO_INTERNAL
#define ARRAY_SIZE(x)    (sizeof((x)) / (sizeof((x)[0])))
#define FIELD_SIZE(s, f) (sizeof(((typeof(s))0)->f))
#endif

enum {
	__FIO_OUTPUT_TERSE	= 0,
	__FIO_OUTPUT_JSON	= 1,
	__FIO_OUTPUT_NORMAL	= 2,
        __FIO_OUTPUT_JSON_PLUS  = 3,
	FIO_OUTPUT_NR		= 4,

	FIO_OUTPUT_TERSE	= 1U << __FIO_OUTPUT_TERSE,
	FIO_OUTPUT_JSON		= 1U << __FIO_OUTPUT_JSON,
	FIO_OUTPUT_NORMAL	= 1U << __FIO_OUTPUT_NORMAL,
	FIO_OUTPUT_JSON_PLUS    = 1U << __FIO_OUTPUT_JSON_PLUS,
};

enum {
	FIO_RAND_DIST_RANDOM	= 0,
	FIO_RAND_DIST_ZIPF,
	FIO_RAND_DIST_PARETO,
	FIO_RAND_DIST_GAUSS,
	FIO_RAND_DIST_ZONED,
};

#define FIO_DEF_ZIPF		1.1
#define FIO_DEF_PARETO		0.2

enum {
	FIO_RAND_GEN_TAUSWORTHE = 0,
	FIO_RAND_GEN_LFSR,
	FIO_RAND_GEN_TAUSWORTHE64,
};

enum {
	FIO_CPUS_SHARED		= 0,
	FIO_CPUS_SPLIT,
};

extern void exec_trigger(const char *);
extern void check_trigger_file(void);

#endif
