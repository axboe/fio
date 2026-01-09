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
#include "log.h"
#include "debug.h"
#include "file.h"
#include "io_ddir.h"
#include "ioengines.h"
#include "iolog.h"
#include "helpers.h"
#include "minmax.h"
#include "options.h"
#include "profile.h"
#include "fio_time.h"
#include "gettime.h"
#include "oslib/getopt.h"
#include "lib/rand.h"
#include "lib/rbtree.h"
#include "lib/num2str.h"
#include "lib/memalign.h"
#include "smalloc.h"
#include "client.h"
#include "server.h"
#include "stat.h"
#include "flow.h"
#include "io_u.h"
#include "io_u_queue.h"
#include "workqueue.h"
#include "steadystate.h"
#include "lib/nowarn_snprintf.h"
#include "dedupe.h"

#ifdef CONFIG_SOLARISAIO
#include <sys/asynch.h>
#endif

#ifdef CONFIG_LIBNUMA
#include <linux/mempolicy.h>
#include <numa.h>

/*
 * "local" is pseudo-policy
 */
#ifndef MPOL_LOCAL
#define MPOL_LOCAL 4
#endif
#endif

#ifdef CONFIG_CUDA
#include <cuda.h>
#endif

struct fio_sem;

#define MAX_TRIM_RANGE	256

/*
 * Range for trim command
 */
struct trim_range {
	unsigned long long start;
	unsigned long long len;
};

/*
 * offset generator types
 */
enum {
	RW_SEQ_SEQ	= 0,
	RW_SEQ_IDENT,
};

enum {
	__TD_F_VER_BACKLOG	= 0,
	__TD_F_TRIM_BACKLOG,
	__TD_F_READ_IOLOG,
	__TD_F_REFILL_BUFFERS,
	__TD_F_SCRAMBLE_BUFFERS,
	__TD_F_DO_VERIFY,
	__TD_F_PROFILE_OPS,
	__TD_F_COMPRESS,
	__TD_F_COMPRESS_LOG,
	__TD_F_VSTATE_SAVED,
	__TD_F_NEED_LOCK,
	__TD_F_CHILD,
	__TD_F_NO_PROGRESS,
	__TD_F_REGROW_LOGS,
	__TD_F_MMAP_KEEP,
	__TD_F_DIRS_CREATED,
	__TD_F_CHECK_RATE,
	__TD_F_SYNCS,
	__TD_F_LAST,		/* not a real bit, keep last */
};

enum {
	TD_F_VER_BACKLOG	= 1U << __TD_F_VER_BACKLOG,
	TD_F_TRIM_BACKLOG	= 1U << __TD_F_TRIM_BACKLOG,
	TD_F_READ_IOLOG		= 1U << __TD_F_READ_IOLOG,
	TD_F_REFILL_BUFFERS	= 1U << __TD_F_REFILL_BUFFERS,
	TD_F_SCRAMBLE_BUFFERS	= 1U << __TD_F_SCRAMBLE_BUFFERS,
	TD_F_DO_VERIFY		= 1U << __TD_F_DO_VERIFY,
	TD_F_PROFILE_OPS	= 1U << __TD_F_PROFILE_OPS,
	TD_F_COMPRESS		= 1U << __TD_F_COMPRESS,
	TD_F_COMPRESS_LOG	= 1U << __TD_F_COMPRESS_LOG,
	TD_F_VSTATE_SAVED	= 1U << __TD_F_VSTATE_SAVED,
	TD_F_NEED_LOCK		= 1U << __TD_F_NEED_LOCK,
	TD_F_CHILD		= 1U << __TD_F_CHILD,
	TD_F_NO_PROGRESS        = 1U << __TD_F_NO_PROGRESS,
	TD_F_REGROW_LOGS	= 1U << __TD_F_REGROW_LOGS,
	TD_F_MMAP_KEEP		= 1U << __TD_F_MMAP_KEEP,
	TD_F_DIRS_CREATED	= 1U << __TD_F_DIRS_CREATED,
	TD_F_CHECK_RATE		= 1U << __TD_F_CHECK_RATE,
	TD_F_SYNCS		= 1U << __TD_F_SYNCS,
};

enum {
	FIO_RAND_BS_OFF		= 0,
	FIO_RAND_BS1_OFF,
	FIO_RAND_BS2_OFF,
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
	FIO_RAND_PRIO_CMDS,
	FIO_RAND_DEDUPE_WORKING_SET_IX,
	FIO_RAND_FDP_OFF,
	FIO_RAND_SPRANDOM_OFF,
	FIO_RAND_NR_OFFS,
};

enum {
	IO_MODE_INLINE = 0,
	IO_MODE_OFFLOAD = 1,

	RATE_PROCESS_LINEAR = 0,
	RATE_PROCESS_POISSON = 1,

	THINKTIME_BLOCKS_TYPE_COMPLETE = 0,
	THINKTIME_BLOCKS_TYPE_ISSUE = 1,
};

enum {
	F_ADV_NONE = 0,
	F_ADV_TYPE,
	F_ADV_RANDOM,
	F_ADV_SEQUENTIAL,
	F_ADV_NOREUSE,
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
	uint64_t size;
	uint64_t size_prev;
};

/*
 * This describes a single thread/process executing a fio job.
 */
struct thread_data {
	struct flist_head opt_list;
	unsigned long long flags;
	struct thread_options o;
	void *eo;
	pthread_t thread;
	unsigned int thread_number;
	unsigned int subjob_number;
	unsigned int groupid;
	struct thread_stat ts __attribute__ ((aligned(8)));

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
	struct timespec bw_sample_time;

	uint64_t stat_io_blocks[DDIR_RWDIR_CNT];
	struct timespec iops_sample_time;

	volatile int update_rusage;
	struct fio_sem *rusage_sem;
	struct rusage ru_start;
	struct rusage ru_end;

	struct fio_file **files;
	unsigned char *file_locks;
	unsigned int files_size;
	unsigned int files_index;
	unsigned int nr_open_files;
	unsigned int nr_done_files;
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
	double random_center;
	int error;
	int sig;
	int done;
	int stop_io;
	pid_t pid;
	char *orig_buffer;
	size_t orig_buffer_size;
	volatile int runstate;
	volatile bool terminate;

	enum fio_ddir last_ddir_completed;
	enum fio_ddir last_ddir_issued;

	int mmapfd;

	void *iolog_buf;
	FILE *iolog_f;

	uint64_t rand_seeds[FIO_RAND_NR_OFFS];

	struct frand_state bsrange_state[DDIR_RWDIR_CNT];
	struct frand_state verify_state;
	struct frand_state verify_state_last_do_io;
	struct frand_state trim_state;
	struct frand_state delay_state;
	struct frand_state fdp_state;

	struct frand_state buf_state;
	struct frand_state buf_state_prev;
	struct frand_state buf_state_ret;
	struct frand_state dedupe_state;
	struct frand_state zone_state;
	struct frand_state prio_state;
	struct frand_state dedupe_working_set_index_state;
	struct frand_state *dedupe_working_set_states;
	struct frand_state sprandom_state;

	unsigned long long num_unique_pages;

	struct zone_split_index **zone_state_index;
	unsigned int num_write_zones;

	unsigned int verify_batch;
	unsigned int trim_batch;
	bool trim_verify;

	struct thread_io_list *vstate;

	int shm_id;

	/*
	 * Job default IO priority set with prioclass and prio options.
	 */
	unsigned int ioprio;

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
	unsigned long long last_rate_check_bytes[DDIR_RWDIR_CNT];
	unsigned long last_rate_check_blocks[DDIR_RWDIR_CNT];
	unsigned long long rate_io_issue_bytes[DDIR_RWDIR_CNT];
	struct timespec last_rate_check_time[DDIR_RWDIR_CNT];
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
	uint64_t verify_read_issues;
	uint64_t io_issue_bytes[DDIR_RWDIR_CNT];
	uint64_t loops;

	/*
	 * Keep track of inflight write sequence numbers (numberio) which are used to save verify state.
	 */
	uint64_t *inflight_numberio;
	unsigned int next_inflight_numberio_idx;
	uint64_t inflight_issued;

	/*
	 * Completions
	 */
	uint64_t io_blocks[DDIR_RWDIR_CNT];
	uint64_t this_io_blocks[DDIR_RWDIR_CNT];
	uint64_t io_bytes[DDIR_RWDIR_CNT];
	uint64_t this_io_bytes[DDIR_RWDIR_CNT];
	uint64_t io_skip_bytes;
	uint64_t zone_bytes;
	struct fio_sem *sem;
	uint64_t bytes_done[DDIR_RWDIR_CNT];
	uint64_t bytes_verified;

	uint64_t *thinktime_blocks_counter;
	struct timespec last_thinktime;
	int64_t last_thinktime_blocks;

	/*
	 * State for random io, a bitmap of blocks done vs not done
	 */
	struct frand_state random_state;

	struct timespec start;	/* start of this loop */
	struct timespec epoch;	/* time job was started */
	unsigned long long alternate_epoch; /* Time job was started, as clock_gettime(log_alternate_epoch_clock_id) */
	unsigned long long job_start; /* Time job was started, as clock_gettime(job_start_clock_id) */
	struct timespec last_issue;
	long time_offset;
	struct timespec ts_cache;
	struct timespec terminate_time;
	unsigned int ts_cache_nr;
	unsigned int ts_cache_mask;
	unsigned int ramp_period_state;

	/*
	 * Time since last latency_window was started
	 */
	struct timespec latency_ts;
	unsigned int latency_qd;
	unsigned int latency_qd_high;
	unsigned int latency_qd_low;
	unsigned int latency_failed;
	unsigned int latency_stable_count;
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
	FILE *io_log_rfile;
	unsigned int io_log_blktrace;
	unsigned int io_log_blktrace_swap;
	unsigned long long io_log_last_ttime;
	struct timespec io_log_start_time;
	unsigned int io_log_current;
	unsigned int io_log_checkmark;
	unsigned int io_log_highmark;
	unsigned int io_log_version;
	struct timespec io_log_highmark_time;

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
	struct frand_state file_size_state;

	/*
	 * Error counts
	 */
	unsigned int total_err_count;
	int first_error;

	struct fio_flow *flow;
	unsigned long long flow_counter;

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

struct thread_segment {
	struct thread_data *threads;
	int shm_id;
	int nr_threads;
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
			nowarn_snprintf(td->verror, sizeof(td->verror),	\
					"file:%s:%d, func=%s, error=%s", \
					__FILE__, __LINE__, (func), (msg)); \
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

#define REAL_MAX_JOBS		4096
#define JOBS_PER_SEG		8
#define REAL_MAX_SEG		(REAL_MAX_JOBS / JOBS_PER_SEG)

extern bool exitall_on_terminate;
extern unsigned int thread_number;
extern unsigned int stat_number;
extern unsigned int nr_segments;
extern unsigned int cur_segment;
extern int groupid;
extern int output_format;
extern int append_terse_output;
extern int temp_stall_ts;
extern uintptr_t page_mask, page_size;
extern bool read_only;
extern int eta_print;
extern int eta_new_line;
extern unsigned int eta_interval_msec;
extern unsigned long done_secs;
extern int fio_gtod_offload;
extern int fio_gtod_cpu;
extern enum fio_cs fio_clock_source;
extern int fio_clock_source_set;
extern int warnings_fatal;
extern int terse_version;
extern bool is_backend;
extern bool is_local_backend;
extern int nr_clients;
extern bool log_syslog;
extern int status_interval;
extern const char fio_version_string[];
extern char *trigger_file;
extern char *trigger_cmd;
extern char *trigger_remote_cmd;
extern long long trigger_timeout;
extern char *aux_path;

extern struct thread_segment segments[REAL_MAX_SEG];

static inline struct thread_data *tnumber_to_td(unsigned int tnumber)
{
	struct thread_segment *seg;

	seg = &segments[tnumber / JOBS_PER_SEG];
	return &seg->threads[tnumber & (JOBS_PER_SEG - 1)];
}

static inline bool is_running_backend(void)
{
	return is_backend || is_local_backend;
}

extern bool eta_time_within_slack(unsigned int time);

static inline void fio_ro_check(const struct thread_data *td, struct io_u *io_u)
{
	assert(!(io_u->ddir == DDIR_WRITE && !td_write(td)) &&
	       !(io_u->ddir == DDIR_TRIM && !(td_trim(td) || td->trim_verify)));

	/*
	 * The last line above allows trim operations during trim/verify
	 * workloads. For these workloads we cannot simply set the trim bit for
	 * the thread's ddir because then fio would assume that
	 * ddir={trimewrite, randtrimwrite}.
	 */
}

static inline bool multi_range_trim(struct thread_data *td, struct io_u *io_u)
{
	if (io_u->ddir == DDIR_TRIM && td->o.num_range > 1)
		return true;

	return false;
}

static inline bool should_fsync(struct thread_data *td)
{
	if (ddir_sync(td->last_ddir_issued))
		return false;
	if (td_write(td) || td->o.override_sync)
		return true;

	return false;
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
extern char *fio_option_dup_subs(const char *);
extern void fio_options_mem_dupe(struct thread_data *);
extern void td_fill_rand_seeds(struct thread_data *);
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

#define TD_ENG_FLAG_SHIFT	(__TD_F_LAST)
#define TD_ENG_FLAG_MASK	((1ULL << (__TD_F_LAST)) - 1)

static inline void td_set_ioengine_flags(struct thread_data *td)
{
	td->flags = (~(TD_ENG_FLAG_MASK << TD_ENG_FLAG_SHIFT) & td->flags) |
		    ((unsigned long long)td->io_ops->flags << TD_ENG_FLAG_SHIFT);
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

enum {
	TERMINATE_NONE = 0,
	TERMINATE_GROUP = 1,
	TERMINATE_STONEWALL = 2,
	TERMINATE_ALL = -1,
};

extern void fio_terminate_threads(unsigned int, unsigned int);
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

extern int io_queue_event(struct thread_data *td, struct io_u *io_u, int *ret,
		   enum fio_ddir ddir, uint64_t *bytes_issued, int from_verify,
		   struct timespec *comp_time);

/*
 * Latency target helpers
 */
extern void lat_target_check(struct thread_data *);
extern void lat_target_init(struct thread_data *);
extern void lat_target_reset(struct thread_data *);

/*
 * Inflight log
 */
extern void log_inflight(struct thread_data *, struct io_u *);
extern void invalidate_inflight(struct thread_data *, struct io_u *);
extern void clear_inflight(struct thread_data *);

/*
 * Iterates all threads/processes within all the defined jobs
 * Usage:
 *		for_each_td(var_name_for_td) {
 *			<< bodoy of your loop >>
 *			 Note: internally-scoped loop index availble as __td_index
 *		} end_for_each_td()
 */
#define for_each_td(td)			\
{								\
	int __td_index;				\
	struct thread_data *(td);	\
	for (__td_index = 0, (td) = &segments[0].threads[0];\
		__td_index < (int) thread_number; __td_index++, (td) = tnumber_to_td(__td_index))
#define for_each_td_index()	    \
{								\
	int __td_index;				\
	for (__td_index = 0; __td_index < (int) thread_number; __td_index++)
#define	end_for_each()	}

#define for_each_file(td, f, i)	\
	if ((td)->files_index)						\
		for ((i) = 0, (f) = (td)->files[0];			\
	    	 (i) < (td)->o.nr_files && ((f) = (td)->files[i]) != NULL; \
		 (i)++)

static inline bool fio_offset_overlap_risk(struct thread_data *td)
{
	if (td->o.norandommap || td->o.softrandommap ||
	    td->o.ddir_seq_add || (td->o.ddir_seq_nr > 1))
		return true;

	return false;
}

static inline bool fio_fill_issue_time(struct thread_data *td)
{
	if (td->o.read_iolog_file ||
	    !td->o.disable_clat || !td->o.disable_slat || !td->o.disable_bw)
		return true;

	return false;
}

static inline bool option_check_rate(struct thread_data *td, enum fio_ddir ddir)
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
	return (td->flags & TD_F_CHECK_RATE) != 0;
}

static inline unsigned long long td_max_bs(struct thread_data *td)
{
	unsigned long long max_bs;

	max_bs = max(td->o.max_bs[DDIR_READ], td->o.max_bs[DDIR_WRITE]);
	return max(td->o.max_bs[DDIR_TRIM], max_bs);
}

static inline unsigned long long td_min_bs(struct thread_data *td)
{
	unsigned long long min_bs;

	min_bs = min(td->o.min_bs[DDIR_READ], td->o.min_bs[DDIR_WRITE]);
	return min(td->o.min_bs[DDIR_TRIM], min_bs);
}

static inline bool td_async_processing(struct thread_data *td)
{
	return (td->flags & TD_F_NEED_LOCK) != 0;
}

static inline bool td_offload_overlap(struct thread_data *td)
{
	return td->o.serialize_overlap && td->o.io_submit_mode == IO_MODE_OFFLOAD;
}

/*
 * We currently only need to do locking if we have verifier threads
 * accessing our internal structures too
 */
static inline void __td_io_u_lock(struct thread_data *td)
{
	pthread_mutex_lock(&td->io_u_lock);
}

static inline void __td_io_u_unlock(struct thread_data *td)
{
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
	FIO_RAND_DIST_ZONED_ABS,
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

extern bool in_flight_overlap(struct io_u_queue *q, struct io_u *io_u);
extern pthread_mutex_t overlap_check;

static inline void *fio_memalign(size_t alignment, size_t size, bool shared)
{
	return __fio_memalign(alignment, size, shared ? smalloc : malloc);
}

static inline void fio_memfree(void *ptr, size_t size, bool shared)
{
	return __fio_memfree(ptr, size, shared ? sfree : free);
}

#endif
