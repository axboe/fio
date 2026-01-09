#ifndef FIO_THREAD_OPTIONS_H
#define FIO_THREAD_OPTIONS_H

#include "arch/arch.h"
#include "os/os.h"
#include "options.h"
#include "stat.h"
#include "gettime.h"
#include "lib/ieee754.h"
#include "lib/pattern.h"
#include "td_error.h"

enum fio_zone_mode {
	ZONE_MODE_NOT_SPECIFIED	= 0,
	ZONE_MODE_NONE		= 1,
	ZONE_MODE_STRIDED	= 2, /* perform I/O in one zone at a time */
	/* perform I/O across multiple zones simultaneously */
	ZONE_MODE_ZBD		= 3,
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
	MEM_MMAPSHARED, /* use mmap with shared flag */
	MEM_CUDA_MALLOC,/* use GPU memory */
};

/*
 * What mode to use for deduped data generation
 */
enum dedupe_mode {
	DEDUPE_MODE_REPEAT = 0,
	DEDUPE_MODE_WORKING_SET = 1,
};

#define ERROR_STR_MAX	128

#define BSSPLIT_MAX	64
#define ZONESPLIT_MAX	256

struct split {
	unsigned int nr;
	unsigned long long val1[ZONESPLIT_MAX];
	unsigned long long val2[ZONESPLIT_MAX];
};

struct split_prio {
	uint64_t bs;
	int32_t prio;
	uint32_t perc;
};

struct bssplit {
	uint64_t bs;
	uint32_t perc;
};

struct zone_split {
	uint8_t access_perc;
	uint8_t size_perc;
	uint8_t pad[6];
	uint64_t size;
};

#define NR_OPTS_SZ	(FIO_MAX_OPTS / (8 * sizeof(uint64_t)))

#define OPT_MAGIC	0x4f50544e

struct thread_options {
	int magic;
	uint64_t set_options[NR_OPTS_SZ];
	char *description;
	char *name;
	char *wait_for;
	char *directory;
	char *filename;
	char *filename_format;
	char *opendir;
	char *ioengine;
	char *ioengine_so_path;
	char *mmapfile;
	enum td_ddir td_ddir;
	unsigned int rw_seq;
	unsigned int kb_base;
	unsigned int unit_base;
	unsigned int ddir_seq_nr;
	long long ddir_seq_add;
	unsigned int iodepth;
	unsigned int iodepth_low;
	unsigned int iodepth_batch;
	unsigned int iodepth_batch_complete_min;
	unsigned int iodepth_batch_complete_max;
	unsigned int serialize_overlap;

	unsigned int unique_filename;

	unsigned long long size;
	unsigned long long io_size;
	unsigned int size_percent;
	unsigned int size_nz;
	unsigned int io_size_percent;
	unsigned int io_size_nz;
	unsigned int fill_device;
	unsigned int file_append;
	unsigned long long file_size_low;
	unsigned long long file_size_high;
	unsigned long long start_offset;
	unsigned long long start_offset_align;
	unsigned int start_offset_nz;

	unsigned long long bs[DDIR_RWDIR_CNT];
	unsigned long long ba[DDIR_RWDIR_CNT];
	unsigned long long min_bs[DDIR_RWDIR_CNT];
	unsigned long long max_bs[DDIR_RWDIR_CNT];
	struct bssplit *bssplit[DDIR_RWDIR_CNT];
	unsigned int bssplit_nr[DDIR_RWDIR_CNT];

	int *ignore_error[ERROR_TYPE_CNT];
	unsigned int ignore_error_nr[ERROR_TYPE_CNT];
	unsigned int error_dump;

	unsigned int nr_files;
	unsigned int open_files;
	unsigned int filetype;
	enum file_lock_mode file_lock_mode;

	unsigned int odirect;
	unsigned int oatomic;
	unsigned int invalidate_cache;
	unsigned int create_serialize;
	unsigned int create_fsync;
	unsigned int create_on_open;
	unsigned int create_only;
	unsigned int end_fsync;
	unsigned int pre_read;
	unsigned int sync_io;
	unsigned int write_hint;
	unsigned int verify;
	unsigned int do_verify;
	unsigned int verify_interval;
	unsigned int verify_offset;
	char *verify_pattern;
	unsigned int verify_pattern_bytes;
	unsigned int verify_pattern_interval;
	struct pattern_fmt verify_fmt[8];
	unsigned int verify_fmt_sz;
	unsigned int verify_fatal;
	unsigned int verify_dump;
	unsigned int verify_async;
	unsigned long long verify_backlog;
	unsigned int verify_batch;
	unsigned int experimental_verify;
	unsigned int verify_state;
	unsigned int verify_state_save;
	unsigned int verify_write_sequence;
	unsigned int verify_header_seed;
	unsigned int use_thread;
	unsigned int unlink;
	unsigned int unlink_each_loop;
	unsigned int do_disk_util;
	unsigned int override_sync;
	unsigned int rand_repeatable;
	unsigned long long rand_seed;
	unsigned int log_avg_msec;
	unsigned int log_hist_msec;
	unsigned int log_hist_coarseness;
	unsigned int log_max;
	unsigned int log_offset;
	unsigned int log_gz;
	unsigned int log_gz_store;
	unsigned int log_alternate_epoch;
	unsigned int log_alternate_epoch_clock_id;
	unsigned int norandommap;
	unsigned int softrandommap;
	unsigned int sprandom;
	unsigned int spr_num_regions;
	fio_fp64_t spr_over_provisioning;
	unsigned int bs_unaligned;
	unsigned int fsync_on_close;
	unsigned int bs_is_seq_rand;

	unsigned int verify_only;

	unsigned int random_distribution;
	unsigned int exitall_error;

	struct zone_split *zone_split[DDIR_RWDIR_CNT];
	unsigned int zone_split_nr[DDIR_RWDIR_CNT];

	fio_fp64_t zipf_theta;
	fio_fp64_t pareto_h;
	fio_fp64_t gauss_dev;
	fio_fp64_t random_center;

	unsigned int random_generator;

	unsigned int perc_rand[DDIR_RWDIR_CNT];

	unsigned int hugepage_size;
	unsigned long long rw_min_bs;
	unsigned int fsync_blocks;
	unsigned int fdatasync_blocks;
	unsigned int barrier_blocks;
	unsigned long long start_delay;
	unsigned long long start_delay_orig;
	unsigned long long start_delay_high;
	unsigned long long timeout;
	unsigned long long ramp_time;
	unsigned long long ramp_size;
	unsigned int ss_state;
	fio_fp64_t ss_limit;
	unsigned long long ss_dur;
	unsigned long long ss_ramp_time;
	unsigned long long ss_check_interval;
	unsigned int overwrite;
	unsigned int bw_avg_time;
	unsigned int iops_avg_time;
	unsigned int loops;
	unsigned long long zone_range;
	unsigned long long zone_size;
	unsigned long long zone_capacity;
	unsigned long long zone_skip;
	uint32_t zone_skip_nz;
	enum fio_zone_mode zone_mode;
	unsigned long long lockmem;
	enum fio_memtype mem_type;
	unsigned int mem_align;

	unsigned long long max_latency[DDIR_RWDIR_CNT];

	unsigned int exit_what;
	unsigned int stonewall;
	unsigned int new_group;
	unsigned int numjobs;
	os_cpu_mask_t cpumask;
	os_cpu_mask_t verify_cpumask;
	os_cpu_mask_t log_gz_cpumask;
	unsigned int cpus_allowed_policy;
	char *numa_cpunodes;
	unsigned short numa_mem_mode;
	unsigned int numa_mem_prefer_node;
	char *numa_memnodes;
	unsigned int gpu_dev_id;
	unsigned int start_offset_percent;

	unsigned int iolog;
	unsigned int rwmixcycle;
	unsigned int rwmix[DDIR_RWDIR_CNT];
	unsigned int nice;
	unsigned int ioprio;
	unsigned int ioprio_class;
	unsigned int ioprio_hint;
	unsigned int file_service_type;
	unsigned int group_reporting;
	unsigned int stats;
	unsigned int fadvise_hint;
	enum fio_fallocate_mode fallocate_mode;
	unsigned int zero_buffers;
	unsigned int refill_buffers;
	unsigned int scramble_buffers;
	char *buffer_pattern;
	unsigned int buffer_pattern_bytes;
	unsigned int compress_percentage;
	unsigned int compress_chunk;
	unsigned int dedupe_percentage;
	unsigned int dedupe_mode;
	unsigned int dedupe_working_set_percentage;
	unsigned int dedupe_global;
	unsigned int time_based;
	unsigned int disable_lat;
	unsigned int disable_clat;
	unsigned int disable_slat;
	unsigned int disable_bw;
	unsigned int unified_rw_rep;
	unsigned int gtod_reduce;
	unsigned int gtod_cpu;
	unsigned int job_start_clock_id;
	enum fio_cs clocksource;
	unsigned int no_stall;
	unsigned int trim_percentage;
	unsigned int trim_batch;
	unsigned int trim_zero;
	unsigned long long trim_backlog;
	unsigned int clat_percentiles;
	unsigned int slat_percentiles;
	unsigned int lat_percentiles;
	unsigned int percentile_precision;	/* digits after decimal for percentiles */
	fio_fp64_t percentile_list[FIO_IO_U_LIST_MAX_LEN];

	char *read_iolog_file;
	bool read_iolog_chunked;
	char *write_iolog_file;
	char *merge_blktrace_file;
	fio_fp64_t merge_blktrace_scalars[FIO_IO_U_LIST_MAX_LEN];
	fio_fp64_t merge_blktrace_iters[FIO_IO_U_LIST_MAX_LEN];

	unsigned int write_bw_log;
	unsigned int write_lat_log;
	unsigned int write_iops_log;
	unsigned int write_hist_log;

	char *bw_log_file;
	char *lat_log_file;
	char *iops_log_file;
	char *hist_log_file;
	char *replay_redirect;

	/*
	 * Pre-run and post-run shell
	 */
	char *exec_prerun;
	char *exec_postrun;

	unsigned int thinkcycles;

	unsigned int thinktime;
	unsigned int thinktime_spin;
	unsigned int thinktime_blocks;
	unsigned int thinktime_blocks_type;
	unsigned int thinktime_iotime;

	uint64_t rate[DDIR_RWDIR_CNT];
	uint64_t ratemin[DDIR_RWDIR_CNT];
	unsigned int ratecycle;
	unsigned int io_submit_mode;
	unsigned int rate_iops[DDIR_RWDIR_CNT];
	unsigned int rate_iops_min[DDIR_RWDIR_CNT];
	unsigned int rate_process;
	unsigned int rate_ign_think;

	char *ioscheduler;

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

	unsigned int offset_increment_percent;
	unsigned int offset_increment_nz;
	unsigned long long offset_increment;
	unsigned long long number_ios;

	unsigned int num_range;

	unsigned int sync_file_range;

	unsigned long long latency_target;
	unsigned long long latency_window;
	uint32_t latency_run;
	fio_fp64_t latency_percentile;

	/*
	 * flow support
	 */
	int flow_id;
	unsigned int flow;
	unsigned int flow_sleep;

	unsigned int sig_figs;

	unsigned block_error_hist;

	unsigned int replay_align;
	unsigned int replay_scale;
	unsigned int replay_time_scale;
	unsigned int replay_skip;

	unsigned int per_job_logs;

	unsigned int allow_create;
	unsigned int allow_mounted_write;

	/* Parameters that affect zonemode=zbd */
	unsigned int read_beyond_wp;
	int max_open_zones;
	unsigned int job_max_open_zones;
	unsigned int ignore_zone_limits;
	unsigned int recover_zbd_write_error;
	fio_fp64_t zrt;
	fio_fp64_t zrf;

	unsigned int fdp;
	unsigned int dp_type;
	unsigned int dp_id_select;
	uint16_t dp_ids[FIO_MAX_DP_IDS];
	unsigned int dp_nr_ids;
	char *dp_scheme_file;

	unsigned int log_entries;
	unsigned int log_prio;
	unsigned int log_issue_time;
};

#define FIO_TOP_STR_MAX		256

struct thread_options_pack {
	uint64_t set_options[NR_OPTS_SZ];
	uint8_t description[FIO_TOP_STR_MAX];
	uint8_t name[FIO_TOP_STR_MAX];
	uint8_t wait_for[FIO_TOP_STR_MAX];
	uint8_t directory[FIO_TOP_STR_MAX];
	uint8_t filename[FIO_TOP_STR_MAX];
	uint8_t filename_format[FIO_TOP_STR_MAX];
	uint8_t opendir[FIO_TOP_STR_MAX];
	uint8_t ioengine[FIO_TOP_STR_MAX];
	uint8_t mmapfile[FIO_TOP_STR_MAX];
	uint32_t td_ddir;
	uint32_t rw_seq;
	uint32_t kb_base;
	uint32_t unit_base;
	uint32_t ddir_seq_nr;
	uint64_t ddir_seq_add;
	uint32_t iodepth;
	uint32_t iodepth_low;
	uint32_t iodepth_batch;
	uint32_t iodepth_batch_complete_min;
	uint32_t iodepth_batch_complete_max;
	uint32_t serialize_overlap;

	uint64_t size;
	uint64_t io_size;
	uint32_t size_percent;
	uint32_t size_nz;
	uint32_t io_size_percent;
	uint32_t io_size_nz;
	uint32_t fill_device;
	uint32_t file_append;
	uint32_t unique_filename;
	uint64_t file_size_low;
	uint64_t file_size_high;
	uint64_t start_offset;
	uint64_t start_offset_align;
	uint32_t start_offset_nz;

	uint64_t bs[DDIR_RWDIR_CNT];
	uint64_t ba[DDIR_RWDIR_CNT];
	uint64_t min_bs[DDIR_RWDIR_CNT];
	uint64_t max_bs[DDIR_RWDIR_CNT];
	struct bssplit bssplit[DDIR_RWDIR_CNT][BSSPLIT_MAX];
	uint32_t bssplit_nr[DDIR_RWDIR_CNT];

	uint32_t ignore_error[ERROR_TYPE_CNT][ERROR_STR_MAX];
	uint32_t ignore_error_nr[ERROR_TYPE_CNT];
	uint32_t error_dump;

	uint32_t nr_files;
	uint32_t open_files;
	uint32_t filetype;
	uint32_t file_lock_mode;

	uint32_t odirect;
	uint32_t oatomic;
	uint32_t invalidate_cache;
	uint32_t create_serialize;
	uint32_t create_fsync;
	uint32_t create_on_open;
	uint32_t create_only;
	uint32_t end_fsync;
	uint32_t pre_read;
	uint32_t sync_io;
	uint32_t write_hint;
	uint32_t verify;
	uint32_t do_verify;
	uint32_t verify_interval;
	uint32_t verify_offset;
	uint32_t verify_pattern_bytes;
	uint32_t verify_pattern_interval;
	uint32_t verify_fatal;
	uint32_t verify_dump;
	uint32_t verify_async;
	uint64_t verify_backlog;
	uint32_t verify_batch;
	uint32_t experimental_verify;
	uint32_t verify_state;
	uint32_t verify_state_save;
	uint32_t verify_write_sequence;
	uint32_t verify_header_seed;
	uint32_t use_thread;
	uint32_t unlink;
	uint32_t unlink_each_loop;
	uint32_t do_disk_util;
	uint32_t override_sync;
	uint32_t rand_repeatable;
	uint64_t rand_seed;
	uint32_t log_avg_msec;
	uint32_t log_hist_msec;
	uint32_t log_hist_coarseness;
	uint32_t log_max;
	uint32_t log_offset;
	uint32_t log_gz;
	uint32_t log_gz_store;
	uint32_t log_alternate_epoch;
	uint32_t log_alternate_epoch_clock_id;
	uint32_t norandommap;
	uint32_t softrandommap;
	uint32_t sprandom;
	uint32_t spr_num_regions;
	fio_fp64_t spr_over_provisioning;
	uint32_t bs_unaligned;
	uint32_t fsync_on_close;
	uint32_t bs_is_seq_rand;

	uint32_t random_distribution;
	uint32_t exitall_error;

	uint32_t sync_file_range;

	struct zone_split zone_split[DDIR_RWDIR_CNT][ZONESPLIT_MAX];
	uint32_t zone_split_nr[DDIR_RWDIR_CNT];

	fio_fp64_t zipf_theta;
	fio_fp64_t pareto_h;
	fio_fp64_t gauss_dev;
	fio_fp64_t random_center;

	uint32_t random_generator;

	uint32_t perc_rand[DDIR_RWDIR_CNT];

	uint32_t hugepage_size;
	uint64_t rw_min_bs;
	uint32_t fsync_blocks;
	uint32_t fdatasync_blocks;
	uint32_t barrier_blocks;
	uint64_t start_delay;
	uint64_t start_delay_high;
	uint64_t timeout;
	uint64_t ramp_time;
	uint64_t ramp_size;
	uint64_t ss_dur;
	uint64_t ss_ramp_time;
	uint32_t ss_state;
	fio_fp64_t ss_limit;
	uint64_t ss_check_interval;
	uint32_t overwrite;
	uint32_t bw_avg_time;
	uint32_t iops_avg_time;
	uint32_t loops;
	uint64_t zone_range;
	uint64_t zone_size;
	uint64_t zone_capacity;
	uint64_t zone_skip;
	uint64_t lockmem;
	uint32_t zone_skip_nz;
	uint32_t mem_type;
	uint32_t mem_align;

	uint32_t exit_what;
	uint32_t stonewall;
	uint32_t new_group;
	uint32_t numjobs;

	/*
	 * We currently can't convert these, so don't enable them
	 */
#if 0
	uint8_t cpumask[FIO_TOP_STR_MAX];
	uint8_t verify_cpumask[FIO_TOP_STR_MAX];
	uint8_t log_gz_cpumask[FIO_TOP_STR_MAX];
#endif
	uint32_t gpu_dev_id;
	uint32_t start_offset_percent;
	uint32_t cpus_allowed_policy;
	uint32_t iolog;
	uint32_t rwmixcycle;
	uint32_t rwmix[DDIR_RWDIR_CNT];
	uint32_t nice;
	uint32_t ioprio;
	uint32_t ioprio_class;
	uint32_t ioprio_hint;
	uint32_t file_service_type;
	uint32_t group_reporting;
	uint32_t stats;
	uint32_t fadvise_hint;
	uint32_t fallocate_mode;
	uint32_t zero_buffers;
	uint32_t refill_buffers;
	uint32_t scramble_buffers;
	uint32_t buffer_pattern_bytes;
	uint32_t compress_percentage;
	uint32_t compress_chunk;
	uint32_t dedupe_percentage;
	uint32_t dedupe_mode;
	uint32_t dedupe_working_set_percentage;
	uint32_t dedupe_global;
	uint32_t time_based;
	uint32_t disable_lat;
	uint32_t disable_clat;
	uint32_t disable_slat;
	uint32_t disable_bw;
	uint32_t unified_rw_rep;
	uint32_t gtod_reduce;
	uint32_t gtod_cpu;
	uint32_t job_start_clock_id;
	uint32_t clocksource;
	uint32_t no_stall;
	uint32_t trim_percentage;
	uint32_t trim_batch;
	uint32_t trim_zero;
	uint64_t trim_backlog;
	uint32_t clat_percentiles;
	uint32_t lat_percentiles;
	uint32_t slat_percentiles;
	uint32_t percentile_precision;
	uint32_t pad;
	fio_fp64_t percentile_list[FIO_IO_U_LIST_MAX_LEN];

	uint8_t read_iolog_file[FIO_TOP_STR_MAX];
	uint8_t write_iolog_file[FIO_TOP_STR_MAX];
	uint8_t merge_blktrace_file[FIO_TOP_STR_MAX];
	fio_fp64_t merge_blktrace_scalars[FIO_IO_U_LIST_MAX_LEN];
	fio_fp64_t merge_blktrace_iters[FIO_IO_U_LIST_MAX_LEN];

	uint32_t write_bw_log;
	uint32_t write_lat_log;
	uint32_t write_iops_log;
	uint32_t write_hist_log;

	uint8_t bw_log_file[FIO_TOP_STR_MAX];
	uint8_t lat_log_file[FIO_TOP_STR_MAX];
	uint8_t iops_log_file[FIO_TOP_STR_MAX];
	uint8_t hist_log_file[FIO_TOP_STR_MAX];
	uint8_t replay_redirect[FIO_TOP_STR_MAX];

	/*
	 * Pre-run and post-run shell
	 */
	uint8_t exec_prerun[FIO_TOP_STR_MAX];
	uint8_t exec_postrun[FIO_TOP_STR_MAX];

	uint32_t thinkcycles;

	uint32_t thinktime;
	uint32_t thinktime_spin;
	uint32_t thinktime_blocks;
	uint32_t thinktime_blocks_type;
	uint32_t thinktime_iotime;

	uint64_t rate[DDIR_RWDIR_CNT];
	uint64_t ratemin[DDIR_RWDIR_CNT];
	uint32_t ratecycle;
	uint32_t io_submit_mode;
	uint32_t rate_iops[DDIR_RWDIR_CNT];
	uint32_t rate_iops_min[DDIR_RWDIR_CNT];
	uint32_t rate_process;
	uint32_t rate_ign_think;

	uint8_t ioscheduler[FIO_TOP_STR_MAX];

	/*
	 * I/O Error handling
	 */
	uint32_t continue_on_error;

	/*
	 * Benchmark profile type
	 */
	uint8_t profile[FIO_TOP_STR_MAX];

	/*
	 * blkio cgroup support
	 */
	uint8_t cgroup[FIO_TOP_STR_MAX];
	uint32_t cgroup_weight;
	uint32_t cgroup_nodelete;

	uint32_t uid;
	uint32_t gid;

	uint32_t offset_increment_percent;
	uint32_t offset_increment_nz;
	uint64_t offset_increment;
	uint64_t number_ios;

	uint64_t latency_target;
	uint64_t latency_window;
	uint64_t max_latency[DDIR_RWDIR_CNT];
	uint32_t latency_run;
	fio_fp64_t latency_percentile;

	/*
	 * flow support
	 */
	int32_t flow_id;
	uint32_t flow;
	uint32_t flow_sleep;

	uint32_t sig_figs;

	uint32_t block_error_hist;

	uint32_t replay_align;
	uint32_t replay_scale;
	uint32_t replay_time_scale;
	uint32_t replay_skip;

	uint32_t per_job_logs;

	uint32_t allow_create;
	uint32_t allow_mounted_write;

	uint32_t zone_mode;
	int32_t max_open_zones;
	uint32_t ignore_zone_limits;
	uint32_t recover_zbd_write_error;

	uint32_t log_entries;
	uint32_t log_prio;
	uint32_t log_issue_time;

	uint32_t fdp;
	uint32_t dp_type;
	uint32_t dp_id_select;
	uint16_t dp_ids[FIO_MAX_DP_IDS];
	uint32_t dp_nr_ids;
	uint8_t dp_scheme_file[FIO_TOP_STR_MAX];

	uint32_t num_range;
	/*
	 * verify_pattern followed by buffer_pattern from the unpacked struct
	 */
	uint8_t patterns[];
} __attribute__((packed));

extern int convert_thread_options_to_cpu(struct thread_options *o,
		struct thread_options_pack *top, size_t top_sz);
extern size_t thread_options_pack_size(struct thread_options *o);
extern void convert_thread_options_to_net(struct thread_options_pack *top, struct thread_options *);
extern int fio_test_cconv(struct thread_options *);
extern void options_default_fill(struct thread_options *o);

typedef int (split_parse_fn)(struct thread_options *, void *,
			     enum fio_ddir, char *, bool);

extern int str_split_parse(struct thread_data *td, char *str,
			   split_parse_fn *fn, void *eo, bool data);

extern int split_parse_ddir(struct thread_options *o, struct split *split,
			    char *str, bool absolute, unsigned int max_splits);

extern int split_parse_prio_ddir(struct thread_options *o,
				 struct split_prio **entries, int *nr_entries,
				 char *str);

#endif
