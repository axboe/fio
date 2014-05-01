#ifndef FIO_THREAD_OPTIONS_H
#define FIO_THREAD_OPTIONS_H

#include "arch/arch.h"
#include "os/os.h"
#include "stat.h"
#include "gettime.h"
#include "lib/ieee754.h"
#include "td_error.h"

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

#define ERROR_STR_MAX	128

#define BSSPLIT_MAX	64

struct bssplit {
	uint32_t bs;
	uint32_t perc;
};

#define OPT_MAGIC	0x4f50544e

struct thread_options {
	int magic;
	char *description;
	char *name;
	char *directory;
	char *filename;
	char *filename_format;
	char *opendir;
	char *ioengine;
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
	unsigned int iodepth_batch_complete;

	unsigned long long size;
	unsigned long long io_limit;
	unsigned int size_percent;
	unsigned int fill_device;
	unsigned int file_append;
	unsigned long long file_size_low;
	unsigned long long file_size_high;
	unsigned long long start_offset;

	unsigned int bs[DDIR_RWDIR_CNT];
	unsigned int ba[DDIR_RWDIR_CNT];
	unsigned int min_bs[DDIR_RWDIR_CNT];
	unsigned int max_bs[DDIR_RWDIR_CNT];
	struct bssplit *bssplit[DDIR_RWDIR_CNT];
	unsigned int bssplit_nr[DDIR_RWDIR_CNT];

	int *ignore_error[ERROR_TYPE_CNT];
	unsigned int ignore_error_nr[ERROR_TYPE_CNT];
	unsigned int error_dump;

	unsigned int nr_files;
	unsigned int open_files;
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
	unsigned int verify;
	unsigned int do_verify;
	unsigned int verifysort;
	unsigned int verifysort_nr;
	unsigned int verify_interval;
	unsigned int verify_offset;
	char verify_pattern[MAX_PATTERN_SIZE];
	unsigned int verify_pattern_bytes;
	unsigned int verify_fatal;
	unsigned int verify_dump;
	unsigned int verify_async;
	unsigned long long verify_backlog;
	unsigned int verify_batch;
	unsigned int experimental_verify;
	unsigned int use_thread;
	unsigned int unlink;
	unsigned int do_disk_util;
	unsigned int override_sync;
	unsigned int rand_repeatable;
	unsigned int allrand_repeatable;
	unsigned long long rand_seed;
	unsigned int use_os_rand;
	unsigned int log_avg_msec;
	unsigned int norandommap;
	unsigned int softrandommap;
	unsigned int bs_unaligned;
	unsigned int fsync_on_close;
	unsigned int bs_is_seq_rand;

	unsigned int verify_only;

	unsigned int random_distribution;

	fio_fp64_t zipf_theta;
	fio_fp64_t pareto_h;

	unsigned int random_generator;

	unsigned int perc_rand[DDIR_RWDIR_CNT];

	unsigned int hugepage_size;
	unsigned int rw_min_bs;
	unsigned int thinktime;
	unsigned int thinktime_spin;
	unsigned int thinktime_blocks;
	unsigned int fsync_blocks;
	unsigned int fdatasync_blocks;
	unsigned int barrier_blocks;
	unsigned long long start_delay;
	unsigned long long start_delay_high;
	unsigned long long timeout;
	unsigned long long ramp_time;
	unsigned int overwrite;
	unsigned int bw_avg_time;
	unsigned int iops_avg_time;
	unsigned int loops;
	unsigned long long zone_range;
	unsigned long long zone_size;
	unsigned long long zone_skip;
	unsigned long long lockmem;
	enum fio_memtype mem_type;
	unsigned int mem_align;

	unsigned int max_latency;

	unsigned int stonewall;
	unsigned int new_group;
	unsigned int numjobs;
	os_cpu_mask_t cpumask;
	unsigned int cpumask_set;
	os_cpu_mask_t verify_cpumask;
	unsigned int verify_cpumask_set;
	unsigned int cpus_allowed_policy;
	char *numa_cpunodes;
	unsigned int numa_cpumask_set;
	unsigned short numa_mem_mode;
	unsigned int numa_mem_prefer_node;
	char *numa_memnodes;
	unsigned int numa_memmask_set;
	unsigned int iolog;
	unsigned int rwmixcycle;
	unsigned int rwmix[DDIR_RWDIR_CNT];
	unsigned int nice;
	unsigned int ioprio;
	unsigned int ioprio_class;
	unsigned int file_service_type;
	unsigned int group_reporting;
	unsigned int fadvise_hint;
	enum fio_fallocate_mode fallocate_mode;
	unsigned int zero_buffers;
	unsigned int refill_buffers;
	unsigned int scramble_buffers;
	char buffer_pattern[MAX_PATTERN_SIZE];
	unsigned int buffer_pattern_bytes;
	unsigned int compress_percentage;
	unsigned int compress_chunk;
	unsigned int time_based;
	unsigned int disable_lat;
	unsigned int disable_clat;
	unsigned int disable_slat;
	unsigned int disable_bw;
	unsigned int unified_rw_rep;
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
	unsigned int percentile_precision;	/* digits after decimal for percentiles */
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

	unsigned int rate[DDIR_RWDIR_CNT];
	unsigned int ratemin[DDIR_RWDIR_CNT];
	unsigned int ratecycle;
	unsigned int rate_iops[DDIR_RWDIR_CNT];
	unsigned int rate_iops_min[DDIR_RWDIR_CNT];

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

	int flow_id;
	int flow;
	int flow_watermark;
	unsigned int flow_sleep;

	unsigned long long offset_increment;
	unsigned long long number_ios;

	unsigned int sync_file_range;

	unsigned long long latency_target;
	unsigned long long latency_window;
	fio_fp64_t latency_percentile;
};

#define FIO_TOP_STR_MAX		256

struct thread_options_pack {
	uint8_t description[FIO_TOP_STR_MAX];
	uint8_t name[FIO_TOP_STR_MAX];
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
	uint32_t iodepth_batch_complete;

	uint64_t size;
	uint64_t io_limit;
	uint32_t size_percent;
	uint32_t fill_device;
	uint32_t file_append;
	uint64_t file_size_low;
	uint64_t file_size_high;
	uint64_t start_offset;

	uint32_t bs[DDIR_RWDIR_CNT];
	uint32_t ba[DDIR_RWDIR_CNT];
	uint32_t min_bs[DDIR_RWDIR_CNT];
	uint32_t max_bs[DDIR_RWDIR_CNT];
	struct bssplit bssplit[DDIR_RWDIR_CNT][BSSPLIT_MAX];
	uint32_t bssplit_nr[DDIR_RWDIR_CNT];

	uint32_t ignore_error[ERROR_TYPE_CNT][ERROR_STR_MAX];
	uint32_t ignore_error_nr[ERROR_TYPE_CNT];
	uint32_t error_dump;

	uint32_t nr_files;
	uint32_t open_files;
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
	uint32_t verify;
	uint32_t do_verify;
	uint32_t verifysort;
	uint32_t verifysort_nr;
	uint32_t verify_interval;
	uint32_t verify_offset;
	uint8_t verify_pattern[MAX_PATTERN_SIZE];
	uint32_t verify_pattern_bytes;
	uint32_t verify_fatal;
	uint32_t verify_dump;
	uint32_t verify_async;
	uint64_t verify_backlog;
	uint32_t verify_batch;
	uint32_t experimental_verify;
	uint32_t use_thread;
	uint32_t unlink;
	uint32_t do_disk_util;
	uint32_t override_sync;
	uint32_t rand_repeatable;
	uint32_t allrand_repeatable;
	uint64_t rand_seed;
	uint32_t use_os_rand;
	uint32_t log_avg_msec;
	uint32_t norandommap;
	uint32_t softrandommap;
	uint32_t bs_unaligned;
	uint32_t fsync_on_close;
	uint32_t bs_is_seq_rand;

	uint32_t random_distribution;
	fio_fp64_t zipf_theta;
	fio_fp64_t pareto_h;

	uint32_t random_generator;

	uint32_t perc_rand[DDIR_RWDIR_CNT];

	uint32_t hugepage_size;
	uint32_t rw_min_bs;
	uint32_t thinktime;
	uint32_t thinktime_spin;
	uint32_t thinktime_blocks;
	uint32_t fsync_blocks;
	uint32_t fdatasync_blocks;
	uint32_t barrier_blocks;
	uint64_t start_delay;
	uint64_t start_delay_high;
	uint64_t timeout;
	uint64_t ramp_time;
	uint32_t overwrite;
	uint32_t bw_avg_time;
	uint32_t iops_avg_time;
	uint32_t loops;
	uint64_t zone_range;
	uint64_t zone_size;
	uint64_t zone_skip;
	uint64_t lockmem;
	uint32_t mem_type;
	uint32_t mem_align;

	uint32_t max_latency;

	uint32_t stonewall;
	uint32_t new_group;
	uint32_t numjobs;
	uint8_t cpumask[FIO_TOP_STR_MAX];
	uint32_t cpumask_set;
	uint8_t verify_cpumask[FIO_TOP_STR_MAX];
	uint32_t verify_cpumask_set;
	uint32_t cpus_allowed_policy;
	uint32_t iolog;
	uint32_t rwmixcycle;
	uint32_t rwmix[DDIR_RWDIR_CNT];
	uint32_t nice;
	uint32_t ioprio;
	uint32_t ioprio_class;
	uint32_t file_service_type;
	uint32_t group_reporting;
	uint32_t fadvise_hint;
	uint32_t fallocate_mode;
	uint32_t zero_buffers;
	uint32_t refill_buffers;
	uint32_t scramble_buffers;
	uint8_t buffer_pattern[MAX_PATTERN_SIZE];
	uint32_t buffer_pattern_bytes;
	unsigned int compress_percentage;
	unsigned int compress_chunk;
	uint32_t time_based;
	uint32_t disable_lat;
	uint32_t disable_clat;
	uint32_t disable_slat;
	uint32_t disable_bw;
	uint32_t unified_rw_rep;
	uint32_t gtod_reduce;
	uint32_t gtod_cpu;
	uint32_t gtod_offload;
	uint32_t clocksource;
	uint32_t no_stall;
	uint32_t trim_percentage;
	uint32_t trim_batch;
	uint32_t trim_zero;
	uint64_t trim_backlog;
	uint32_t clat_percentiles;
	uint32_t percentile_precision;
	fio_fp64_t percentile_list[FIO_IO_U_LIST_MAX_LEN];

	uint8_t read_iolog_file[FIO_TOP_STR_MAX];
	uint8_t write_iolog_file[FIO_TOP_STR_MAX];
	uint8_t bw_log_file[FIO_TOP_STR_MAX];
	uint8_t lat_log_file[FIO_TOP_STR_MAX];
	uint8_t iops_log_file[FIO_TOP_STR_MAX];
	uint8_t replay_redirect[FIO_TOP_STR_MAX];

	/*
	 * Pre-run and post-run shell
	 */
	uint8_t exec_prerun[FIO_TOP_STR_MAX];
	uint8_t exec_postrun[FIO_TOP_STR_MAX];

	uint32_t rate[DDIR_RWDIR_CNT];
	uint32_t ratemin[DDIR_RWDIR_CNT];
	uint32_t ratecycle;
	uint32_t rate_iops[DDIR_RWDIR_CNT];
	uint32_t rate_iops_min[DDIR_RWDIR_CNT];

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

	int32_t flow_id;
	int32_t flow;
	int32_t flow_watermark;
	uint32_t flow_sleep;

	uint64_t offset_increment;
	uint64_t number_ios;

	uint32_t sync_file_range;

	uint64_t latency_target;
	uint64_t latency_window;
	fio_fp64_t latency_percentile;
} __attribute__((packed));

extern void convert_thread_options_to_cpu(struct thread_options *o, struct thread_options_pack *top);
extern void convert_thread_options_to_net(struct thread_options_pack *top, struct thread_options *);
extern int fio_test_cconv(struct thread_options *);
extern void options_default_fill(struct thread_options *o);

#endif
