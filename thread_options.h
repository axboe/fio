#ifndef FIO_THREAD_OPTIONS_H
#define FIO_THREAD_OPTIONS_H

#include "arch/arch.h"
#include "os/os.h"
#include "stat.h"
#include "gettime.h"

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

	int flow_id;
	int flow;
	int flow_watermark;
	unsigned int flow_sleep;

	unsigned int sync_file_range;
};

#endif
