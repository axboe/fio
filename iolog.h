#ifndef FIO_IOLOG_H
#define FIO_IOLOG_H

#include "lib/rbtree.h"
#include "lib/ieee754.h"
#include "flist.h"
#include "ioengine.h"

/*
 * Use for maintaining statistics
 */
struct io_stat {
	uint64_t max_val;
	uint64_t min_val;
	uint64_t samples;

	fio_fp64_t mean;
	fio_fp64_t S;
};

/*
 * A single data sample
 */
struct io_sample {
	uint64_t time;
	uint64_t val;
	uint32_t ddir;
	uint32_t bs;
};

enum {
	IO_LOG_TYPE_LAT = 1,
	IO_LOG_TYPE_CLAT,
	IO_LOG_TYPE_SLAT,
	IO_LOG_TYPE_BW,
	IO_LOG_TYPE_IOPS,
};

/*
 * Dynamically growing data sample log
 */
struct io_log {
	/*
	 * Entries already logged
	 */
	unsigned long nr_samples;
	unsigned long max_samples;
	struct io_sample *log;

	unsigned int log_type;

	/*
	 * If we fail extending the log, stop collecting more entries.
	 */
	unsigned int disabled;

	/*
	 * Windowed average, for logging single entries average over some
	 * period of time.
	 */
	struct io_stat avg_window[DDIR_RWDIR_CNT];
	unsigned long avg_msec;
	unsigned long avg_last;
};

enum {
	IP_F_ONRB	= 1,
	IP_F_ONLIST	= 2,
	IP_F_TRIMMED	= 4,
	IP_F_IN_FLIGHT	= 8,
};

/*
 * When logging io actions, this matches a single sent io_u
 */
struct io_piece {
	union {
		struct rb_node rb_node;
		struct flist_head list;
	};
	struct flist_head trim_list;
	union {
		int fileno;
		struct fio_file *file;
	};
	unsigned long long offset;
	unsigned short numberio;
	unsigned long len;
	unsigned int flags;
	enum fio_ddir ddir;
	union {
		unsigned long delay;
		unsigned int file_action;
	};
};

/*
 * Log exports
 */
enum file_log_act {
	FIO_LOG_ADD_FILE,
	FIO_LOG_OPEN_FILE,
	FIO_LOG_CLOSE_FILE,
	FIO_LOG_UNLINK_FILE,
};

struct io_u;
extern int __must_check read_iolog_get(struct thread_data *, struct io_u *);
extern void log_io_u(struct thread_data *, struct io_u *);
extern void log_file(struct thread_data *, struct fio_file *, enum file_log_act);
extern int __must_check init_iolog(struct thread_data *td);
extern void log_io_piece(struct thread_data *, struct io_u *);
extern void unlog_io_piece(struct thread_data *, struct io_u *);
extern void trim_io_piece(struct thread_data *, struct io_u *);
extern void queue_io_piece(struct thread_data *, struct io_piece *);
extern void prune_io_piece_log(struct thread_data *);
extern void write_iolog_close(struct thread_data *);

/*
 * Logging
 */
extern void finalize_logs(struct thread_data *td);
extern void add_lat_sample(struct thread_data *, enum fio_ddir, unsigned long,
				unsigned int);
extern void add_clat_sample(struct thread_data *, enum fio_ddir, unsigned long,
				unsigned int);
extern void add_slat_sample(struct thread_data *, enum fio_ddir, unsigned long,
				unsigned int);
extern void add_bw_sample(struct thread_data *, enum fio_ddir, unsigned int,
				struct timeval *);
extern void add_iops_sample(struct thread_data *, enum fio_ddir, unsigned int,
				struct timeval *);
extern void init_disk_util(struct thread_data *);
extern void update_rusage_stat(struct thread_data *);
extern void setup_log(struct io_log **, unsigned long, int);
extern void __finish_log(struct io_log *, const char *);
extern struct io_log *agg_io_log[DDIR_RWDIR_CNT];
extern int write_bw_log;
extern void add_agg_sample(unsigned long, enum fio_ddir, unsigned int);
extern void fio_writeout_logs(struct thread_data *);

static inline void init_ipo(struct io_piece *ipo)
{
	memset(ipo, 0, sizeof(*ipo));
	INIT_FLIST_HEAD(&ipo->trim_list);
}

#endif
