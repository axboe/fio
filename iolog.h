#ifndef FIO_IOLOG_H
#define FIO_IOLOG_H

#include "lib/rbtree.h"
#include "lib/ieee754.h"
#include "flist.h"
#include "ioengines.h"

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

struct io_hist {
	uint64_t samples;
	unsigned long hist_last;
	struct flist_head list;
};


union io_sample_data {
	uint64_t val;
	struct io_u_plat_entry *plat_entry;
};

#define sample_val(value) ((union io_sample_data) { .val = value })
#define sample_plat(plat) ((union io_sample_data) { .plat_entry = plat })

/*
 * A single data sample
 */
struct io_sample {
	uint64_t time;
	union io_sample_data data;
	uint32_t __ddir;
	uint32_t bs;
};

struct io_sample_offset {
	struct io_sample s;
	uint64_t offset;
};

enum {
	IO_LOG_TYPE_LAT = 1,
	IO_LOG_TYPE_CLAT,
	IO_LOG_TYPE_SLAT,
	IO_LOG_TYPE_BW,
	IO_LOG_TYPE_IOPS,
	IO_LOG_TYPE_HIST,
};

#define DEF_LOG_ENTRIES		1024
#define MAX_LOG_ENTRIES		(1024 * DEF_LOG_ENTRIES)

struct io_logs {
	struct flist_head list;
	uint64_t nr_samples;
	uint64_t max_samples;
	void *log;
};

/*
 * Dynamically growing data sample log
 */
struct io_log {
	/*
	 * Entries already logged
	 */
	struct flist_head io_logs;
	uint32_t cur_log_max;

	/*
	 * When the current log runs out of space, store events here until
	 * we have a chance to regrow
	 */
	struct io_logs *pending;

	unsigned int log_ddir_mask;

	char *filename;

	struct thread_data *td;

	unsigned int log_type;

	/*
	 * If we fail extending the log, stop collecting more entries.
	 */
	bool disabled;

	/*
	 * Log offsets
	 */
	unsigned int log_offset;

	/*
	 * Max size of log entries before a chunk is compressed
	 */
	unsigned int log_gz;

	/*
	 * Don't deflate for storing, just store the compressed bits
	 */
	unsigned int log_gz_store;

	/*
	 * Windowed average, for logging single entries average over some
	 * period of time.
	 */
	struct io_stat avg_window[DDIR_RWDIR_CNT];
	unsigned long avg_msec;
	unsigned long avg_last;

	/*
	 * Windowed latency histograms, for keeping track of when we need to
	 * save a copy of the histogram every approximately hist_msec
	 * milliseconds.
	 */
	struct io_hist hist_window[DDIR_RWDIR_CNT];
	unsigned long hist_msec;
	unsigned int hist_coarseness;

	pthread_mutex_t chunk_lock;
	unsigned int chunk_seq;
	struct flist_head chunk_list;
};

/*
 * If the upper bit is set, then we have the offset as well
 */
#define LOG_OFFSET_SAMPLE_BIT	0x80000000U
#define io_sample_ddir(io)	((io)->__ddir & ~LOG_OFFSET_SAMPLE_BIT)

static inline void io_sample_set_ddir(struct io_log *log,
				      struct io_sample *io,
				      enum fio_ddir ddir)
{
	io->__ddir = ddir | log->log_ddir_mask;
}

static inline size_t __log_entry_sz(int log_offset)
{
	if (log_offset)
		return sizeof(struct io_sample_offset);
	else
		return sizeof(struct io_sample);
}

static inline size_t log_entry_sz(struct io_log *log)
{
	return __log_entry_sz(log->log_offset);
}

static inline size_t log_sample_sz(struct io_log *log, struct io_logs *cur_log)
{
	return cur_log->nr_samples * log_entry_sz(log);
}

static inline struct io_sample *__get_sample(void *samples, int log_offset,
					     uint64_t sample)
{
	uint64_t sample_offset = sample * __log_entry_sz(log_offset);
	return (struct io_sample *) ((char *) samples + sample_offset);
}

struct io_logs *iolog_cur_log(struct io_log *);
uint64_t iolog_nr_samples(struct io_log *);
void regrow_logs(struct thread_data *);

static inline struct io_sample *get_sample(struct io_log *iolog,
					   struct io_logs *cur_log,
					   uint64_t sample)
{
	return __get_sample(cur_log->log, iolog->log_offset, sample);
}

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
extern void log_io_u(const struct thread_data *, const struct io_u *);
extern void log_file(struct thread_data *, struct fio_file *, enum file_log_act);
extern int __must_check init_iolog(struct thread_data *td);
extern void log_io_piece(struct thread_data *, struct io_u *);
extern void unlog_io_piece(struct thread_data *, struct io_u *);
extern void trim_io_piece(struct thread_data *, const struct io_u *);
extern void queue_io_piece(struct thread_data *, struct io_piece *);
extern void prune_io_piece_log(struct thread_data *);
extern void write_iolog_close(struct thread_data *);
extern int iolog_compress_init(struct thread_data *, struct sk_out *);
extern void iolog_compress_exit(struct thread_data *);
extern size_t log_chunk_sizes(struct io_log *);

#ifdef CONFIG_ZLIB
extern int iolog_file_inflate(const char *);
#endif

/*
 * Logging
 */
struct log_params {
	struct thread_data *td;
	unsigned long avg_msec;
	unsigned long hist_msec;
	int hist_coarseness;
	int log_type;
	int log_offset;
	int log_gz;
	int log_gz_store;
	int log_compress;
};

static inline bool per_unit_log(struct io_log *log)
{
	return log && !log->avg_msec;
}

static inline bool inline_log(struct io_log *log)
{
	return log->log_type == IO_LOG_TYPE_LAT ||
		log->log_type == IO_LOG_TYPE_CLAT ||
		log->log_type == IO_LOG_TYPE_SLAT;
}

static inline void ipo_bytes_align(unsigned int replay_align, struct io_piece *ipo)
{
	if (!replay_align)
		return;

	ipo->offset &= ~(replay_align - (uint64_t)1);
}

extern void finalize_logs(struct thread_data *td, bool);
extern void setup_log(struct io_log **, struct log_params *, const char *);
extern void flush_log(struct io_log *, bool);
extern void flush_samples(FILE *, void *, uint64_t);
extern unsigned long hist_sum(int, int, unsigned int *, unsigned int *);
extern void free_log(struct io_log *);
extern void fio_writeout_logs(bool);
extern void td_writeout_logs(struct thread_data *, bool);
extern int iolog_cur_flush(struct io_log *, struct io_logs *);

static inline void init_ipo(struct io_piece *ipo)
{
	memset(ipo, 0, sizeof(*ipo));
	INIT_FLIST_HEAD(&ipo->trim_list);
}

struct iolog_compress {
	struct flist_head list;
	void *buf;
	size_t len;
	unsigned int seq;
};

#endif
