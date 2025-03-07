#ifndef FIO_BLKTRACE_H
#define FIO_BLKTRACE_H


#ifdef FIO_HAVE_BLKTRACE

#include <asm/types.h>

#include "blktrace_api.h"

struct blktrace_cursor {
	struct fifo		*fifo;	// fifo queue for reading
	FILE			*f;	// blktrace file
	__u64			length; // length of trace
	struct blk_io_trace	t;	// current io trace
	int			swap;	// bitwise reverse required
	int			scalar;	// scale percentage
	int			iter;	// current iteration
	int			nr_iter; // number of iterations to run
};

bool is_blktrace(const char *, int *);
bool init_blktrace_read(struct thread_data *, const char *, int);
bool read_blktrace(struct thread_data* td);

int merge_blktrace_iologs(struct thread_data *td);

#else

static inline bool is_blktrace(const char *fname, int *need_swap)
{
	return false;
}

static inline bool init_blktrace_read(struct thread_data *td, const char *fname,
				 int need_swap)
{
	return false;
}

static inline bool read_blktrace(struct thread_data* td)
{
	return false;
}


static inline int merge_blktrace_iologs(struct thread_data *td)
{
	return false;
}

#endif
#endif
