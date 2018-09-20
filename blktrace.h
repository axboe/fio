#ifndef FIO_BLKTRACE_H
#define FIO_BLKTRACE_H


#ifdef FIO_HAVE_BLKTRACE

#include "blktrace_api.h"

struct blktrace_cursor {
	struct fifo		*fifo;	// fifo queue for reading
	int			fd;	// blktrace file
	struct blk_io_trace	t;	// current io trace
	int			swap;	// bitwise reverse required
	int			scalar;	// scale percentage
};

bool is_blktrace(const char *, int *);
bool load_blktrace(struct thread_data *, const char *, int);
int merge_blktrace_iologs(struct thread_data *td);

#else

static inline bool is_blktrace(const char *fname, int *need_swap)
{
	return false;
}

static inline bool load_blktrace(struct thread_data *td, const char *fname,
				 int need_swap)
{
	return false;
}

#endif
#endif
