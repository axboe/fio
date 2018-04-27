#ifndef FIO_BLKTRACE_H
#define FIO_BLKTRACE_H

#ifdef FIO_HAVE_BLKTRACE

bool is_blktrace(const char *, int *);
bool load_blktrace(struct thread_data *, const char *, int);

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
