#ifndef FIO_BLKTRACE_H
#define FIO_BLKTRACE_H

#ifdef FIO_HAVE_BLKTRACE

int is_blktrace(const char *, int *);
int load_blktrace(struct thread_data *, const char *, int);

#else

static inline int is_blktrace(const char *fname, int *need_swap)
{
	return 0;
}

static inline int load_blktrace(struct thread_data *td, const char *fname,
				int need_swap)
{
	return 1;
}

#endif
#endif
