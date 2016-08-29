#ifndef FIO_TRIM_H
#define FIO_TRIM_H

#include "fio.h"

#ifdef FIO_HAVE_TRIM
extern bool __must_check get_next_trim(struct thread_data *td, struct io_u *io_u);
extern bool io_u_should_trim(struct thread_data *td, struct io_u *io_u);

/*
 * Determine whether a given io_u should be logged for verify or
 * for discard
 */
static inline void remove_trim_entry(struct thread_data *td, struct io_piece *ipo)
{
	if (!flist_empty(&ipo->trim_list)) {
		flist_del_init(&ipo->trim_list);
		td->trim_entries--;
	}
}

#else
static inline bool get_next_trim(struct thread_data *td, struct io_u *io_u)
{
	return false;
}
static inline bool io_u_should_trim(struct thread_data *td, struct io_u *io_u)
{
	return false;
}
static inline void remove_trim_entry(struct thread_data *td, struct io_piece *ipo)
{
}
#endif

#endif
