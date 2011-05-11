/*
 * TRIM/DISCARD support
 */
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>

#include "fio.h"
#include "trim.h"

#ifdef FIO_HAVE_TRIM
int get_next_trim(struct thread_data *td, struct io_u *io_u)
{
	struct io_piece *ipo;

	/*
	 * this io_u is from a requeue, we already filled the offsets
	 */
	if (io_u->file)
		return 0;
	if (flist_empty(&td->trim_list))
		return 1;

	assert(td->trim_entries);
	ipo = flist_entry(td->trim_list.next, struct io_piece, trim_list);
	remove_trim_entry(td, ipo);

	io_u->offset = ipo->offset;
	io_u->buflen = ipo->len;
	io_u->file = ipo->file;

	/*
	 * If not verifying that trimmed ranges return zeroed data,
	 * remove this from the to-read verify lists
	 */
	if (!td->o.trim_zero) {
		if (ipo->flags & IP_F_ONLIST)
			flist_del(&ipo->list);
		else {
			assert(ipo->flags & IP_F_ONRB);
			rb_erase(&ipo->rb_node, &td->io_hist_tree);
		}
		td->io_hist_len--;
		free(ipo);
	} else
		ipo->flags |= IP_F_TRIMMED;

	if (!fio_file_open(io_u->file)) {
		int r = td_io_open_file(td, io_u->file);

		if (r) {
			dprint(FD_VERIFY, "failed file %s open\n",
					io_u->file->file_name);
			return 1;
		}
	}

	get_file(io_u->file);
	assert(fio_file_open(io_u->file));
	io_u->ddir = DDIR_TRIM;
	io_u->xfer_buf = NULL;
	io_u->xfer_buflen = io_u->buflen;

	dprint(FD_VERIFY, "get_next_trim: ret io_u %p\n", io_u);
	return 0;
}

int io_u_should_trim(struct thread_data *td, struct io_u *io_u)
{
	unsigned long long val;
	unsigned long r;

	if (!td->o.trim_percentage)
		return 0;

	if (td->o.use_os_rand) {
		r = os_random_long(&td->trim_state);
		val = (OS_RAND_MAX / 100ULL);
	} else {
		r = __rand(&td->__trim_state);
		val = (FRAND_MAX / 100ULL);
	}

	val *= (unsigned long long) td->o.trim_percentage;
	return r <= val;
}
#endif
