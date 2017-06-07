#include "fio.h"
#include "io_ddir.h"
#include "td_error.h"

static int __NON_FATAL_ERR[] = { EIO, EILSEQ };

enum error_type_bit td_error_type(enum fio_ddir ddir, int err)
{
	if (err == EILSEQ)
		return ERROR_TYPE_VERIFY_BIT;
	if (ddir == DDIR_READ)
		return ERROR_TYPE_READ_BIT;
	return ERROR_TYPE_WRITE_BIT;
}

int td_non_fatal_error(struct thread_data *td, enum error_type_bit etype,
		       int err)
{
	unsigned int i;

	if (!td->o.ignore_error[etype]) {
		td->o.ignore_error[etype] = __NON_FATAL_ERR;
		td->o.ignore_error_nr[etype] = ARRAY_SIZE(__NON_FATAL_ERR);
	}

	if (!(td->o.continue_on_error & (1 << etype)))
		return 0;
	for (i = 0; i < td->o.ignore_error_nr[etype]; i++)
		if (td->o.ignore_error[etype][i] == err)
			return 1;

	return 0;
}

void update_error_count(struct thread_data *td, int err)
{
	td->total_err_count++;
	if (td->total_err_count == 1)
		td->first_error = err;
}
