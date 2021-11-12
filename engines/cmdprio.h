/*
 * IO priority handling declarations and helper functions common to the
 * libaio and io_uring engines.
 */

#ifndef FIO_CMDPRIO_H
#define FIO_CMDPRIO_H

#include "../fio.h"

struct cmdprio {
	unsigned int percentage[DDIR_RWDIR_CNT];
	unsigned int class[DDIR_RWDIR_CNT];
	unsigned int level[DDIR_RWDIR_CNT];
	unsigned int bssplit_nr[DDIR_RWDIR_CNT];
	struct bssplit *bssplit[DDIR_RWDIR_CNT];
};

int fio_cmdprio_bssplit_parse(struct thread_data *td, const char *input,
			      struct cmdprio *cmdprio);

int fio_cmdprio_percentage(struct cmdprio *cmdprio, struct io_u *io_u);

int fio_cmdprio_init(struct thread_data *td, struct cmdprio *cmdprio,
		     bool *has_cmdprio);

#endif
