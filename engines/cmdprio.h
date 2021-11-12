/*
 * IO priority handling declarations and helper functions common to the
 * libaio and io_uring engines.
 */

#ifndef FIO_CMDPRIO_H
#define FIO_CMDPRIO_H

#include "../fio.h"

/* read and writes only, no trim */
#define CMDPRIO_RWDIR_CNT 2

struct cmdprio {
	unsigned int percentage[CMDPRIO_RWDIR_CNT];
	unsigned int class[CMDPRIO_RWDIR_CNT];
	unsigned int level[CMDPRIO_RWDIR_CNT];
	unsigned int bssplit_nr[CMDPRIO_RWDIR_CNT];
	struct bssplit *bssplit[CMDPRIO_RWDIR_CNT];
};

int fio_cmdprio_bssplit_parse(struct thread_data *td, const char *input,
			      struct cmdprio *cmdprio);

bool fio_cmdprio_set_ioprio(struct thread_data *td, struct cmdprio *cmdprio,
			    struct io_u *io_u);

int fio_cmdprio_init(struct thread_data *td, struct cmdprio *cmdprio,
		     bool *has_cmdprio);

#endif
