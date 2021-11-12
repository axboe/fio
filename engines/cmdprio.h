/*
 * IO priority handling declarations and helper functions common to the
 * libaio and io_uring engines.
 */

#ifndef FIO_CMDPRIO_H
#define FIO_CMDPRIO_H

#include "../fio.h"

/* read and writes only, no trim */
#define CMDPRIO_RWDIR_CNT 2

enum {
	CMDPRIO_MODE_NONE,
	CMDPRIO_MODE_PERC,
	CMDPRIO_MODE_BSSPLIT,
};

struct cmdprio_options {
	unsigned int percentage[CMDPRIO_RWDIR_CNT];
	unsigned int class[CMDPRIO_RWDIR_CNT];
	unsigned int level[CMDPRIO_RWDIR_CNT];
	char *bssplit_str;
};

struct cmdprio {
	struct cmdprio_options *options;
	unsigned int bssplit_nr[CMDPRIO_RWDIR_CNT];
	struct bssplit *bssplit[CMDPRIO_RWDIR_CNT];
	unsigned int mode;
};

bool fio_cmdprio_set_ioprio(struct thread_data *td, struct cmdprio *cmdprio,
			    struct io_u *io_u);

void fio_cmdprio_cleanup(struct cmdprio *cmdprio);

int fio_cmdprio_init(struct thread_data *td, struct cmdprio *cmdprio,
		     struct cmdprio_options *options);

#endif
