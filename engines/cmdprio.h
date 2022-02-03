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

struct cmdprio_prio {
	int32_t prio;
	uint32_t perc;
	uint16_t clat_prio_index;
};

struct cmdprio_bsprio {
	uint64_t bs;
	uint32_t tot_perc;
	unsigned int nr_prios;
	struct cmdprio_prio *prios;
};

struct cmdprio_bsprio_desc {
	struct cmdprio_bsprio *bsprios;
	unsigned int nr_bsprios;
};

struct cmdprio_options {
	unsigned int percentage[CMDPRIO_RWDIR_CNT];
	unsigned int class[CMDPRIO_RWDIR_CNT];
	unsigned int level[CMDPRIO_RWDIR_CNT];
	char *bssplit_str;
};

struct cmdprio {
	struct cmdprio_options *options;
	struct cmdprio_prio perc_entry[CMDPRIO_RWDIR_CNT];
	struct cmdprio_bsprio_desc bsprio_desc[CMDPRIO_RWDIR_CNT];
	unsigned int mode;
};

bool fio_cmdprio_set_ioprio(struct thread_data *td, struct cmdprio *cmdprio,
			    struct io_u *io_u);

void fio_cmdprio_cleanup(struct cmdprio *cmdprio);

int fio_cmdprio_init(struct thread_data *td, struct cmdprio *cmdprio,
		     struct cmdprio_options *options);

#endif
