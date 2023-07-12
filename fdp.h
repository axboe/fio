#ifndef FIO_FDP_H
#define FIO_FDP_H

#include "io_u.h"

#define FDP_DIR_DTYPE	2
#define FDP_MAX_RUHS	128

/*
 * How fio chooses what placement identifier to use next. Choice of
 * uniformly random, or roundrobin.
 */

enum {
	FIO_FDP_RANDOM	= 0x1,
	FIO_FDP_RR	= 0x2,
};

struct fio_ruhs_info {
	uint32_t nr_ruhs;
	uint32_t pli_loc;
	uint16_t plis[];
};

int fdp_init(struct thread_data *td);
void fdp_free_ruhs_info(struct fio_file *f);
void fdp_fill_dspec_data(struct thread_data *td, struct io_u *io_u);

#endif /* FIO_FDP_H */
