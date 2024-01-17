#ifndef FIO_DATAPLACEMENT_H
#define FIO_DATAPLACEMENT_H

#include "io_u.h"

#define STREAMS_DIR_DTYPE	1
#define FDP_DIR_DTYPE		2
#define FDP_MAX_RUHS		128
#define FIO_MAX_DP_IDS 		16

/*
 * How fio chooses what placement identifier to use next. Choice of
 * uniformly random, or roundrobin.
 */
enum {
	FIO_DP_RANDOM	= 0x1,
	FIO_DP_RR	= 0x2,
};


enum {
	FIO_DP_NONE	= 0x0,
	FIO_DP_FDP	= 0x1,
	FIO_DP_STREAMS	= 0x2,
};

struct fio_ruhs_info {
	uint32_t nr_ruhs;
	uint32_t pli_loc;
	uint16_t plis[];
};

int dp_init(struct thread_data *td);
void fdp_free_ruhs_info(struct fio_file *f);
void dp_fill_dspec_data(struct thread_data *td, struct io_u *io_u);

#endif /* FIO_DATAPLACEMENT_H */
