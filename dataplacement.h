#ifndef FIO_DATAPLACEMENT_H
#define FIO_DATAPLACEMENT_H

#include "io_u.h"

#define STREAMS_DIR_DTYPE	1
#define FDP_DIR_DTYPE		2
#define FIO_MAX_DP_IDS 		128
#define DP_MAX_SCHEME_ENTRIES	32

/*
 * How fio chooses what placement identifier to use next. Choice of
 * uniformly random, or roundrobin.
 */
enum {
	FIO_DP_RANDOM	= 0x1,
	FIO_DP_RR	= 0x2,
	FIO_DP_SCHEME	= 0x3,
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

struct fio_ruhs_scheme_entry {
	unsigned long long start_offset;
	unsigned long long end_offset;
	uint16_t pli;
};

struct fio_ruhs_scheme {
	uint16_t nr_schemes;
	struct fio_ruhs_scheme_entry scheme_entries[DP_MAX_SCHEME_ENTRIES];
};

int dp_init(struct thread_data *td);
void fdp_free_ruhs_info(struct fio_file *f);
void dp_fill_dspec_data(struct thread_data *td, struct io_u *io_u);

#endif /* FIO_DATAPLACEMENT_H */
