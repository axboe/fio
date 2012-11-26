#ifndef FIO_LFSR_H
#define FIO_LFSR_H

#include <inttypes.h>

#define FIO_MAX_TAPS	8

struct lfsr_taps {
	unsigned int length;
	unsigned int taps[FIO_MAX_TAPS];
};


struct fio_lfsr {
	uint64_t last_val;
	uint64_t max_val;
	uint64_t num_vals;
	struct lfsr_taps taps;
};

int lfsr_next(struct fio_lfsr *fl, uint64_t *off);
int lfsr_init(struct fio_lfsr *fl, uint64_t size);

#endif
