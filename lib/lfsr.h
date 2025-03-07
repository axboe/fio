#ifndef FIO_LFSR_H
#define FIO_LFSR_H

#include <inttypes.h>

#define FIO_MAX_TAPS	6

struct lfsr_taps {
	unsigned int length;
	unsigned int taps[FIO_MAX_TAPS];
};


struct fio_lfsr {
	uint64_t xormask;
	uint64_t last_val;
	uint64_t cached_bit;
	uint64_t max_val;
	uint64_t num_vals;
	uint64_t cycle_length;
	uint64_t cached_cycle_length;
	unsigned int spin;
};

int lfsr_next(struct fio_lfsr *fl, uint64_t *off);
int lfsr_init(struct fio_lfsr *fl, uint64_t size,
	      uint64_t seed, unsigned int spin);
int lfsr_reset(struct fio_lfsr *fl, uint64_t seed);

#endif
