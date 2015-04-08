#ifndef FIO_GAUSS_H
#define FIO_GAUSS_H

#include <inttypes.h>
#include "rand.h"

struct gauss_state {
	struct frand_state r;
	uint64_t nranges;
	unsigned int stddev;
};

void gauss_init(struct gauss_state *gs, unsigned long nranges, double dev,
		unsigned int seed);
unsigned long long gauss_next(struct gauss_state *gs);

#endif
