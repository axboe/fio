#ifndef FIO_GAUSS_H
#define FIO_GAUSS_H

#include <inttypes.h>
#include "rand.h"

struct gauss_state {
	struct frand_state r;
	uint64_t nranges;
	unsigned int stddev;
	unsigned int rand_off;
	bool disable_hash;
};

void gauss_init(struct gauss_state *gs, unsigned long nranges, double dev,
		double center, unsigned int seed);
unsigned long long gauss_next(struct gauss_state *gs);
void gauss_disable_hash(struct gauss_state *gs);

#endif
