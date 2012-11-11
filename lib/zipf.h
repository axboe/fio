#ifndef FIO_ZIPF_H
#define FIO_ZIPF_H

#include <inttypes.h>
#include "rand.h"

struct zipf_state {
	uint64_t nranges;
	double theta;
	double zeta2;
	double zetan;
	double pareto_pow;
	struct frand_state rand;
	uint64_t rand_off;
};

void zipf_init(struct zipf_state *zs, unsigned long nranges, double theta, unsigned int seed);
unsigned long long zipf_next(struct zipf_state *zs);

void pareto_init(struct zipf_state *zs, unsigned long nranges, double h, unsigned int seed);
unsigned long long pareto_next(struct zipf_state *zs);

#endif
