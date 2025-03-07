#ifndef FIO_ZIPF_H
#define FIO_ZIPF_H

#include <inttypes.h>
#include "rand.h"
#include "types.h"

struct zipf_state {
	uint64_t nranges;
	double theta;
	double zeta2;
	double zetan;
	double pareto_pow;
	struct frand_state rand;
	uint64_t rand_off;
	bool disable_hash;
};

void zipf_init(struct zipf_state *zs, uint64_t nranges, double theta,
	       double center, unsigned int seed);
uint64_t zipf_next(struct zipf_state *zs);

void pareto_init(struct zipf_state *zs, uint64_t nranges, double h,
		 double center, unsigned int seed);
uint64_t pareto_next(struct zipf_state *zs);
void zipf_disable_hash(struct zipf_state *zs);

#endif
