#ifndef FIO_ZIPF_H
#define FIO_ZIPF_H

#include "rand.h"

struct zipf_state {
	uint64_t nranges;
	double theta;
	double zeta2;
	double zetan;
	struct frand_state rand;
};

void zipf_init(struct zipf_state *zs, unsigned long nranges, double theta);
unsigned long long zipf_next(struct zipf_state *zs);

#endif
