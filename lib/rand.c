#include "rand.h"

struct frand_state __fio_rand_state;

static inline int __seed(unsigned int x, unsigned int m)
{
	return (x < m) ? x + m : x;
}

void init_rand(struct frand_state *state)
{
#define LCG(x)  ((x) * 69069)   /* super-duper LCG */

	state->s1 = __seed(LCG((2^31) + (2^17) + (2^7)), 1);
	state->s2 = __seed(LCG(state->s1), 7);
	state->s3 = __seed(LCG(state->s2), 15);

	__rand(state);
	__rand(state);
	__rand(state);
	__rand(state);
	__rand(state);
	__rand(state);
}
