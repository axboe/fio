#include <math.h>
#include <string.h>
#include "zipf.h"
#include "../minmax.h"
#include "../hash.h"

#define ZIPF_MAX_GEN	10000000UL

static void zipf_update(struct zipf_state *zs)
{
	uint64_t to_gen;
	unsigned int i;

	/*
	 * It can become very costly to generate long sequences. Just cap it at
	 * 10M max, that should be doable in 1-2s on even slow machines.
	 * Precision will take a slight hit, but nothing major.
	 */
	to_gen = min(zs->nranges, (uint64_t) ZIPF_MAX_GEN);

	for (i = 0; i < to_gen; i++)
		zs->zetan += pow(1.0 / (double) (i + 1), zs->theta);
}

static void shared_rand_init(struct zipf_state *zs, uint64_t nranges,
			     double center, unsigned int seed)
{
	memset(zs, 0, sizeof(*zs));
	zs->nranges = nranges;

	init_rand_seed(&zs->rand, seed, 0);
	zs->rand_off = __rand(&zs->rand);
	if (center != -1)
		zs->rand_off = nranges * center;
}

void zipf_init(struct zipf_state *zs, uint64_t nranges, double theta,
	       double center, unsigned int seed)
{
	shared_rand_init(zs, nranges, center, seed);

	zs->theta = theta;
	zs->zeta2 = pow(1.0, zs->theta) + pow(0.5, zs->theta);

	zipf_update(zs);
}

uint64_t zipf_next(struct zipf_state *zs)
{
	double alpha, eta, rand_uni, rand_z;
	unsigned long long n = zs->nranges;
	unsigned long long val;

	alpha = 1.0 / (1.0 - zs->theta);
	eta = (1.0 - pow(2.0 / n, 1.0 - zs->theta)) / (1.0 - zs->zeta2 / zs->zetan);

	rand_uni = (double) __rand(&zs->rand) / (double) FRAND32_MAX;
	rand_z = rand_uni * zs->zetan;

	if (rand_z < 1.0)
		val = 1;
	else if (rand_z < (1.0 + pow(0.5, zs->theta)))
		val = 2;
	else
		val = 1 + (unsigned long long)(n * pow(eta*rand_uni - eta + 1.0, alpha));

	val--;

	if (!zs->disable_hash)
		val = __hash_u64(val);

	return (val + zs->rand_off) % zs->nranges;
}

void pareto_init(struct zipf_state *zs, uint64_t nranges, double h,
		 double center, unsigned int seed)
{
	shared_rand_init(zs, nranges, center, seed);
	zs->pareto_pow = log(h) / log(1.0 - h);
}

uint64_t pareto_next(struct zipf_state *zs)
{
	double rand = (double) __rand(&zs->rand) / (double) FRAND32_MAX;
	unsigned long long n;

	n = (zs->nranges - 1) * pow(rand, zs->pareto_pow);

	if (!zs->disable_hash)
		n = __hash_u64(n);

	return (n + zs->rand_off)  % zs->nranges;
}

void zipf_disable_hash(struct zipf_state *zs)
{
	zs->disable_hash = true;
}
