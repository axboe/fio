#include <math.h>
#include <string.h>
#include "../hash.h"
#include "gauss.h"

#define GAUSS_ITERS	12

static int gauss_dev(struct gauss_state *gs)
{
	unsigned int r;
	int vr;

	if (!gs->stddev)
		return 0;

	r = __rand(&gs->r);
	vr = gs->stddev * (r / (FRAND32_MAX + 1.0));

	return vr - gs->stddev / 2;
}

unsigned long long gauss_next(struct gauss_state *gs)
{
	unsigned long long sum = 0;
	int i;

	for (i = 0; i < GAUSS_ITERS; i++)
		sum += __rand(&gs->r) % (gs->nranges + 1);

	sum = (sum + GAUSS_ITERS - 1) / GAUSS_ITERS;

	if (gs->stddev) {
		int dev = gauss_dev(gs);

		while (dev + sum >= gs->nranges)
			dev /= 2;
		sum += dev;
	}

	if (!gs->disable_hash)
		sum = __hash_u64(sum);

	return (sum + gs->rand_off) % gs->nranges;
}

void gauss_init(struct gauss_state *gs, unsigned long nranges, double dev,
		double center, unsigned int seed)
{
	memset(gs, 0, sizeof(*gs));
	init_rand_seed(&gs->r, seed, 0);
	gs->nranges = nranges;

	if (dev != 0.0) {
		gs->stddev = ceil((double)(nranges * dev) / 100.0);
		if (gs->stddev > nranges / 2)
			gs->stddev = nranges / 2;
	}
	if (center == -1)
	  gs->rand_off = 0;
	else
	  gs->rand_off = nranges * (center - 0.5);
}

void gauss_disable_hash(struct gauss_state *gs)
{
	gs->disable_hash = true;
}
