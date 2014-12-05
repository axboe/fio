/*
  This is a maximally equidistributed combined Tausworthe generator
  based on code from GNU Scientific Library 1.5 (30 Jun 2004)

   x_n = (s1_n ^ s2_n ^ s3_n)

   s1_{n+1} = (((s1_n & 4294967294) <<12) ^ (((s1_n <<13) ^ s1_n) >>19))
   s2_{n+1} = (((s2_n & 4294967288) << 4) ^ (((s2_n << 2) ^ s2_n) >>25))
   s3_{n+1} = (((s3_n & 4294967280) <<17) ^ (((s3_n << 3) ^ s3_n) >>11))

   The period of this generator is about 2^88.

   From: P. L'Ecuyer, "Maximally Equidistributed Combined Tausworthe
   Generators", Mathematics of Computation, 65, 213 (1996), 203--213.

   This is available on the net from L'Ecuyer's home page,

   http://www.iro.umontreal.ca/~lecuyer/myftp/papers/tausme.ps
   ftp://ftp.iro.umontreal.ca/pub/simulation/lecuyer/papers/tausme.ps

   There is an erratum in the paper "Tables of Maximally
   Equidistributed Combined LFSR Generators", Mathematics of
   Computation, 68, 225 (1999), 261--269:
   http://www.iro.umontreal.ca/~lecuyer/myftp/papers/tausme2.ps

        ... the k_j most significant bits of z_j must be non-
        zero, for each j. (Note: this restriction also applies to the
        computer code given in [4], but was mistakenly not mentioned in
        that paper.)

   This affects the seeding procedure by imposing the requirement
   s1 > 1, s2 > 7, s3 > 15.

*/

#include <string.h>
#include <assert.h>
#include "rand.h"
#include "../hash.h"

static inline int __seed(unsigned int x, unsigned int m)
{
	return (x < m) ? x + m : x;
}

static void __init_rand(struct frand_state *state, unsigned int seed)
{
	int cranks = 6;

#define LCG(x, seed)  ((x) * 69069 ^ (seed))

	state->s1 = __seed(LCG((2^31) + (2^17) + (2^7), seed), 1);
	state->s2 = __seed(LCG(state->s1, seed), 7);
	state->s3 = __seed(LCG(state->s2, seed), 15);

	while (cranks--)
		__rand(state);
}

void init_rand(struct frand_state *state)
{
	__init_rand(state, 1);
}

void init_rand_seed(struct frand_state *state, unsigned int seed)
{
	__init_rand(state, seed);
}

void __fill_random_buf(void *buf, unsigned int len, unsigned long seed)
{
	void *ptr = buf;

	while (len) {
		int this_len;

		if (len >= sizeof(int64_t)) {
			*((int64_t *) ptr) = seed;
			this_len = sizeof(int64_t);
		} else if (len >= sizeof(int32_t)) {
			*((int32_t *) ptr) = seed;
			this_len = sizeof(int32_t);
		} else if (len >= sizeof(int16_t)) {
			*((int16_t *) ptr) = seed;
			this_len = sizeof(int16_t);
		} else {
			*((int8_t *) ptr) = seed;
			this_len = sizeof(int8_t);
		}
		ptr += this_len;
		len -= this_len;
		seed *= GOLDEN_RATIO_PRIME;
		seed >>= 3;
	}
}

unsigned long fill_random_buf(struct frand_state *fs, void *buf,
			      unsigned int len)
{
	unsigned long r = __rand(fs);

	if (sizeof(int) != sizeof(long *))
		r *= (unsigned long) __rand(fs);

	__fill_random_buf(buf, len, r);
	return r;
}

void fill_pattern(void *p, unsigned int len, char *pattern,
		  unsigned int pattern_bytes)
{
	switch (pattern_bytes) {
	case 0:
		assert(0);
		break;
	case 1:
		memset(p, pattern[0], len);
		break;
	default: {
		unsigned int i = 0, size = 0;
		unsigned char *b = p;

		while (i < len) {
			size = pattern_bytes;
			if (size > (len - i))
				size = len - i;
			memcpy(b+i, pattern, size);
			i += size;
		}
		break;
		}
	}
}

void __fill_random_buf_percentage(unsigned long seed, void *buf,
				  unsigned int percentage,
				  unsigned int segment, unsigned int len,
				  char *pattern, unsigned int pbytes)
{
	unsigned int this_len;

	if (percentage == 100) {
		if (pbytes)
			fill_pattern(buf, len, pattern, pbytes);
		else
			memset(buf, 0, len);
		return;
	}

	if (segment > len)
		segment = len;

	while (len) {
		/*
		 * Fill random chunk
		 */
		this_len = (segment * (100 - percentage)) / 100;
		if (this_len > len)
			this_len = len;

		__fill_random_buf(buf, this_len, seed);

		len -= this_len;
		if (!len)
			break;
		buf += this_len;

		if (this_len > len)
			this_len = len;
		else if (len - this_len <= sizeof(long))
			this_len = len;

		if (pbytes)
			fill_pattern(buf, this_len, pattern, pbytes);
		else
			memset(buf, 0, this_len);

		len -= this_len;
		buf += this_len;
	}
}

unsigned long fill_random_buf_percentage(struct frand_state *fs, void *buf,
					 unsigned int percentage,
					 unsigned int segment, unsigned int len,
					 char *pattern, unsigned int pbytes)
{
	unsigned long r = __rand(fs);

	if (sizeof(int) != sizeof(long *))
		r *= (unsigned long) __rand(fs);

	__fill_random_buf_percentage(r, buf, percentage, segment, len,
					pattern, pbytes);
	return r;
}
