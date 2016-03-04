#ifndef FIO_RAND_H
#define FIO_RAND_H

#include <inttypes.h>
#include "../arch/arch.h"

#define FRAND32_MAX	(-1U)
#define FRAND64_MAX	(-1ULL)

struct taus88_state {
	unsigned int s1, s2, s3;
};

struct taus258_state {
	uint64_t s1, s2, s3, s4, s5;
};

struct frand_state {
	unsigned int use64;
	union {
		struct taus88_state state32;
		struct taus258_state state64;
	};
};

struct frand64_state {
	uint64_t s1, s2, s3, s4, s5;
};

static inline uint64_t rand_max(struct frand_state *state)
{
	if (state->use64)
		return FRAND64_MAX;
	else
		return FRAND32_MAX;
}

static inline void __frand32_copy(struct taus88_state *dst,
				  struct taus88_state *src)
{
	dst->s1 = src->s1;
	dst->s2 = src->s2;
	dst->s3 = src->s3;
}

static inline void __frand64_copy(struct taus258_state *dst,
				  struct taus258_state *src)
{
	dst->s1 = src->s1;
	dst->s2 = src->s2;
	dst->s3 = src->s3;
	dst->s4 = src->s4;
	dst->s5 = src->s5;
}

static inline void frand_copy(struct frand_state *dst, struct frand_state *src)
{
	if (src->use64)
		__frand64_copy(&dst->state64, &src->state64);
	else
		__frand32_copy(&dst->state32, &src->state32);

	dst->use64 = src->use64;
}

static inline unsigned int __rand32(struct taus88_state *state)
{
#define TAUSWORTHE(s,a,b,c,d) ((s&c)<<d) ^ (((s <<a) ^ s)>>b)

	state->s1 = TAUSWORTHE(state->s1, 13, 19, 4294967294UL, 12);
	state->s2 = TAUSWORTHE(state->s2, 2, 25, 4294967288UL, 4);
	state->s3 = TAUSWORTHE(state->s3, 3, 11, 4294967280UL, 17);

	return (state->s1 ^ state->s2 ^ state->s3);
}

static inline uint64_t __rand64(struct taus258_state *state)
{
	uint64_t xval;

	xval = ((state->s1 <<  1) ^ state->s1) >> 53;
	state->s1 = ((state->s1 & 18446744073709551614ULL) << 10) ^ xval;

	xval = ((state->s2 << 24) ^ state->s2) >> 50;
	state->s2 = ((state->s2 & 18446744073709551104ULL) <<  5) ^ xval;

	xval = ((state->s3 <<  3) ^ state->s3) >> 23;
	state->s3 = ((state->s3 & 18446744073709547520ULL) << 29) ^ xval;

	xval = ((state->s4 <<  5) ^ state->s4) >> 24;
	state->s4 = ((state->s4 & 18446744073709420544ULL) << 23) ^ xval;

	xval = ((state->s5 <<  3) ^ state->s5) >> 33;
	state->s5 = ((state->s5 & 18446744073701163008ULL) <<  8) ^ xval;

	return (state->s1 ^ state->s2 ^ state->s3 ^ state->s4 ^ state->s5);
}

static inline uint64_t __rand(struct frand_state *state)
{
	if (state->use64)
		return __rand64(&state->state64);
	else
		return __rand32(&state->state32);
}

static inline double __rand_0_1(struct frand_state *state)
{
	if (state->use64) {
		uint64_t val = __rand64(&state->state64);

		return (val + 1.0) / (FRAND64_MAX + 1.0);
	} else {
		uint32_t val = __rand32(&state->state32);

		return (val + 1.0) / (FRAND32_MAX + 1.0);
	}
}

/*
 * Generate a random value between 'start' and 'end', both inclusive
 */
static inline int rand_between(struct frand_state *state, int start, int end)
{
	uint64_t r;

	r = __rand(state);
	return start + (int) ((double)end * (r / (rand_max(state) + 1.0)));
}

extern void init_rand(struct frand_state *, int);
extern void init_rand_seed(struct frand_state *, unsigned int seed, int);
extern void __fill_random_buf(void *buf, unsigned int len, unsigned long seed);
extern unsigned long fill_random_buf(struct frand_state *, void *buf, unsigned int len);
extern void __fill_random_buf_percentage(unsigned long, void *, unsigned int, unsigned int, unsigned int, char *, unsigned int);
extern unsigned long fill_random_buf_percentage(struct frand_state *, void *, unsigned int, unsigned int, unsigned int, char *, unsigned int);

#endif
