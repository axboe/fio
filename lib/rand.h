#ifndef FIO_RAND_H
#define FIO_RAND_H

#include <inttypes.h>
#include <assert.h>
#include <stdio.h>
#ifdef CONFIG_ARCH_AES
#include <xmmintrin.h>
#endif
#include "types.h"

extern int arch_random, arch_aes;

#define FRAND32_MAX	(-1U)
#define FRAND32_MAX_PLUS_ONE	(1.0 * (1ULL << 32))
#define FRAND64_MAX	(-1ULL)
#define FRAND64_MAX_PLUS_ONE	(1.0 * (1ULL << 32) * (1ULL << 32))

enum fio_rand_type {
	FIO_RAND_32,
	FIO_RAND_64,
	FIO_RAND_AES,
};

struct taus88_state {
	unsigned int s1, s2, s3;
};

struct taus258_state {
	uint64_t s1, s2, s3, s4, s5;
};

struct frand_state {
	enum fio_rand_type rand_type;
	union {
		struct taus88_state state32;
		struct taus258_state state64;
	};
#ifdef CONFIG_ARCH_AES
	__m128i aes_key;
	__m128i aes_accum;
#endif
};

static inline uint64_t rand_max(struct frand_state *state)
{
	switch (state->rand_type) {
	case FIO_RAND_64:
		return FRAND64_MAX;
	case FIO_RAND_32:
		return FRAND32_MAX;
	default:
		return ~0UL;
	}
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

static inline void __frand_aes_copy(struct frand_state *dst,
				    struct frand_state *src)
{
#ifdef CONFIG_ARCH_AES
	dst->aes_key = src->aes_key;
	dst->aes_accum = src->aes_accum;
#endif
}

static inline void frand_copy(struct frand_state *dst, struct frand_state *src)
{
	switch (src->rand_type) {
	case FIO_RAND_64:
		__frand64_copy(&dst->state64, &src->state64);
		break;
	case FIO_RAND_32:
		__frand32_copy(&dst->state32, &src->state32);
		break;
	case FIO_RAND_AES:
		__frand_aes_copy(dst, src);
		break;
	}
	dst->rand_type = src->rand_type;
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
	switch (state->rand_type) {
	case FIO_RAND_64:
		return __rand64(&state->state64);
	case FIO_RAND_32:
		return __rand32(&state->state32);
	default:
		return 0;
	}
}

static inline double __rand_0_1(struct frand_state *state)
{
	switch (state->rand_type) {
	case FIO_RAND_64: {
		uint64_t val = __rand64(&state->state64);

		return (val + 1.0) / FRAND64_MAX_PLUS_ONE;
		}
	case FIO_RAND_32: {
		uint32_t val = __rand32(&state->state32);

		return (val + 1.0) / FRAND32_MAX_PLUS_ONE;
		}
	default:
		fprintf(stderr, "fio: illegal rand type for 0..1 generation\n");
		return 0.0;
	}
}

static inline uint32_t rand32_upto(struct frand_state *state, uint32_t end)
{
	uint32_t r;

	assert(state->rand_type == FIO_RAND_32);

	r = __rand32(&state->state32);
	end++;
	return (int) ((double)end * (r / FRAND32_MAX_PLUS_ONE));
}

static inline uint64_t rand64_upto(struct frand_state *state, uint64_t end)
{
	uint64_t r;

	assert(state->rand_type == FIO_RAND_64);

	r = __rand64(&state->state64);
	end++;
	return (uint64_t) ((double)end * (r / FRAND64_MAX_PLUS_ONE));
}

/*
 * Generate a random value between 'start' and 'end', both inclusive
 */
static inline uint64_t rand_between(struct frand_state *state, uint64_t start,
				    uint64_t end)
{
	switch (state->rand_type) {
	case FIO_RAND_64:
		return start + rand64_upto(state, end - start);
	case FIO_RAND_32:
		return start + rand32_upto(state, end - start);
	default:
		fprintf(stderr, "fio: illegal rand type for rand_between\n");
		return start;
	}
}

static inline uint64_t __get_next_seed(struct frand_state *fs)
{
	uint64_t r = __rand(fs);

	if (sizeof(int) != sizeof(long *))
		r *= (unsigned long) __rand(fs);

	return r;
}

extern void init_rand(struct frand_state *, enum fio_rand_type);
extern void init_rand_seed(struct frand_state *, uint64_t seed, enum fio_rand_type);
void __init_rand64(struct taus258_state *state, uint64_t seed);
extern void __fill_random_buf(void *buf, unsigned int len, uint64_t seed);
extern uint64_t fill_random_buf(struct frand_state *, void *buf, unsigned int len);
extern void __fill_random_buf_percentage(uint64_t, void *, unsigned int, unsigned int, unsigned int, char *, unsigned int);
extern uint64_t fill_random_buf_percentage(struct frand_state *, void *, unsigned int, unsigned int, unsigned int, char *, unsigned int);

#ifdef CONFIG_ARCH_AES
void fill_random_buf_aes(struct frand_state *, void *, unsigned int);
void aes_seed(struct frand_state *, unsigned int);
#endif

#endif
