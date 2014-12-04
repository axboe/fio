#ifndef FIO_RAND_H
#define FIO_RAND_H

#define FRAND_MAX	(-1U)

struct frand_state {
	unsigned int s1, s2, s3;
};

static inline void frand_copy(struct frand_state *dst,
			      struct frand_state *src)
{
	dst->s1 = src->s1;
	dst->s2 = src->s2;
	dst->s3 = src->s3;
}

static inline unsigned int __rand(struct frand_state *state)
{
#define TAUSWORTHE(s,a,b,c,d) ((s&c)<<d) ^ (((s <<a) ^ s)>>b)

	state->s1 = TAUSWORTHE(state->s1, 13, 19, 4294967294UL, 12);
	state->s2 = TAUSWORTHE(state->s2, 2, 25, 4294967288UL, 4);
	state->s3 = TAUSWORTHE(state->s3, 3, 11, 4294967280UL, 17);

	return (state->s1 ^ state->s2 ^ state->s3);
}

extern void init_rand(struct frand_state *);
extern void init_rand_seed(struct frand_state *, unsigned int seed);
extern void __fill_random_buf(void *buf, unsigned int len, unsigned long seed);
extern unsigned long fill_random_buf(struct frand_state *, void *buf, unsigned int len);
extern void __fill_random_buf_percentage(unsigned long, void *, unsigned int, unsigned int, unsigned int, char *, unsigned int);
extern unsigned long fill_random_buf_percentage(struct frand_state *, void *, unsigned int, unsigned int, unsigned int, char *, unsigned int);
extern void fill_pattern(void *p, unsigned int len, char *pattern, unsigned int pattern_bytes);

#endif
