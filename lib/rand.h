#ifndef FIO_RAND_H
#define FIO_RAND_H

struct frand_state {
	unsigned int s1, s2, s3;
};

extern struct frand_state __fio_rand_state;

static inline unsigned int __rand(struct frand_state *state)
{
#define TAUSWORTHE(s,a,b,c,d) ((s&c)<<d) ^ (((s <<a) ^ s)>>b)

	state->s1 = TAUSWORTHE(state->s1, 13, 19, 4294967294UL, 12);
	state->s2 = TAUSWORTHE(state->s2, 2, 25, 4294967288UL, 4);
	state->s3 = TAUSWORTHE(state->s3, 3, 11, 4294967280UL, 17);

	return (state->s1 ^ state->s2 ^ state->s3);
}

extern void init_rand(struct frand_state *);
extern void fill_random_buf(void *buf, unsigned int len);

#endif
