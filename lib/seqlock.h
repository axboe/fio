#ifndef FIO_SEQLOCK_H
#define FIO_SEQLOCK_H

#include "types.h"
#include "../arch/arch.h"

struct seqlock {
	volatile int sequence;
};

static inline void seqlock_init(struct seqlock *s)
{
	s->sequence = 0;
}

static inline unsigned int read_seqlock_begin(struct seqlock *s)
{
	unsigned int seq;

	do {
		seq = s->sequence;
		if (!(seq & 1))
			break;
		nop;
	} while (1);

	read_barrier();
	return seq;
}

static inline bool read_seqlock_retry(struct seqlock *s, unsigned int seq)
{
	read_barrier();
	return s->sequence != seq;
}

static inline void write_seqlock_begin(struct seqlock *s)
{
	s->sequence++;
	write_barrier();
}

static inline void write_seqlock_end(struct seqlock *s)
{
	write_barrier();
	s->sequence++;
}

#endif
