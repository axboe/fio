#ifndef FIO_SEQLOCK_H
#define FIO_SEQLOCK_H

#include "types.h"
#include "../arch/arch.h"

struct seqlock {
#ifdef __cplusplus
	std::atomic<unsigned int> sequence;
#else
	volatile unsigned int sequence;
#endif
};

static inline void seqlock_init(struct seqlock *s)
{
	s->sequence = 0;
}

static inline unsigned int read_seqlock_begin(struct seqlock *s)
{
	unsigned int seq;

	do {
		seq = atomic_load_acquire(&s->sequence);
		if (!(seq & 1))
			break;
		nop;
	} while (1);

	return seq;
}

static inline bool read_seqlock_retry(struct seqlock *s, unsigned int seq)
{
	read_barrier();
	return s->sequence != seq;
}

static inline void write_seqlock_begin(struct seqlock *s)
{
	s->sequence = atomic_load_acquire(&s->sequence) + 1;
}

static inline void write_seqlock_end(struct seqlock *s)
{
	atomic_store_release(&s->sequence, s->sequence + 1);
}

#endif
