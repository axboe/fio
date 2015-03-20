#ifndef FIO_IO_U_QUEUE
#define FIO_IO_U_QUEUE

#include <assert.h>

struct io_u;

struct io_u_queue {
	struct io_u **io_us;
	unsigned int nr;
	unsigned int max;
};

static inline struct io_u *io_u_qpop(struct io_u_queue *q)
{
	if (q->nr) {
		const unsigned int next = --q->nr;
		struct io_u *io_u = q->io_us[next];

		q->io_us[next] = NULL;
		return io_u;
	}

	return NULL;
}

static inline void io_u_qpush(struct io_u_queue *q, struct io_u *io_u)
{
	if (q->nr < q->max) {
		q->io_us[q->nr++] = io_u;
		return;
	}

	assert(0);
}

static inline int io_u_qempty(const struct io_u_queue *q)
{
	return !q->nr;
}

#define io_u_qiter(q, io_u, i)	\
	for (i = 0; i < (q)->nr && (io_u = (q)->io_us[i]); i++)

int io_u_qinit(struct io_u_queue *q, unsigned int nr);
void io_u_qexit(struct io_u_queue *q);

struct io_u_ring {
	unsigned int head;
	unsigned int tail;
	unsigned int max;
	struct io_u **ring;
};

int io_u_rinit(struct io_u_ring *ring, unsigned int nr);
void io_u_rexit(struct io_u_ring *ring);

static inline void io_u_rpush(struct io_u_ring *r, struct io_u *io_u)
{
	if (r->head + 1 != r->tail) {
		r->ring[r->head] = io_u;
		r->head = (r->head + 1) & (r->max - 1);
		return;
	}

	assert(0);
}

static inline struct io_u *io_u_rpop(struct io_u_ring *r)
{
	if (r->head != r->tail) {
		struct io_u *io_u = r->ring[r->tail];

		r->tail = (r->tail + 1) & (r->max - 1);
		return io_u;
	}

	return NULL;
}

static inline int io_u_rempty(struct io_u_ring *ring)
{
	return ring->head == ring->tail;
}

#endif
