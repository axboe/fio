#include <stdlib.h>
#include "io_u_queue.h"

int io_u_qinit(struct io_u_queue *q, unsigned int nr)
{
	q->io_us = calloc(nr, sizeof(struct io_u *));
	if (!q->io_us)
		return 1;

	q->nr = 0;
	q->max = nr;
	return 0;
}

void io_u_qexit(struct io_u_queue *q)
{
	free(q->io_us);
}

int io_u_rinit(struct io_u_ring *ring, unsigned int nr)
{
	ring->max = nr + 1;
	if (ring->max & (ring->max - 1)) {
		ring->max--;
		ring->max |= ring->max >> 1;
		ring->max |= ring->max >> 2;
		ring->max |= ring->max >> 4;
		ring->max |= ring->max >> 8;
		ring->max |= ring->max >> 16;
		ring->max++;
	}

	ring->ring = calloc(ring->max, sizeof(struct io_u *));
	if (!ring->ring)
		return 1;

	ring->head = ring->tail = 0;
	return 0;
}

void io_u_rexit(struct io_u_ring *ring)
{
	free(ring->ring);
}
