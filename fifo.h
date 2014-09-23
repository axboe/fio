#ifndef FIO_FIFO_H
#define FIO_FIFO_H
/*
 * A simple FIFO implementation.
 *
 * Copyright (C) 2004 Stelian Pop <stelian@popies.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */
#include "minmax.h"

struct fifo {
	unsigned char *buffer;	/* the buffer holding the data */
	unsigned int size;	/* the size of the allocated buffer */
	unsigned int in;	/* data is added at offset (in % size) */
	unsigned int out;	/* data is extracted from off. (out % size) */
};

struct fifo *fifo_alloc(unsigned int);
unsigned int fifo_put(struct fifo *, void *, unsigned int);
unsigned int fifo_get(struct fifo *, void *, unsigned int);
void fifo_free(struct fifo *);

static inline unsigned int fifo_len(struct fifo *fifo)
{
	return fifo->in - fifo->out;
}

static inline unsigned int fifo_room(struct fifo *fifo)
{
	return fifo->size - fifo->in + fifo->out;
}

#endif
