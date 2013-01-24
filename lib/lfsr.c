#include <stdio.h>

#include "lfsr.h"

/*
 * From table 3 of
 *
 * http://www.xilinx.com/support/documentation/application_notes/xapp052.pdf
 */
static struct lfsr_taps lfsr_taps[] = {
	{
		.length	= 16,
		.taps	= { 16, 15, 13, 4, },
	},
	{
		.length = 17,
		.taps	= { 17, 14, },
	},
	{
		.length = 18,
		.taps	= { 18, 11, },
	},
	{
		.length	= 19,
		.taps	= { 19, 6, 2, 1, },
	},
	{
		.length	= 20,
		.taps	= { 20, 17, },
	},
	{
		.length	= 21,
		.taps	= { 21, 19, },
	},
	{
		.length	= 22,
		.taps	= { 22, 21, },
	},
	{
		.length	= 23,
		.taps	= { 23, 18, },
	},
	{
		.length = 24,
		.taps	= { 24, 23, 22, 17, },
	},
	{
		.length	= 25,
		.taps	= { 25, 22, },
	},
	{
		.length	= 26,
		.taps	= {26, 6, 2, 1, },
	},
	{
		.length	= 27,
		.taps	= { 27, 5, 2, 1, },
	},
	{
		.length	= 28,
		.taps	= { 28, 25, },
	},
	{
		.length	= 29,
		.taps	= {29, 27, },
	},
	{
		.length	= 30,
		.taps	= { 30, 6, 4, 1, },
	},
	{
		.length	= 31,
		.taps	= { 31, 28, },
	},
	{
		.length	= 32,
		.taps	= { 32, 22, 2, 1, },
	},
	{
		.length	= 33,
		.taps	= { 33, 20, },
	},
	{
		.length	= 34,
		.taps	= { 34, 27, 2, 1, },
	},
	{
		.length	= 35,
		.taps	= { 35, 33, },
	},
	{
		.length	= 36,
		.taps	= { 36, 25, },
	},
	{
		.length	= 37,
		.taps	= { 37, 5, 4, 3, 2, 1, },
	},
	{
		.length	= 38,
		.taps	= { 38, 6, 5, 1, },
	},
	{
		.length	= 39,
		.taps	= { 39, 35, },
	},
	{
		.length	= 40,
		.taps	= { 40, 38, 21, 19, },
	},
	{
		.length	= 41,
		.taps	= { 41, 38, },
	},
	{
		.length	= 42,
		.taps	= { 42, 41, 20, 19, },
	},
	{
		.length	= 43,
		.taps	= { 43, 42, 38, 37, },
	},
	{
		.length	= 44,
		.taps	= { 44, 43, 38, 37, },
	},
	{
		.length	= 45,
		.taps	= { 45, 44, 42, 41, },
	},
	{
		.length	= 46,
		.taps	= { 46, 45, 26, 25, },
	},
	{
		.length	= 47,
		.taps	= { 47, 42, },
	},
	{
		.length	= 48,
		.taps	= { 48, 47, 21, 20, },
	},
	{
		.length	= 49,
		.taps	= { 49, 40, },
	},
	{
		.length	= 50,
		.taps	= { 50, 49, 36, 35, },
	},
	{
		.length	= 51,
		.taps	= { 51, 50, 36, 35, },
	},
	{
		.length	= 52,
		.taps	= { 52, 49, },
	},
	{
		.length	= 53,
		.taps	= { 53, 52, 38, 37 },
	},
	{
		.length	= 54,
		.taps	= { 54, 53, 18, 17 },
	},
	{
		.length	= 55,
		.taps	= { 55, 31, },
	},
	{
		.length	= 56,
		.taps	= { 56, 55, 35, 34, },
	},
	{
		.length	= 57,
		.taps	= { 57, 50, },
	},
	{
		.length = 58,
		.taps	= { 58, 39, },
	},
	{
		.length	= 59,
		.taps	= { 59, 58, 38, 37, },
	},
	{
		.length	= 60,
		.taps	= { 60, 59, },
	},
	{
		.length	= 61,
		.taps	= { 61, 60, 46, 45, },
	},
	{
		.length	= 62,
		.taps	= { 62, 61, 6, 5, },
	},
	{
		.length	= 63,
		.taps	= { 63, 62, },
	},
};

#define FIO_LFSR_CRANKS		128

static uint64_t __lfsr_next(uint64_t v, struct lfsr_taps *lt)
{
	uint64_t xor_mask = 0;
	int i;

	for (i = 0; lt->taps[i]; i++)
		xor_mask ^= (v << (lt->taps[i] - 1));

	xor_mask &= ~(~0UL << 1) << (lt->length - 1);
	return xor_mask | (v >> 1);
}

int lfsr_next(struct fio_lfsr *fl, uint64_t *off, uint64_t last)
{
	if (fl->num_vals > fl->max_val)
		return 1;

	do {
		fl->last_val = __lfsr_next(fl->last_val, &fl->taps);
		if (fl->last_val - 1 <= fl->max_val &&
		    fl->last_val <= last)
			break;
	} while (1);

	*off = fl->last_val - 1;
	fl->num_vals++;
	return 0;
}

static struct lfsr_taps *find_lfsr(uint64_t size)
{
	int i;

	for (i = 0; lfsr_taps[i].length; i++)
		if (((1UL << lfsr_taps[i].length) + FIO_LFSR_CRANKS) >= size)
			return &lfsr_taps[i];

	return NULL;
}

void lfsr_reset(struct fio_lfsr *fl, unsigned long seed)
{
	unsigned int i;

	fl->last_val = seed;
	fl->num_vals = 0;

	for (i = 0; i < FIO_LFSR_CRANKS; i++)
		fl->last_val = __lfsr_next(fl->last_val, &fl->taps);
}

int lfsr_init(struct fio_lfsr *fl, uint64_t size, unsigned long seed)
{
	struct lfsr_taps *tap;
	int i;

	tap = find_lfsr(size);
	if (!tap)
		return 1;

	fl->max_val = size - 1;
	fl->taps.length = tap->length;

	for (i = 0; i < FIO_MAX_TAPS; i++) {
		fl->taps.taps[i] = tap->taps[i];
		if (!fl->taps.taps[i])
			break;
	}

	lfsr_reset(fl, seed);
	return 0;
}
