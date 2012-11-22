#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../arch/arch.h"
#include "bitmap.h"
#include "../smalloc.h"
#include "../minmax.h"

#if BITS_PER_LONG == 64
#define UNIT_SIZE		8
#define UNIT_SHIFT		6
#elif BITS_PER_LONG == 32
#define UNIT_SIZE		4
#define UNIT_SHIFT		5
#else
#error "Number of arch bits unknown"
#endif

#define BLOCKS_PER_UNIT		(1UL << UNIT_SHIFT)
#define BLOCKS_PER_UNIT_MASK	(BLOCKS_PER_UNIT - 1)

#define firstfree_valid(b)	((b)->first_free != (uint64_t) -1)

struct bitmap_level {
	int level;
	unsigned long map_size;
	unsigned long *map;
};

struct bitmap {
	unsigned int nr_levels;
	struct bitmap_level *levels;
	uint64_t first_free;
};

static unsigned long ulog64(unsigned long val, unsigned int log)
{
	while (log-- && val)
		val >>= UNIT_SHIFT;

	return val;
}

void bitmap_reset(struct bitmap *bitmap)
{
	int i;

	for (i = 0; i < bitmap->nr_levels; i++) {
		struct bitmap_level *bl = &bitmap->levels[i];

		memset(bl->map, 0, bl->map_size * UNIT_SIZE);
	}
}

void bitmap_free(struct bitmap *bitmap)
{
	unsigned int i;

	if (!bitmap)
		return;

	for (i = 0; i < bitmap->nr_levels; i++)
		sfree(bitmap->levels[i].map);

	sfree(bitmap->levels);
	sfree(bitmap);
}

struct bitmap *bitmap_new(unsigned long nr_bits)
{
	struct bitmap *bitmap;
	unsigned int i, levels;

	bitmap = smalloc(sizeof(*bitmap));
	if (!bitmap)
		return NULL;

	levels = 1;
	i = (nr_bits + BLOCKS_PER_UNIT - 1) >> UNIT_SHIFT;
	while (i > 1) {
		i = (i + BLOCKS_PER_UNIT - 1) >> UNIT_SHIFT;
		levels++;
	}

	bitmap->nr_levels = levels;
	bitmap->levels = smalloc(bitmap->nr_levels * sizeof(struct bitmap_level));
	bitmap->first_free = 0;

	for (i = 0; i < bitmap->nr_levels; i++) {
		struct bitmap_level *bl = &bitmap->levels[i];

		bl->level = i;
		bl->map_size = (nr_bits + BLOCKS_PER_UNIT - 1) >> UNIT_SHIFT;
		bl->map = smalloc(bl->map_size << UNIT_SHIFT);
		if (!bl->map)
			goto err;

		nr_bits = (nr_bits + BLOCKS_PER_UNIT - 1) >> UNIT_SHIFT;
	}

	bitmap_reset(bitmap);
	return bitmap;
err:
	for (i = 0; i < bitmap->nr_levels; i++)
		if (bitmap->levels[i].map)
			sfree(bitmap->levels[i].map);

	sfree(bitmap->levels);
	return NULL;
}

static int bitmap_handler(struct bitmap *bitmap, uint64_t bit_nr,
			  int (*func)(struct bitmap_level *, unsigned long, unsigned int,
			  void *), void *data)
{
	struct bitmap_level *bl;
	int i;

	for (i = 0; i < bitmap->nr_levels; i++) {
		unsigned long index = ulog64(bit_nr, i);
		unsigned long offset = index >> UNIT_SHIFT;
		unsigned int bit = index & BLOCKS_PER_UNIT_MASK;

		bl = &bitmap->levels[i];

		if (func(bl, offset, bit, data))
			return 1;
	}

	return 0;
}

static int bitmap_handler_topdown(struct bitmap *bitmap, uint64_t bit_nr,
	int (*func)(struct bitmap_level *, unsigned long, unsigned int, void *),
	void *data)
{
	struct bitmap_level *bl;
	int i, level = bitmap->nr_levels;

	for (i = bitmap->nr_levels - 1; i >= 0; i--) {
		unsigned long index = ulog64(bit_nr, --level);
		unsigned long offset = index >> UNIT_SHIFT;
		unsigned int bit = index & BLOCKS_PER_UNIT_MASK;

		bl = &bitmap->levels[i];

		if (func(bl, offset, bit, data))
			return 1;
	}

	return 0;
}

static int bitmap_clear_fn(struct bitmap_level *bl, unsigned long offset,
			   unsigned int bit, void *unused)
{
	if (!(bl->map[offset] & (1UL << bit)))
		return 1;

	bl->map[offset] &= ~(1UL << bit);
	return 0;
}

void bitmap_clear(struct bitmap *bitmap, uint64_t bit_nr)
{
	bitmap_handler(bitmap, bit_nr, bitmap_clear_fn, NULL);
}

struct bitmap_set_data {
	unsigned int nr_bits;
	unsigned int set_bits;
	unsigned int fail_ok;
};

static unsigned long bit_masks[] = {
	0x0000000000000000, 0x0000000000000001, 0x0000000000000003, 0x0000000000000007,
	0x000000000000000f, 0x000000000000001f, 0x000000000000003f, 0x000000000000007f,
	0x00000000000000ff, 0x00000000000001ff, 0x00000000000003ff, 0x00000000000007ff,
	0x0000000000000fff, 0x0000000000001fff, 0x0000000000003fff, 0x0000000000007fff,
	0x000000000000ffff, 0x000000000001ffff, 0x000000000003ffff, 0x000000000007ffff,
	0x00000000000fffff, 0x00000000001fffff, 0x00000000003fffff, 0x00000000007fffff,
	0x0000000000ffffff, 0x0000000001ffffff, 0x0000000003ffffff, 0x0000000007ffffff,
	0x000000000fffffff, 0x000000001fffffff, 0x000000003fffffff, 0x000000007fffffff,
	0x00000000ffffffff,
#if BITS_PER_LONG == 64
	0x00000001ffffffff, 0x00000003ffffffff, 0x00000007ffffffff, 0x0000000fffffffff,
	0x0000001fffffffff, 0x0000003fffffffff, 0x0000007fffffffff, 0x000000ffffffffff,
	0x000001ffffffffff, 0x000003ffffffffff, 0x000007ffffffffff, 0x00000fffffffffff,
	0x00001fffffffffff, 0x00003fffffffffff, 0x00007fffffffffff, 0x0000ffffffffffff,
	0x0001ffffffffffff, 0x0003ffffffffffff, 0x0007ffffffffffff, 0x000fffffffffffff,
	0x001fffffffffffff, 0x003fffffffffffff, 0x007fffffffffffff, 0x00ffffffffffffff,
	0x01ffffffffffffff, 0x03ffffffffffffff, 0x07ffffffffffffff, 0x0fffffffffffffff,
	0x1fffffffffffffff, 0x3fffffffffffffff, 0x7fffffffffffffff, 0xffffffffffffffff
#endif
};

static int bitmap_set_fn(struct bitmap_level *bl, unsigned long offset,
			 unsigned int bit, void *__data)
{
	struct bitmap_set_data *data = __data;
	unsigned long mask, overlap;
	unsigned int nr_bits;

	nr_bits = min(data->nr_bits, BLOCKS_PER_UNIT - bit);

	mask = bit_masks[nr_bits] << bit;

	/*
	 * Mask off any potential overlap, only sets contig regions
	 */
	overlap = bl->map[offset] & mask;
	if (overlap == mask) {
		assert(data->fail_ok);
		return 1;
	}

	while (overlap) {
		unsigned long clear_mask = ~(1UL << ffz(~overlap));

		mask &= clear_mask;
		overlap &= clear_mask;
		nr_bits--;
	}

	assert(mask);
	assert(!(bl->map[offset] & mask));
		
	bl->map[offset] |= mask;

	if (!bl->level)
		data->set_bits = nr_bits;

	data->nr_bits = 1;
	return bl->map[offset] != -1UL;
}

static void __bitmap_set(struct bitmap *bitmap, uint64_t bit_nr,
			 struct bitmap_set_data *data)
{
	unsigned int set_bits, nr_bits = data->nr_bits;

	if (bitmap->first_free >= bit_nr &&
	    bitmap->first_free < bit_nr + data->nr_bits)
		bitmap->first_free = -1ULL;

	set_bits = 0;
	while (nr_bits) {
		bitmap_handler(bitmap, bit_nr, bitmap_set_fn, data);
		set_bits += data->set_bits;

		if (data->set_bits != (BLOCKS_PER_UNIT - nr_bits))
			break;

		nr_bits -= data->set_bits;
		bit_nr += data->set_bits;

		data->nr_bits = nr_bits;
		data->fail_ok = 1;
	}

	data->set_bits = set_bits;
}

void bitmap_set(struct bitmap *bitmap, uint64_t bit_nr)
{
	struct bitmap_set_data data = { .nr_bits = 1, };

	__bitmap_set(bitmap, bit_nr, &data);
}

unsigned int bitmap_set_nr(struct bitmap *bitmap, uint64_t bit_nr, unsigned int nr_bits)
{
	struct bitmap_set_data data = { .nr_bits = nr_bits, };

	__bitmap_set(bitmap, bit_nr, &data);
	return data.set_bits;
}

static int bitmap_isset_fn(struct bitmap_level *bl, unsigned long offset,
			    unsigned int bit, void *unused)
{
	return (bl->map[offset] & (1UL << bit)) != 0;
}

int bitmap_isset(struct bitmap *bitmap, uint64_t bit_nr)
{
	return bitmap_handler_topdown(bitmap, bit_nr, bitmap_isset_fn, NULL);
}

static uint64_t bitmap_find_first_free(struct bitmap *bitmap, unsigned int level,
				       uint64_t index)
{
	unsigned long j;
	int i;

	/*
	 * Start at the bottom, then converge towards first free bit at the top
	 */
	for (i = level; i >= 0; i--) {
		struct bitmap_level *bl = &bitmap->levels[i];

		if (index >= bl->map_size) {
			index = -1ULL;
			break;
		}

		for (j = index; j < bl->map_size; j++) {
			if (bl->map[j] == -1UL)
				continue;

			/*
			 * First free bit here is our index into the first
			 * free bit at the next higher level
			 */
			index = (j << UNIT_SHIFT) + ffz(bl->map[j]);
			break;
		}
	}

	return index;
}

uint64_t bitmap_first_free(struct bitmap *bitmap)
{
	if (firstfree_valid(bitmap))
		return bitmap->first_free;

	bitmap->first_free = bitmap_find_first_free(bitmap, bitmap->nr_levels - 1, 0);
	return bitmap->first_free;
}

struct bitmap_next_free_data {
	unsigned int level;
	unsigned long offset;
	uint64_t bit;
};

static int bitmap_next_free_fn(struct bitmap_level *bl, unsigned long offset,
			       unsigned int bit, void *__data)
{
	struct bitmap_next_free_data *data = __data;
	uint64_t mask = ~((1UL << ((data->bit & BLOCKS_PER_UNIT_MASK) + 1)) - 1);

	if (!(mask & bl->map[offset]))
		return 0;

	if (bl->map[offset] != -1UL) {
		data->level = bl->level;
		data->offset = offset;
		return 1;
	}

	data->bit = (data->bit + BLOCKS_PER_UNIT - 1) / BLOCKS_PER_UNIT;
	return 0;
}

/*
 * 'bit_nr' is already set. Find the next free bit after this one.
 */
uint64_t bitmap_next_free(struct bitmap *bitmap, uint64_t bit_nr)
{
	struct bitmap_next_free_data data = { .level = -1U, .bit = bit_nr, };

	if (firstfree_valid(bitmap) && bit_nr < bitmap->first_free)
		return bitmap->first_free;

	if (!bitmap_handler(bitmap, bit_nr, bitmap_next_free_fn, &data))
		return bitmap_first_free(bitmap);

	assert(data.level != -1U);

	return bitmap_find_first_free(bitmap, data.level, data.offset);
}
