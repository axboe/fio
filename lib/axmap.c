/*
 * Bitmap of bitmaps, where each layer is number-of-bits-per-word smaller than
 * the previous. Hence an 'axmap', since we axe each previous layer into a
 * much smaller piece. I swear, that is why it's named like that. It has
 * nothing to do with anything remotely narcissistic.
 *
 * A set bit at layer N indicates a full word at layer N-1, and so forth. As
 * the bitmap becomes progressively more full, checking for existence
 * becomes cheaper (since fewer layers are walked, making it a lot more
 * cache friendly) and locating the next free space likewise.
 *
 * Axmaps get pretty close to optimal (1 bit per block) space usage, since
 * layers quickly diminish in size. Doing the size math is straight forward,
 * since we have log64(blocks) layers of maps. For 20000 blocks, overhead
 * is roughly 1.9%, or 1.019 bits per block. The number quickly converges
 * towards 1.0158, or 1.58% of overhead.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../arch/arch.h"
#include "axmap.h"
#include "../minmax.h"

#if BITS_PER_LONG == 64
#define UNIT_SHIFT		6
#elif BITS_PER_LONG == 32
#define UNIT_SHIFT		5
#else
#error "Number of arch bits unknown"
#endif

#define BLOCKS_PER_UNIT		(1U << UNIT_SHIFT)
#define BLOCKS_PER_UNIT_MASK	(BLOCKS_PER_UNIT - 1)

#define firstfree_valid(b)	((b)->first_free != (uint64_t) -1)

static const unsigned long bit_masks[] = {
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

struct axmap_level {
	int level;
	unsigned long map_size;
	unsigned long *map;
};

struct axmap {
	unsigned int nr_levels;
	struct axmap_level *levels;
	uint64_t first_free;
	uint64_t nr_bits;
};

static inline unsigned long ulog64(unsigned long val, unsigned int log)
{
	while (log-- && val)
		val >>= UNIT_SHIFT;

	return val;
}

void axmap_reset(struct axmap *axmap)
{
	int i;

	for (i = 0; i < axmap->nr_levels; i++) {
		struct axmap_level *al = &axmap->levels[i];

		memset(al->map, 0, al->map_size * sizeof(unsigned long));
	}

	axmap->first_free = 0;
}

void axmap_free(struct axmap *axmap)
{
	unsigned int i;

	if (!axmap)
		return;

	for (i = 0; i < axmap->nr_levels; i++)
		free(axmap->levels[i].map);

	free(axmap->levels);
	free(axmap);
}

struct axmap *axmap_new(unsigned long nr_bits)
{
	struct axmap *axmap;
	unsigned int i, levels;

	axmap = malloc(sizeof(*axmap));
	if (!axmap)
		return NULL;

	levels = 1;
	i = (nr_bits + BLOCKS_PER_UNIT - 1) >> UNIT_SHIFT;
	while (i > 1) {
		i = (i + BLOCKS_PER_UNIT - 1) >> UNIT_SHIFT;
		levels++;
	}

	axmap->nr_levels = levels;
	axmap->levels = calloc(axmap->nr_levels, sizeof(struct axmap_level));
	axmap->nr_bits = nr_bits;

	for (i = 0; i < axmap->nr_levels; i++) {
		struct axmap_level *al = &axmap->levels[i];

		al->level = i;
		al->map_size = (nr_bits + BLOCKS_PER_UNIT - 1) >> UNIT_SHIFT;
		al->map = malloc(al->map_size * sizeof(unsigned long));
		if (!al->map)
			goto err;

		nr_bits = (nr_bits + BLOCKS_PER_UNIT - 1) >> UNIT_SHIFT;
	}

	axmap_reset(axmap);
	return axmap;
err:
	for (i = 0; i < axmap->nr_levels; i++)
		if (axmap->levels[i].map)
			free(axmap->levels[i].map);

	free(axmap->levels);
	free(axmap);
	return NULL;
}

static bool axmap_handler(struct axmap *axmap, uint64_t bit_nr,
			  bool (*func)(struct axmap_level *, unsigned long, unsigned int,
			  void *), void *data)
{
	struct axmap_level *al;
	uint64_t index = bit_nr;
	int i;

	for (i = 0; i < axmap->nr_levels; i++) {
		unsigned long offset = index >> UNIT_SHIFT;
		unsigned int bit = index & BLOCKS_PER_UNIT_MASK;

		al = &axmap->levels[i];

		if (func(al, offset, bit, data))
			return true;

		if (index)
			index >>= UNIT_SHIFT;
	}

	return false;
}

static bool axmap_handler_topdown(struct axmap *axmap, uint64_t bit_nr,
	bool (*func)(struct axmap_level *, unsigned long, unsigned int, void *))
{
	int i;

	for (i = axmap->nr_levels - 1; i >= 0; i--) {
		unsigned long index = ulog64(bit_nr, i);
		unsigned long offset = index >> UNIT_SHIFT;
		unsigned int bit = index & BLOCKS_PER_UNIT_MASK;

		if (func(&axmap->levels[i], offset, bit, NULL))
			return true;
	}

	return false;
}

static bool axmap_clear_fn(struct axmap_level *al, unsigned long offset,
			   unsigned int bit, void *unused)
{
	if (!(al->map[offset] & (1UL << bit)))
		return true;

	al->map[offset] &= ~(1UL << bit);
	return false;
}

void axmap_clear(struct axmap *axmap, uint64_t bit_nr)
{
	axmap_handler(axmap, bit_nr, axmap_clear_fn, NULL);

	if (bit_nr < axmap->first_free)
		axmap->first_free = bit_nr;
}

struct axmap_set_data {
	unsigned int nr_bits;
	unsigned int set_bits;
};

static bool axmap_set_fn(struct axmap_level *al, unsigned long offset,
			 unsigned int bit, void *__data)
{
	struct axmap_set_data *data = __data;
	unsigned long mask, overlap;
	unsigned int nr_bits;

	nr_bits = min(data->nr_bits, BLOCKS_PER_UNIT - bit);

	mask = bit_masks[nr_bits] << bit;

	/*
	 * Mask off any potential overlap, only sets contig regions
	 */
	overlap = al->map[offset] & mask;
	if (overlap == mask) {
done:
		data->set_bits = 0;
		return true;
	}

	if (overlap) {
		const int __bit = ffz(~overlap);

		nr_bits = __bit - bit;
		if (!nr_bits)
			goto done;

		mask = bit_masks[nr_bits] << bit;
	}

	assert(mask);
	assert(!(al->map[offset] & mask));
	al->map[offset] |= mask;

	if (!al->level)
		data->set_bits = nr_bits;

	data->nr_bits = 1;
	return al->map[offset] != -1UL;
}

static void __axmap_set(struct axmap *axmap, uint64_t bit_nr,
			 struct axmap_set_data *data)
{
	unsigned int set_bits, nr_bits = data->nr_bits;

	if (axmap->first_free >= bit_nr &&
	    axmap->first_free < bit_nr + data->nr_bits)
		axmap->first_free = -1ULL;

	if (bit_nr > axmap->nr_bits)
		return;
	else if (bit_nr + nr_bits > axmap->nr_bits)
		nr_bits = axmap->nr_bits - bit_nr;

	set_bits = 0;
	while (nr_bits) {
		axmap_handler(axmap, bit_nr, axmap_set_fn, data);
		set_bits += data->set_bits;

		if (!data->set_bits ||
		    data->set_bits != (BLOCKS_PER_UNIT - nr_bits))
			break;

		nr_bits -= data->set_bits;
		bit_nr += data->set_bits;

		data->nr_bits = nr_bits;
	}

	data->set_bits = set_bits;
}

void axmap_set(struct axmap *axmap, uint64_t bit_nr)
{
	struct axmap_set_data data = { .nr_bits = 1, };

	__axmap_set(axmap, bit_nr, &data);
}

unsigned int axmap_set_nr(struct axmap *axmap, uint64_t bit_nr,
			  unsigned int nr_bits)
{
	unsigned int set_bits = 0;

	do {
		struct axmap_set_data data = { .nr_bits = nr_bits, };
		unsigned int max_bits, this_set;

		max_bits = BLOCKS_PER_UNIT - (bit_nr & BLOCKS_PER_UNIT_MASK);
		if (nr_bits > max_bits)
			data.nr_bits = max_bits;

		this_set = data.nr_bits;
		__axmap_set(axmap, bit_nr, &data);
		set_bits += data.set_bits;
		if (data.set_bits != this_set)
			break;

		nr_bits -= data.set_bits;
		bit_nr += data.set_bits;
	} while (nr_bits);

	return set_bits;
}

static bool axmap_isset_fn(struct axmap_level *al, unsigned long offset,
			   unsigned int bit, void *unused)
{
	return (al->map[offset] & (1UL << bit)) != 0;
}

bool axmap_isset(struct axmap *axmap, uint64_t bit_nr)
{
	if (bit_nr <= axmap->nr_bits)
		return axmap_handler_topdown(axmap, bit_nr, axmap_isset_fn);

	return false;
}

/*
 * Find the first free bit that is at least as large as bit_nr.  Return
 * -1 if no free bit is found before the end of the map.
 */
static uint64_t axmap_find_first_free(struct axmap *axmap, uint64_t bit_nr)
{
	int i;
	unsigned long temp;
	unsigned int bit;
	uint64_t offset, base_index, index;
	struct axmap_level *al;

	index = 0;
	for (i = axmap->nr_levels - 1; i >= 0; i--) {
		al = &axmap->levels[i];

		/* Shift previously calculated index for next level */
		index <<= UNIT_SHIFT;

		/*
		 * Start from an index that's at least as large as the
		 * originally passed in bit number.
		 */
		base_index = bit_nr >> (UNIT_SHIFT * i);
		if (index < base_index)
			index = base_index;

		/* Get the offset and bit for this level */
		offset = index >> UNIT_SHIFT;
		bit = index & BLOCKS_PER_UNIT_MASK;

		/*
		 * If the previous level had unused bits in its last
		 * word, the offset could be bigger than the map at
		 * this level. That means no free bits exist before the
		 * end of the map, so return -1.
		 */
		if (offset >= al->map_size)
			return -1ULL;

		/* Check the first word starting with the specific bit */
		temp = ~bit_masks[bit] & ~al->map[offset];
		if (temp)
			goto found;

		/*
		 * No free bit in the first word, so iterate
		 * looking for a word with one or more free bits.
		 */
		for (offset++; offset < al->map_size; offset++) {
			temp = ~al->map[offset];
			if (temp)
				goto found;
		}

		/* Did not find a free bit */
		return -1ULL;

found:
		/* Compute the index of the free bit just found */
		index = (offset << UNIT_SHIFT) + ffz(~temp);
	}

	/* If found an unused bit in the last word of level 0, return -1 */
	if (index >= axmap->nr_bits)
		return -1ULL;

	return index;
}

/*
 * 'bit_nr' is already set. Find the next free bit after this one.
 * Return -1 if no free bits found.
 */
uint64_t axmap_next_free(struct axmap *axmap, uint64_t bit_nr)
{
	uint64_t ret;
	uint64_t next_bit = bit_nr + 1;
	unsigned long temp;
	uint64_t offset;
	unsigned int bit;

	if (bit_nr >= axmap->nr_bits)
		return -1ULL;

	/* If at the end of the map, wrap-around */
	if (next_bit == axmap->nr_bits)
		next_bit = 0;

	offset = next_bit >> UNIT_SHIFT;
	bit = next_bit & BLOCKS_PER_UNIT_MASK;

	/*
	 * As an optimization, do a quick check for a free bit
	 * in the current word at level 0. If not found, do
	 * a topdown search.
	 */
	temp = ~bit_masks[bit] & ~axmap->levels[0].map[offset];
	if (temp) {
		ret = (offset << UNIT_SHIFT) + ffz(~temp);

		/* Might have found an unused bit at level 0 */
		if (ret >= axmap->nr_bits)
			ret = -1ULL;
	} else
		ret = axmap_find_first_free(axmap, next_bit);

	/*
	 * If there are no free bits starting at next_bit and going
	 * to the end of the map, wrap around by searching again
	 * starting at bit 0.
	 */
	if (ret == -1ULL && next_bit != 0)
		ret = axmap_find_first_free(axmap, 0);
	return ret;
}
