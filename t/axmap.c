#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "../lib/lfsr.h"
#include "../lib/axmap.h"

static int test_regular(uint64_t size, int seed)
{
	struct fio_lfsr lfsr;
	struct axmap *map;
	int err;

	printf("Using %llu entries...", (unsigned long long) size);
	fflush(stdout);

	lfsr_init(&lfsr, size, seed, seed & 0xF);
	map = axmap_new(size);
	err = 0;

	while (size--) {
		uint64_t val;

		if (lfsr_next(&lfsr, &val)) {
			printf("lfsr: short loop\n");
			err = 1;
			break;
		}
		if (axmap_isset(map, val)) {
			printf("bit already set\n");
			err = 1;
			break;
		}
		axmap_set(map, val);
		if (!axmap_isset(map, val)) {
			printf("bit not set\n");
			err = 1;
			break;
		}
	}

	if (err)
		return err;

	printf("pass!\n");
	axmap_free(map);
	return 0;
}

static int check_next_free(struct axmap *map, uint64_t start, uint64_t expected)
{

	uint64_t ff;

	ff = axmap_next_free(map, start);
	if (ff != expected) {
		printf("axmap_next_free broken: Expected %llu, got %llu\n",
				(unsigned long long)expected, (unsigned long long) ff);
		return 1;
	}
	return 0;
}

static int test_next_free(uint64_t size, int seed)
{
	struct fio_lfsr lfsr;
	struct axmap *map;
	uint64_t osize;
	uint64_t ff, lastfree;
	int err, i;

	printf("Test next_free %llu entries...", (unsigned long long) size);
	fflush(stdout);

	map = axmap_new(size);
	err = 0;


	/* Empty map.  Next free after 0 should be 1. */
	if (check_next_free(map, 0, 1))
		err = 1;

	/* Empty map.  Next free after 63 should be 64. */
	if (check_next_free(map, 63, 64))
		err = 1;

	/* Empty map.  Next free after size - 2 should be size - 1 */
	if (check_next_free(map, size - 2, size - 1))
		err = 1;

	/* Empty map.  Next free after size - 1 should be 0 */
	if (check_next_free(map, size - 1, 0))
		err = 1;

	/* Empty map.  Next free after 63 should be 64. */
	if (check_next_free(map, 63, 64))
		err = 1;


	/* Bit 63 set.  Next free after 62 should be 64. */
	axmap_set(map, 63);
	if (check_next_free(map, 62, 64))
		err = 1;

	/* Last bit set.  Next free after size - 2 should be 0. */
	axmap_set(map, size - 1);
	if (check_next_free(map, size - 2, 0))
		err = 1;

	/* Last bit set.  Next free after size - 1 should be 0. */
	if (check_next_free(map, size - 1, 0))
		err = 1;
	
	/* Last 64 bits set.  Next free after size - 66 or size - 65 should be 0. */
	for (i=size - 65; i < size; i++)
		axmap_set(map, i);
	if (check_next_free(map, size - 66, 0))
		err = 1;
	if (check_next_free(map, size - 65, 0))
		err = 1;
	
	/* Last 64 bits set.  Next free after size - 67 should be size - 66. */
	if (check_next_free(map, size - 67, size - 66))
		err = 1;

	axmap_free(map);
	
	/* Start with a fresh map and mostly fill it up */
	lfsr_init(&lfsr, size, seed, seed & 0xF);
	map = axmap_new(size);
	osize = size;

	/* Leave 1 entry free */
	size--;
	while (size--) {
		uint64_t val;

		if (lfsr_next(&lfsr, &val)) {
			printf("lfsr: short loop\n");
			err = 1;
			break;
		}
		if (axmap_isset(map, val)) {
			printf("bit already set\n");
			err = 1;
			break;
		}
		axmap_set(map, val);
		if (!axmap_isset(map, val)) {
			printf("bit not set\n");
			err = 1;
			break;
		}
	}

	/* Get last free bit */
	lastfree = axmap_next_free(map, 0);
	if (lastfree == -1ULL) {
		printf("axmap_next_free broken: Couldn't find last free bit\n");
		err = 1;
	}

	/* Start with last free bit and test wrap-around */
	ff = axmap_next_free(map, lastfree);
	if (ff != lastfree) {
		printf("axmap_next_free broken: wrap-around test #1 failed\n");
		err = 1;
	}

	/* Start with last bit and test wrap-around */
	ff = axmap_next_free(map, osize - 1);
	if (ff != lastfree) {
		printf("axmap_next_free broken: wrap-around test #2 failed\n");
		err = 1;
	}

	/* Set last free bit */
	axmap_set(map, lastfree);
	ff = axmap_next_free(map, 0);
	if (ff != -1ULL) {
		printf("axmap_next_free broken: Expected -1 from full map\n");
		err = 1;
	}

	ff = axmap_next_free(map, osize);
	if (ff != -1ULL) {
		printf("axmap_next_free broken: Expected -1 from out of bounds request\n");
		err = 1;
	}

	if (err)
		return err;

	printf("pass!\n");
	axmap_free(map);
	return 0;
}

static int test_multi(uint64_t size, unsigned int bit_off)
{
	unsigned int map_size = size;
	struct axmap *map;
	uint64_t val = bit_off;
	int i, err;

	printf("Test multi %llu entries %u offset...", (unsigned long long) size, bit_off);
	fflush(stdout);

	map = axmap_new(map_size);
	while (val + 128 <= map_size) {
		err = 0;
		for (i = val; i < val + 128; i++) {
			if (axmap_isset(map, val + i)) {
				printf("bit already set\n");
				err = 1;
				break;
			}
		}

		if (err)
			break;

		err = axmap_set_nr(map, val, 128);
		if (err != 128) {
			printf("only set %u bits\n", err);
			break;
		}

		err = 0;
		for (i = 0; i < 128; i++) {
			if (!axmap_isset(map, val + i)) {
				printf("bit not set: %llu\n", (unsigned long long) val + i);
				err = 1;
				break;
			}
		}

		val += 128;
		if (err)
			break;
	}

	if (!err)
		printf("pass!\n");

	axmap_free(map);
	return err;
}

struct overlap_test {
	unsigned int start;
	unsigned int nr;
	unsigned int ret;
};

static int test_overlap(void)
{
	struct overlap_test tests[] = {
		{
			.start	= 0,
			.nr	= 0,
			.ret	= 0,
		},
		{
			.start	= 16,
			.nr	= 16,
			.ret	= 16,
		},
		{
			.start	= 16,
			.nr	= 0,
			.ret	= 0,
		},
		{
			.start	= 0,
			.nr	= 32,
			.ret	= 16,
		},
		{
			.start	= 48,
			.nr	= 32,
			.ret	= 32,
		},
		{
			.start	= 32,
			.nr	= 32,
			.ret	= 16,
		},
		{
			.start	= 79,
			.nr	= 1,
			.ret	= 0,
		},
		{
			.start	= 80,
			.nr	= 21,
			.ret	= 21,
		},
		{
			.start	= 102,
			.nr	= 1,
			.ret	= 1,
		},
		{
			.start	= 101,
			.nr	= 3,
			.ret	= 1,
		},
		{
			.start	= 106,
			.nr	= 4,
			.ret	= 4,
		},
		{
			.start	= 105,
			.nr	= 3,
			.ret	= 1,
		},
		{
			.start	= 120,
			.nr	= 4,
			.ret	= 4,
		},
		{
			.start	= 118,
			.nr	= 2,
			.ret	= 2,
		},
		{
			.start	= 118,
			.nr	= 2,
			.ret	= 0,
		},
		{
			.start	= 1100,
			.nr	= 1,
			.ret	= 1,
		},
		{
			.start	= 1000,
			.nr	= 256,
			.ret	= 100,
		},
		{
			.start	= 22684,
			.nr	= 1,
			.ret	= 1,
		},
		{
			.start	= 22670,
			.nr	= 60,
			.ret	= 14,
		},
		{
			.start	= 22670,
			.nr	= 60,
			.ret	= 0,
		},
		{
			.start	= -1U,
		},
	};
	struct axmap *map;
	int entries, i, ret, err = 0;

	entries = 0;
	for (i = 0; tests[i].start != -1U; i++) {
		unsigned int this = tests[i].start + tests[i].nr;

		if (this > entries)
			entries = this;
	}

	printf("Test overlaps...\n");
	fflush(stdout);

	map = axmap_new(entries);

	for (i = 0; tests[i].start != -1U; i++) {
		struct overlap_test *t = &tests[i];

		printf("\tstart=%6u, nr=%3u: ", t->start, t->nr);
		ret = axmap_set_nr(map, t->start, t->nr);
		if (ret != t->ret) {
			printf("%3d (FAIL, wanted %d)\n", ret, t->ret);
			err = 1;
			break;
		}
		printf("%3d (PASS)\n", ret);
	}

	axmap_free(map);
	return err;
}

int main(int argc, char *argv[])
{
	uint64_t size = (1ULL << 23) - 200;
	int seed = 1;

	if (argc > 1) {
		size = strtoul(argv[1], NULL, 10);
		if (argc > 2)
			seed = strtoul(argv[2], NULL, 10);
	}

	if (test_regular(size, seed))
		return 1;
	if (test_multi(size, 0))
		return 2;
	if (test_multi(size, 17))
		return 3;
	if (test_overlap())
		return 4;
	if (test_next_free(size, seed))
		return 5;

	/* Test 3 levels, all full:  64*64*64 */
	if (test_next_free(64*64*64, seed))
		return 6;

	/* Test 4 levels, with 2 inner levels not full */
	if (test_next_free(((((64*64)-63)*64)-63)*64*12, seed))
		return 7;

	return 0;
}
