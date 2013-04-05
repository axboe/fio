#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include "../lib/lfsr.h"
#include "../lib/axmap.h"

void *smalloc(size_t size)
{
	return malloc(size);
}

void sfree(void *ptr)
{
	free(ptr);
}

static int test_regular(size_t size, int seed)
{
	struct fio_lfsr lfsr;
	struct axmap *map;
	size_t osize;
	uint64_t ff;
	int err;

	printf("Using %llu entries...", (unsigned long long) size);
	fflush(stdout);

	lfsr_init(&lfsr, size, seed, seed & 0xF);
	map = axmap_new(size);
	osize = size;
	err = 0;

	while (size--) {
		uint64_t val;

		if (lfsr_next(&lfsr, &val, osize)) {
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

	ff = axmap_next_free(map, osize);
	if (ff != (uint64_t) -1ULL) {
		printf("axmap_next_free broken: got %llu\n", (unsigned long long) ff);
		return 1;
	}

	printf("pass!\n");
	axmap_free(map);
	return 0;
}

static int test_multi(size_t size, unsigned int bit_off)
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

int main(int argc, char *argv[])
{
	size_t size = (1UL << 23) - 200;
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

	return 0;
}
