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

int main(int argc, char *argv[])
{
	struct fio_lfsr lfsr;
	size_t osize, size = (1UL << 28) - 200;
	struct axmap *map;
	uint64_t ff;
	int seed = 1;

	if (argc > 1) {
		size = strtoul(argv[1], NULL, 10);
		if (argc > 2)
			seed = strtoul(argv[2], NULL, 10);
	}

	printf("Using %llu entries\n", (unsigned long long) size);

	lfsr_init(&lfsr, size, seed, seed & 0xF);
	map = axmap_new(size);
	osize = size;

	while (size--) {
		uint64_t val;

		if (lfsr_next(&lfsr, &val, osize)) {
			printf("lfsr: short loop\n");
			break;
		}
		if (axmap_isset(map, val)) {
			printf("bit already set\n");
			break;
		}
		axmap_set(map, val);
		if (!axmap_isset(map, val)) {
			printf("bit not set\n");
			break;
		}
	}

	ff = axmap_next_free(map, osize);
	if (ff != (uint64_t) -1ULL) {
		printf("axmap_next_free broken: got %llu\n", (unsigned long long) ff);
		return 1;
	}

	return 0;
}
