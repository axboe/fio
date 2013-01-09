#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include "../lib/lfsr.h"

struct axmap;
void axmap_set(struct axmap *, uint64_t);
struct axmap *axmap_new(uint64_t size);

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
	size_t size = (1UL << 28) - 200;
	struct axmap *map;
	int seed = 1;

	if (argc > 1) {
		size = strtoul(argv[1], NULL, 10);
		if (argc > 2)
			seed = strtoul(argv[2], NULL, 10);
	}

	printf("Using %llu entries\n", (unsigned long long) size);

	lfsr_init(&lfsr, size, seed);
	map = axmap_new(size);

	while (size--) {
		uint64_t val;

		lfsr_next(&lfsr, &val);
		axmap_set(map, val);
	}

	return 0;
}
