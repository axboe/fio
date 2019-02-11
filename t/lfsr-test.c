#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

#include "../lib/lfsr.h"
#include "../gettime.h"
#include "../fio_time.h"

static void usage(void)
{
	printf("Usage: lfsr-test 0x<numbers> [seed] [spin] [verify]\n");
	printf("-------------------------------------------------------------\n");
	printf("*numbers: how many random numbers to produce (in hex)\n"
		   "seed:     initial value\n"
		   "spin:     how many iterations before we produce a number\n"
		   "verify:   check if LFSR has iterated correctly\n\n"
		   "Only <numbers> is required. The rest are evaluated to 0 or false\n"
		   "Elapsed/mean time and verification results are printed at the"
	       "end of the test\n");
}

int main(int argc, char *argv[])
{
	int r;
	struct timespec start, end;
	struct fio_lfsr *fl;
	int verify = 0;
	unsigned int spin = 0;
	uint64_t seed = 0;
	uint64_t numbers;
	uint64_t v_size;
	uint64_t i;
	void *v = NULL, *v_start;
	double total, mean;

	arch_init(argv);

	/* Read arguments */
	switch (argc) {
		case 5: if (strncmp(argv[4], "verify", 7) == 0)
				verify = 1;
			/* fall through */
		case 4: spin = atoi(argv[3]);
			/* fall through */
		case 3: seed = atol(argv[2]);
			/* fall through */
		case 2: numbers = strtol(argv[1], NULL, 16);
				break;
		default: usage();
				 return 1;
	}

	/* Initialize LFSR */
	fl = malloc(sizeof(struct fio_lfsr));
	if (!fl) {
		perror("malloc");
		return 1;
	}

	r = lfsr_init(fl, numbers, seed, spin);
	if (r) {
		printf("Initialization failed.\n");
		return r;
	}

	/* Print specs */
	printf("LFSR specs\n");
	printf("==========================\n");
	printf("Size is         %u\n", 64 - __builtin_clzl(fl->cached_bit));
	printf("Max val is      %lu\n", (unsigned long) fl->max_val);
	printf("XOR-mask is     0x%lX\n", (unsigned long) fl->xormask);
	printf("Seed is         %lu\n", (unsigned long) fl->last_val);
	printf("Spin is         %u\n", fl->spin);
	printf("Cycle length is %lu\n", (unsigned long) fl->cycle_length);

	/* Create verification table */
	if (verify) {
		v_size = numbers * sizeof(uint8_t);
		v = malloc(v_size);
		memset(v, 0, v_size);
		printf("\nVerification table is %lf KiB\n", (double)(v_size) / 1024);
	}
	v_start = v;

	/*
	 * Iterate over a tight loop until we have produced all the requested
	 * numbers. Verifying the results should introduce some small yet not
	 * negligible overhead.
	 */
	fprintf(stderr, "\nTest initiated... ");
	fio_gettime(&start, NULL);
	while (!lfsr_next(fl, &i)) {
		if (verify)
			*(uint8_t *)(v + i) += 1;
	}
	fio_gettime(&end, NULL);
	fprintf(stderr, "finished.\n");


	/* Check if all expected numbers within range have been calculated */
	r = 0;
	if (verify) {
		fprintf(stderr, "Verifying results... ");
		for (i = 0; i < numbers; i++) {
			if (*(uint8_t *)(v + i) != 1) {
				fprintf(stderr, "failed (%lu = %d).\n",
						(unsigned long) i,
						*(uint8_t *)(v + i));
				r = 1;
				break;
			}
		}
		if (!r)
			fprintf(stderr, "OK!\n");
	}

	/* Calculate elapsed time and mean time per number */
	total = utime_since(&start, &end);
	mean = total / fl->num_vals;

	printf("\nTime results ");
	if (verify)
		printf("(slower due to verification)");
	printf("\n==============================\n");
	printf("Elapsed: %lf s\n", total / pow(10,6));
	printf("Mean:    %lf us\n", mean);

	free(v_start);
	free(fl);
	return r;
}
