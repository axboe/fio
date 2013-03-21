#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "../lib/lfsr.h"

void usage()
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

	/* Read arguments */
	switch (argc) {
		case 5: if (strncmp(argv[4], "verify", 7) == 0)
					verify = 1;
		case 4: spin = atoi(argv[3]);
		case 3: seed = atol(argv[2]);
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
	printf("Max val is      %lu\n", fl->max_val);
	printf("XOR-mask is     0x%lX\n", fl->xormask);
	printf("Seed is         %lu\n", fl->last_val);
	printf("Spin is         %u\n", fl->spin);
	printf("Cycle length is %lu\n", fl->cycle_length);

	/* Create verification table */
	if (verify) {
		v_size = numbers * sizeof(uint8_t);
		v = malloc(v_size);
		memset(v, 0, v_size);
		printf("\nVerification table is %lf KBs\n", (double)(v_size) / 1024);
	}
	v_start = v;

	/*
	 * Iterate over a tight loop until we have produced all the requested
	 * numbers. Verifying the results should introduce some small yet not
	 * negligible overhead.
	 */
	fprintf(stderr, "\nTest initiated... ");
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
	while (!lfsr_next(fl, &i, fl->max_val)) {
		if (verify)
			*(uint8_t *)(v + i) += 1;
	}
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);
	fprintf(stderr, "finished.\n");


	/* Check if all expected numbers within range have been calculated */
	r = 0;
	if (verify) {
		fprintf(stderr, "Verifying results... ");
		for (i = 0; i < numbers; i++) {
			if (*(uint8_t *)(v + i) != 1) {
				fprintf(stderr, "failed (%lu = %d).\n",
						i, *(uint8_t *)(v + i));
				r = 1;
				break;
			}
		}
		if (!r)
			fprintf(stderr, "OK!\n");
	}

	/* Calculate elapsed time and mean time per number */
	total = (end.tv_sec - start.tv_sec) * pow(10,9) +
		end.tv_nsec - start.tv_nsec;
	mean = total / fl->num_vals;

	printf("\nTime results ");
	if (verify)
		printf("(slower due to verification)");
	printf("\n==============================\n");
	printf("Elapsed: %lf s\n", total / pow(10,9));
	printf("Mean:    %lf ns\n", mean);

	free(v_start);
	free(fl);
	return r;
}
