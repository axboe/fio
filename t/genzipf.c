/*
 * Generate/analyze pareto/zipf distributions to better understand
 * what an access pattern would look like.
 *
 * For instance, the following would generate a zipf distribution
 * with theta 1.2, using 100,000 values and split the reporting into
 * 20 buckets:
 *
 *	t/genzipf zipf 1.2 100000 20
 *
 * Only the distribution type (zipf or pareto) and spread input need
 * to be given, if not given defaults are used.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>

#include "../lib/zipf.h"

#define DEF_NR		1000000
#define DEF_NR_OUTPUT	23

static int val_cmp(const void *p1, const void *p2)
{
	const unsigned long *v1 = p1;
	const unsigned long *v2 = p2;

	return *v1 - *v2;
}

int main(int argc, char *argv[])
{
	unsigned long nranges, output_nranges;
	unsigned long *vals;
	unsigned long i, j, nr_vals, cur_vals, max_val, interval;
	double *output, perc, perc_i;
	struct zipf_state zs;
	int use_zipf;
	double val;

	if (argc < 3) {
		printf("%s: {zipf,pareto} val values [output ranges]\n", argv[0]);
		return 1;
	}

	if (!strcmp(argv[1], "zipf"))
		use_zipf = 1;
	else if (!strcmp(argv[1], "pareto"))
		use_zipf = 0;
	else {
		printf("Bad distribution type <%s>\n", argv[1]);
		return 1;
	}

	val = atof(argv[2]);

	nranges = DEF_NR;
	output_nranges = DEF_NR_OUTPUT;

	if (argc >= 4)
		nranges = strtoul(argv[3], NULL, 10);
	if (argc >= 5)
		output_nranges = strtoul(argv[4], NULL, 10);

	printf("Generating %s distribution with %f input and %lu ranges.\n", use_zipf ? "zipf" : "pareto", val, nranges);

	if (use_zipf)
		zipf_init(&zs, nranges, val);
	else
		pareto_init(&zs, nranges, val);

	vals = malloc(nranges * sizeof(unsigned long));

	max_val = nr_vals = 0;
	for (i = 0; i < nranges; i++) {
		if (use_zipf)
			vals[nr_vals] = zipf_next(&zs);
		else
			vals[nr_vals] = pareto_next(&zs);

		if (vals[nr_vals] > max_val)
			max_val = vals[nr_vals];
		nr_vals++;
	}

	qsort(vals, nr_vals, sizeof(unsigned long), val_cmp);

	interval = (max_val + output_nranges - 1) / output_nranges;

	output = malloc(output_nranges * sizeof(double));

	for (i = j = 0, cur_vals = 0; i < nr_vals; i++) {
		if (vals[i] > interval) {
			output[j] = (double) (cur_vals + 1) / (double) nr_vals;
			output[j] *= 100.0;
			j++;
			cur_vals = 0;
			interval += (max_val + output_nranges - 1) / output_nranges;
			continue;
		}
		cur_vals++;
	}

	if (cur_vals) {
		output[j] = (double) (cur_vals + 1) / (double) nr_vals;
		output[j] *= 100.0;
		j++;
	}

	perc_i = 100.0 / (double) output_nranges;
	perc = 0.0;
	for (i = 0; i < j; i++) {
		printf("%6.2f%% -> %6.2f%%:\t%6.2f%%\n",  perc, perc + perc_i, output[i]);
		perc += perc_i;
	}

	free(output);
	free(vals);
	return 0;
}
