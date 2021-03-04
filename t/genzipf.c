/*
 * Generate/analyze pareto/zipf distributions to better understand
 * what an access pattern would look like.
 *
 * For instance, the following would generate a zipf distribution
 * with theta 1.2, using 262144 (1 GiB / 4096) values and split the
 * reporting into 20 buckets:
 *
 *	./t/fio-genzipf -t zipf -i 1.2 -g 1 -b 4096 -o 20
 *
 * Only the distribution type (zipf or pareto) and spread input need
 * to be given, if not given defaults are used.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../lib/zipf.h"
#include "../lib/gauss.h"
#include "../flist.h"
#include "../hash.h"

#define DEF_NR_OUTPUT	20

struct node {
	struct flist_head list;
	unsigned long long val;
	unsigned long hits;
};

static struct flist_head *hash;
static unsigned long hash_bits = 24;
static unsigned long hash_size = 1 << 24;

enum {
	TYPE_NONE = 0,
	TYPE_ZIPF,
	TYPE_PARETO,
	TYPE_NORMAL,
};
static const char *dist_types[] = { "None", "Zipf", "Pareto", "Normal" };

enum {
	OUTPUT_NORMAL,
	OUTPUT_CSV,
};

static int dist_type = TYPE_ZIPF;
static unsigned long gib_size = 500;
static unsigned long block_size = 4096;
static unsigned long output_nranges = DEF_NR_OUTPUT;
static double percentage;
static double dist_val;
static int output_type = OUTPUT_NORMAL;

#define DEF_ZIPF_VAL	1.2
#define DEF_PARETO_VAL	0.3

static unsigned int hashv(unsigned long long val)
{
	return jhash(&val, sizeof(val), 0) & (hash_size - 1);
}

static struct node *hash_lookup(unsigned long long val)
{
	struct flist_head *l = &hash[hashv(val)];
	struct flist_head *entry;
	struct node *n;

	flist_for_each(entry, l) {
		n = flist_entry(entry, struct node, list);
		if (n->val == val)
			return n;
	}

	return NULL;
}

static void hash_insert(struct node *n, unsigned long long val)
{
	struct flist_head *l = &hash[hashv(val)];

	n->val = val;
	n->hits = 1;
	flist_add_tail(&n->list, l);
}

static void usage(void)
{
	printf("genzipf: test zipf/pareto values for fio input\n");
	printf("\t-h\tThis help screen\n");
	printf("\t-p\tGenerate size of data set that are hit by this percentage\n");
	printf("\t-t\tDistribution type (zipf, pareto, or normal)\n");
	printf("\t-i\tDistribution algorithm input (zipf theta, pareto power,\n"
		"\t\tor normal %% deviation)\n");
	printf("\t-b\tBlock size of a given range (in bytes)\n");
	printf("\t-g\tSize of data set (in gigabytes)\n");
	printf("\t-o\tNumber of output rows\n");
	printf("\t-c\tOutput ranges in CSV format\n");
}

static int parse_options(int argc, char *argv[])
{
	const char *optstring = "t:g:i:o:b:p:ch";
	int c, dist_val_set = 0;

	while ((c = getopt(argc, argv, optstring)) != -1) {
		switch (c) {
		case 'h':
			usage();
			return 1;
		case 'p':
			percentage = atof(optarg);
			break;
		case 'b':
			block_size = strtoul(optarg, NULL, 10);
			break;
		case 't':
			if (!strncmp(optarg, "zipf", 4))
				dist_type = TYPE_ZIPF;
			else if (!strncmp(optarg, "pareto", 6))
				dist_type = TYPE_PARETO;
			else if (!strncmp(optarg, "normal", 6))
				dist_type = TYPE_NORMAL;
			else {
				printf("wrong dist type: %s\n", optarg);
				return 1;
			}
			break;
		case 'g':
			gib_size = strtoul(optarg, NULL, 10);
			break;
		case 'i':
			dist_val = atof(optarg);
			dist_val_set = 1;
			break;
		case 'o':
			output_nranges = strtoul(optarg, NULL, 10);
			break;
		case 'c':
			output_type = OUTPUT_CSV;
			break;
		default:
			printf("bad option %c\n", c);
			return 1;
		}
	}

	if (dist_type == TYPE_PARETO) {
		if ((dist_val >= 1.00 || dist_val < 0.00)) {
			printf("pareto input must be > 0.00 and < 1.00\n");
			return 1;
		}
		if (!dist_val_set)
			dist_val = DEF_PARETO_VAL;
	} else if (dist_type == TYPE_ZIPF) {
		if (dist_val == 1.0) {
			printf("zipf input must be different than 1.0\n");
			return 1;
		}
		if (!dist_val_set)
			dist_val = DEF_ZIPF_VAL;
	}

	return 0;
}

struct output_sum {
	double output;
	unsigned int nranges;
};

static int node_cmp(const void *p1, const void *p2)
{
	const struct node *n1 = p1;
	const struct node *n2 = p2;

	return n2->hits - n1->hits;
}

static void output_csv(struct node *nodes, unsigned long nnodes)
{
	unsigned long i;

	printf("rank, count\n");
	for (i = 0; i < nnodes; i++)
		printf("%lu, %lu\n", i, nodes[i].hits);
}

static void output_normal(struct node *nodes, unsigned long nnodes,
			  unsigned long nranges)
{
	unsigned long i, j, cur_vals, interval_step, next_interval, total_vals;
	unsigned long blocks = percentage * nnodes / 100;
	double hit_percent_sum = 0;
	unsigned long long hit_sum = 0;
	double perc, perc_i;
	struct output_sum *output_sums;

	interval_step = (nnodes - 1) / output_nranges + 1;
	next_interval = interval_step;
	output_sums = malloc(output_nranges * sizeof(struct output_sum));

	for (i = 0; i < output_nranges; i++) {
		output_sums[i].output = 0.0;
		output_sums[i].nranges = 0;
	}

	j = total_vals = cur_vals = 0;

	for (i = 0; i < nnodes; i++) {
		struct output_sum *os = &output_sums[j];
		struct node *node = &nodes[i];
		cur_vals += node->hits;
		total_vals += node->hits;
		os->nranges += node->hits;
		if (i == (next_interval) -1 || i == nnodes - 1) {
			os->output = (double) cur_vals / (double) nranges;
			os->output *= 100.0;
			cur_vals = 0;
			next_interval += interval_step;
			j++;
		}

		if (percentage) {
			if (total_vals >= blocks) {
				double cs = (double) i * block_size / (1024.0 * 1024.0);
				char p = 'M';

				if (cs > 1024.0) {
					cs /= 1024.0;
					p = 'G';
				}
				if (cs > 1024.0) {
					cs /= 1024.0;
					p = 'T';
				}

				printf("%.2f%% of hits satisfied in %.3f%cB of cache\n", percentage, cs, p);
				percentage = 0.0;
			}
		}
	}

	perc_i = 100.0 / (double)output_nranges;
	perc = 0.0;

	printf("\n   Rows           Hits %%         Sum %%           # Hits          Size\n");
	printf("-----------------------------------------------------------------------\n");
	for (i = 0; i < output_nranges; i++) {
		struct output_sum *os = &output_sums[i];
		double gb = (double)os->nranges * block_size / 1024.0;
		char p = 'K';

		if (gb > 1024.0) {
			p = 'M';
			gb /= 1024.0;
		}
		if (gb > 1024.0) {
			p = 'G';
			gb /= 1024.0;
		}

		perc += perc_i;
		hit_percent_sum += os->output;
		hit_sum += os->nranges;
		printf("%s %6.2f%%\t%6.2f%%\t\t%6.2f%%\t\t%8u\t%6.2f%c\n",
			i ? "|->" : "Top", perc, os->output, hit_percent_sum,
			os->nranges, gb, p);
	}

	printf("-----------------------------------------------------------------------\n");
	printf("Total\t\t\t\t\t\t%8llu\n", hit_sum);
	free(output_sums);
}

int main(int argc, char *argv[])
{
	unsigned long offset;
	unsigned long long nranges;
	unsigned long nnodes;
	struct node *nodes;
	struct zipf_state zs;
	struct gauss_state gs;
	int i, j;

	if (parse_options(argc, argv))
		return 1;

	if (output_type != OUTPUT_CSV)
		printf("Generating %s distribution with %f input and %lu GiB size and %lu block_size.\n",
		       dist_types[dist_type], dist_val, gib_size, block_size);

	nranges = gib_size * 1024 * 1024 * 1024ULL;
	nranges /= block_size;

	if (dist_type == TYPE_ZIPF)
		zipf_init(&zs, nranges, dist_val, -1, 1);
	else if (dist_type == TYPE_PARETO)
		pareto_init(&zs, nranges, dist_val, -1, 1);
	else
		gauss_init(&gs, nranges, dist_val, -1, 1);

	hash_bits = 0;
	hash_size = nranges;
	while ((hash_size >>= 1) != 0)
		hash_bits++;

	hash_size = 1 << hash_bits;

	hash = calloc(hash_size, sizeof(struct flist_head));
	for (i = 0; i < hash_size; i++)
		INIT_FLIST_HEAD(&hash[i]);

	nodes = malloc(nranges * sizeof(struct node));

	for (i = j = 0; i < nranges; i++) {
		struct node *n;

		if (dist_type == TYPE_ZIPF)
			offset = zipf_next(&zs);
		else if (dist_type == TYPE_PARETO)
			offset = pareto_next(&zs);
		else
			offset = gauss_next(&gs);

		n = hash_lookup(offset);
		if (n)
			n->hits++;
		else {
			hash_insert(&nodes[j], offset);
			j++;
		}
	}

	qsort(nodes, j, sizeof(struct node), node_cmp);
	nnodes = j;

	if (output_type == OUTPUT_CSV)
		output_csv(nodes, nnodes);
	else
		output_normal(nodes, nnodes, nranges);

	free(hash);
	free(nodes);
	return 0;
}
