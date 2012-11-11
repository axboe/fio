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
#include <unistd.h>

#include "../lib/zipf.h"
#include "../flist.h"
#include "../hash.h"
#include "../rbtree.h"

#define DEF_NR		1000000
#define DEF_NR_OUTPUT	23

struct node {
	struct flist_head list;
	struct rb_node rb;
	unsigned long long val;
	unsigned long hits;
};

static struct flist_head *hash;
static unsigned long hash_bits = 24;
static unsigned long hash_size = 1 << 24;
static struct rb_root rb;

enum {
	TYPE_NONE = 0,
	TYPE_ZIPF,
	TYPE_PARETO,
};
static const char *dist_types[] = { "None", "Zipf", "Pareto" };

static int dist_type = TYPE_ZIPF;
static unsigned long gb_size = 500;
static unsigned long block_size = 4096;
static unsigned long output_nranges = DEF_NR_OUTPUT;
static double percentage;
static double dist_val;

#define DEF_ZIPF_VAL	1.2
#define DEF_PARETO_VAL	0.3

static struct node *hash_lookup(unsigned long long val)
{
	struct flist_head *l = &hash[hash_long(val, hash_bits)];
	struct flist_head *entry;
	struct node *n;

	flist_for_each(entry, l) {
		n = flist_entry(entry, struct node, list);
		if (n->val == val)
			return n;
	}

	return NULL;
}

static void hash_insert(unsigned long long val)
{
	struct flist_head *l = &hash[hash_long(val, hash_bits)];
	struct node *n = malloc(sizeof(*n));

	n->val = val;
	n->hits = 1;
	flist_add_tail(&n->list, l);
}

static void rb_insert(struct node *n)
{
	struct rb_node **p, *parent;

	memset(&n->rb, 0, sizeof(n->rb));
	p = &rb.rb_node;
	parent = NULL;
	while (*p) {
		struct node *__n;

		parent = *p;
		__n = rb_entry(parent, struct node, rb);
		if (n->hits > __n->hits)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}

	rb_link_node(&n->rb, parent, p);
	rb_insert_color(&n->rb, &rb);
}

static unsigned long rb_add(struct flist_head *list)
{
	struct flist_head *entry;
	unsigned long ret = 0;
	struct node *n;

	flist_for_each(entry, list) {
		n = flist_entry(entry, struct node, list);

		rb_insert(n);
		ret++;
	}

	return ret;
}

static unsigned long rb_gen(void)
{
	unsigned long ret = 0;
	unsigned int i;

	for (i = 0; i < hash_size; i++)
		ret += rb_add(&hash[i]);

	return ret;
}

static int parse_options(int argc, char *argv[])
{
	const char *optstring = "t:g:i:o:b:p:";
	int c, dist_val_set = 0;

	while ((c = getopt(argc, argv, optstring)) != -1) {
		switch (c) {
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
			else {
				printf("wrong dist type: %s\n", optarg);
				return 1;
			}
			break;
		case 'g':
			gb_size = strtoul(optarg, NULL, 10);
			break;
		case 'i':
			dist_val = atof(optarg);
			dist_val_set = 1;
			break;
		case 'o':
			output_nranges = strtoul(optarg, NULL, 10);
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

int main(int argc, char *argv[])
{
	unsigned long offset;
	unsigned long i, j, nr_vals, cur_vals, interval, total_vals;
	unsigned long long nranges;
	struct output_sum *output_sums;
	double perc, perc_i;
	struct zipf_state zs;
	struct rb_node *n;

	if (parse_options(argc, argv))
		return 1;

	printf("Generating %s distribution with %f input and %lu GB size and %lu block_size.\n", dist_types[dist_type], dist_val, gb_size, block_size);

	nranges = gb_size * 1024 * 1024 * 1024ULL;
	nranges /= block_size;

	if (dist_type == TYPE_ZIPF)
		zipf_init(&zs, nranges, dist_val, 1);
	else
		pareto_init(&zs, nranges, dist_val, 1);

	hash_bits = 0;
	hash_size = nranges;
	while ((hash_size >>= 1) != 0)
		hash_bits++;

	hash_size = 1 << hash_bits;

	hash = malloc(hash_size * sizeof(struct flist_head));
	for (i = 0; i < hash_size; i++)
		INIT_FLIST_HEAD(&hash[i]);

	for (nr_vals = i = 0; i < nranges; i++) {
		struct node *n;

		if (dist_type == TYPE_ZIPF)
			offset = zipf_next(&zs);
		else
			offset = pareto_next(&zs);

		n = hash_lookup(offset);
		if (n)
			n->hits++;
		else
			hash_insert(offset);

		nr_vals++;
	}

	nr_vals = rb_gen();

	interval = (nr_vals + output_nranges - 1) / output_nranges;

	output_sums = malloc(output_nranges * sizeof(struct output_sum));
	for (i = 0; i < output_nranges; i++) {
		output_sums[i].output = 0.0;
		output_sums[i].nranges = 1;
	}

	total_vals = i = j = cur_vals = 0;
	
	n = rb_first(&rb);
	while (n) {
		struct node *node = rb_entry(n, struct node, rb);
		struct output_sum *os = &output_sums[j];

		if (i >= interval) {
			os->output = (double) (cur_vals + 1) / (double) nranges;
			os->output *= 100.0;
			j++;
			cur_vals = node->hits;
			interval += (nr_vals + output_nranges - 1) / output_nranges;
		} else {
			cur_vals += node->hits;
			os->nranges += node->hits;
		}

		i++;
		total_vals += node->hits;

		if (percentage) {
			unsigned long blocks = percentage * nranges / 100;

			if (total_vals >= blocks) {
				double cs = i * block_size / (1024 * 1024);
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

		n = rb_next(n);
	}

	perc_i = 100.0 / (double) output_nranges;
	perc = 0.0;

	printf("\n   Rows           Hits           No Hits         Size\n");
	printf("--------------------------------------------------------\n");
	for (i = 0; i < j; i++) {
		struct output_sum *os = &output_sums[i];
		double gb = (double) os->nranges * block_size / 1024.0;
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
		printf("%s %6.2f%%\t%6.2f%%\t\t%8u\t%6.2f%c\n", i ? "|->" : "Top", perc, os->output, os->nranges, gb, p);
	}

	free(output_sums);
	free(hash);
	return 0;
}
