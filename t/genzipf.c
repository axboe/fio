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
static unsigned long nranges = DEF_NR;
static unsigned long output_nranges = DEF_NR_OUTPUT;
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
	const char *optstring = "t:g:i:r:o:";
	int c, dist_val_set = 0;

	while ((c = getopt(argc, argv, optstring)) != -1) {
		switch (c) {
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
		case 'r':
			nranges = strtoul(optarg, NULL, 10);
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

int main(int argc, char *argv[])
{
	unsigned long offset;
	unsigned long i, j, nr_vals, cur_vals, interval;
	double *output, perc, perc_i;
	struct zipf_state zs;
	struct rb_node *n;

	if (parse_options(argc, argv))
		return 1;

	printf("Generating %s distribution with %f input and %lu ranges.\n", dist_types[dist_type], dist_val, nranges);
	printf("Using device gb=%lu\n\n", gb_size);

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

	for (nr_vals = 0, i = 0; i < nranges; i++) {
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

	output = malloc(output_nranges * sizeof(double));

	i = j = cur_vals = 0;
	
	n = rb_first(&rb);
	while (n) {
		struct node *node = rb_entry(n, struct node, rb);

		if (i >= interval) {
			output[j] = (double) (cur_vals + 1) / (double) nranges;
			output[j] *= 100.0;
			j++;
			cur_vals = node->hits;
			interval += (nr_vals + output_nranges - 1) / output_nranges;
		} else
			cur_vals += node->hits;

		n = rb_next(n);
		i++;
	}

	perc_i = 100.0 / (double) output_nranges;
	perc = 0.0;

	printf("   Rows           Hits           Size\n");
	printf("-------------------------------------------\n");
	for (i = 0; i < j; i++) {
		double gb = (double) gb_size * perc_i / 100.0;
		char p = 'G';

		if (gb < 1.0) {
			p = 'M';
			gb *= 1024.0;
		}

		perc += perc_i;
		printf("%s %6.2f%%\t%6.2f%%\t\t%6.2f%c\n", i ? "|->" : "Top", perc, output[i], gb, p);
	}

	free(output);
	free(hash);
	return 0;
}
