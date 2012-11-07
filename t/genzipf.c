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

int main(int argc, char *argv[])
{
	unsigned long nranges, output_nranges;
	unsigned long offset;
	unsigned long i, j, nr_vals, cur_vals, interval;
	double *output, perc, perc_i;
	struct zipf_state zs;
	struct rb_node *n;
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

		if (use_zipf)
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
	for (i = 0; i < j; i++) {
		perc += perc_i;
		printf("%s %6.2f%%:\t%6.2f%% of hits\n", i ? "|->" : "Top", perc, output[i]);
	}

	free(output);
	free(hash);
	return 0;
}
