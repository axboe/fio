/*
 * IO priority handling helper functions common to the libaio and io_uring
 * engines.
 */

#include "cmdprio.h"

/*
 * Temporary array used during parsing. Will be freed after the corresponding
 * struct bsprio_desc has been generated and saved in cmdprio->bsprio_desc.
 */
struct cmdprio_parse_result {
	struct split_prio *entries;
	int nr_entries;
};

/*
 * Temporary array used during init. Will be freed after the corresponding
 * struct clat_prio_stat array has been saved in td->ts.clat_prio and the
 * matching clat_prio_indexes have been saved in each struct cmdprio_prio.
 */
struct cmdprio_values {
	unsigned int *prios;
	int nr_prios;
};

static int find_clat_prio_index(unsigned int *all_prios, int nr_prios,
				int32_t prio)
{
	int i;

	for (i = 0; i < nr_prios; i++) {
		if (all_prios[i] == prio)
			return i;
	}

	return -1;
}

/**
 * assign_clat_prio_index - In order to avoid stat.c the need to loop through
 * all possible priorities each time add_clat_sample() / add_lat_sample() is
 * called, save which index to use in each cmdprio_prio. This will later be
 * propagated to the io_u, if the specific io_u was determined to use a cmdprio
 * priority value.
 */
static void assign_clat_prio_index(struct cmdprio_prio *prio,
				   struct cmdprio_values *values)
{
	int clat_prio_index = find_clat_prio_index(values->prios,
						   values->nr_prios,
						   prio->prio);
	if (clat_prio_index == -1) {
		clat_prio_index = values->nr_prios;
		values->prios[clat_prio_index] = prio->prio;
		values->nr_prios++;
	}
	prio->clat_prio_index = clat_prio_index;
}

/**
 * init_cmdprio_values - Allocate a temporary array that can hold all unique
 * priorities (per ddir), so that we can assign_clat_prio_index() for each
 * cmdprio_prio during setup. This temporary array is freed after setup.
 */
static int init_cmdprio_values(struct cmdprio_values *values,
			       int max_unique_prios, struct thread_stat *ts)
{
	values->prios = calloc(max_unique_prios + 1,
			       sizeof(*values->prios));
	if (!values->prios)
		return 1;

	/* td->ioprio/ts->ioprio is always stored at index 0. */
	values->prios[0] = ts->ioprio;
	values->nr_prios++;

	return 0;
}

/**
 * init_ts_clat_prio - Allocates and fills a clat_prio_stat array which holds
 * all unique priorities (per ddir).
 */
static int init_ts_clat_prio(struct thread_stat *ts, enum fio_ddir ddir,
			     struct cmdprio_values *values)
{
	int i;

	if (alloc_clat_prio_stat_ddir(ts, ddir, values->nr_prios))
		return 1;

	for (i = 0; i < values->nr_prios; i++)
		ts->clat_prio[ddir][i].ioprio = values->prios[i];

	return 0;
}

static int fio_cmdprio_fill_bsprio(struct cmdprio_bsprio *bsprio,
				   struct split_prio *entries,
				   struct cmdprio_values *values,
				   int implicit_cmdprio, int start, int end)
{
	struct cmdprio_prio *prio;
	int i = end - start + 1;

	bsprio->prios = calloc(i, sizeof(*bsprio->prios));
	if (!bsprio->prios)
		return 1;

	bsprio->bs = entries[start].bs;
	bsprio->nr_prios = 0;
	for (i = start; i <= end; i++) {
		prio = &bsprio->prios[bsprio->nr_prios];
		prio->perc = entries[i].perc;
		if (entries[i].prio == -1)
			prio->prio = implicit_cmdprio;
		else
			prio->prio = entries[i].prio;
		assign_clat_prio_index(prio, values);
		bsprio->tot_perc += entries[i].perc;
		if (bsprio->tot_perc > 100) {
			log_err("fio: cmdprio_bssplit total percentage "
				"for bs: %"PRIu64" exceeds 100\n",
				bsprio->bs);
			free(bsprio->prios);
			return 1;
		}
		bsprio->nr_prios++;
	}

	return 0;
}

static int
fio_cmdprio_generate_bsprio_desc(struct cmdprio_bsprio_desc *bsprio_desc,
				 struct cmdprio_parse_result *parse_res,
				 struct cmdprio_values *values,
				 int implicit_cmdprio)
{
	struct split_prio *entries = parse_res->entries;
	int nr_entries = parse_res->nr_entries;
	struct cmdprio_bsprio *bsprio;
	int i, start, count = 0;

	/*
	 * The parsed result is sorted by blocksize, so count only the number
	 * of different blocksizes, to know how many cmdprio_bsprio we need.
	 */
	for (i = 0; i < nr_entries; i++) {
		while (i + 1 < nr_entries && entries[i].bs == entries[i + 1].bs)
			i++;
		count++;
	}

	/*
	 * This allocation is not freed on error. Instead, the calling function
	 * is responsible for calling fio_cmdprio_cleanup() on error.
	 */
	bsprio_desc->bsprios = calloc(count, sizeof(*bsprio_desc->bsprios));
	if (!bsprio_desc->bsprios)
		return 1;

	start = 0;
	bsprio_desc->nr_bsprios = 0;
	for (i = 0; i < nr_entries; i++) {
		while (i + 1 < nr_entries && entries[i].bs == entries[i + 1].bs)
			i++;
		bsprio = &bsprio_desc->bsprios[bsprio_desc->nr_bsprios];
		/*
		 * All parsed entries with the same blocksize get saved in the
		 * same cmdprio_bsprio, to expedite the search in the hot path.
		 */
		if (fio_cmdprio_fill_bsprio(bsprio, entries, values,
					    implicit_cmdprio, start, i))
			return 1;

		start = i + 1;
		bsprio_desc->nr_bsprios++;
	}

	return 0;
}

static int fio_cmdprio_bssplit_ddir(struct thread_options *to, void *cb_arg,
				    enum fio_ddir ddir, char *str, bool data)
{
	struct cmdprio_parse_result *parse_res_arr = cb_arg;
	struct cmdprio_parse_result *parse_res = &parse_res_arr[ddir];

	if (ddir == DDIR_TRIM)
		return 0;

	if (split_parse_prio_ddir(to, &parse_res->entries,
				  &parse_res->nr_entries, str))
		return 1;

	return 0;
}

static int fio_cmdprio_bssplit_parse(struct thread_data *td, const char *input,
				     struct cmdprio_parse_result *parse_res)
{
	char *str, *p;
	int ret = 0;

	p = str = strdup(input);

	strip_blank_front(&str);
	strip_blank_end(str);

	ret = str_split_parse(td, str, fio_cmdprio_bssplit_ddir, parse_res,
			      false);

	free(p);
	return ret;
}

/**
 * fio_cmdprio_percentage - Returns the percentage of I/Os that should
 * use a cmdprio priority value (rather than the default context priority).
 *
 * For CMDPRIO_MODE_BSSPLIT, if the percentage is non-zero, we will also
 * return the matching bsprio, to avoid the same linear search elsewhere.
 * For CMDPRIO_MODE_PERC, we will never return a bsprio.
 */
static int fio_cmdprio_percentage(struct cmdprio *cmdprio, struct io_u *io_u,
				  struct cmdprio_bsprio **bsprio)
{
	struct cmdprio_bsprio *bsprio_entry;
	enum fio_ddir ddir = io_u->ddir;
	int i;

	switch (cmdprio->mode) {
	case CMDPRIO_MODE_PERC:
		*bsprio = NULL;
		return cmdprio->perc_entry[ddir].perc;
	case CMDPRIO_MODE_BSSPLIT:
		for (i = 0; i < cmdprio->bsprio_desc[ddir].nr_bsprios; i++) {
			bsprio_entry = &cmdprio->bsprio_desc[ddir].bsprios[i];
			if (bsprio_entry->bs == io_u->buflen) {
				*bsprio = bsprio_entry;
				return bsprio_entry->tot_perc;
			}
		}
		break;
	default:
		/*
		 * An I/O engine should never call this function if cmdprio
		 * is not is use.
		 */
		assert(0);
	}

	/*
	 * This is totally fine, the given blocksize simply does not
	 * have any (non-zero) cmdprio_bssplit entries defined.
	 */
	*bsprio = NULL;
	return 0;
}

/**
 * fio_cmdprio_set_ioprio - Set an io_u ioprio according to cmdprio options
 *
 * Generates a random percentage value to determine if an io_u ioprio needs
 * to be set. If the random percentage value is within the user specified
 * percentage of I/Os that should use a cmdprio priority value (rather than
 * the default priority), then this function updates the io_u with an ioprio
 * value as defined by the cmdprio/cmdprio_hint/cmdprio_class or
 * cmdprio_bssplit options.
 *
 * Return true if the io_u ioprio was changed and false otherwise.
 */
bool fio_cmdprio_set_ioprio(struct thread_data *td, struct cmdprio *cmdprio,
			    struct io_u *io_u)
{
	struct cmdprio_bsprio *bsprio;
	unsigned int p, rand;
	uint32_t perc = 0;
	int i;

	p = fio_cmdprio_percentage(cmdprio, io_u, &bsprio);
	if (!p)
		return false;

	rand = rand_between(&td->prio_state, 0, 99);
	if (rand >= p)
		return false;

	switch (cmdprio->mode) {
	case CMDPRIO_MODE_PERC:
		io_u->ioprio = cmdprio->perc_entry[io_u->ddir].prio;
		io_u->clat_prio_index =
			cmdprio->perc_entry[io_u->ddir].clat_prio_index;
		return true;
	case CMDPRIO_MODE_BSSPLIT:
		assert(bsprio);
		for (i = 0; i < bsprio->nr_prios; i++) {
			struct cmdprio_prio *prio = &bsprio->prios[i];

			perc += prio->perc;
			if (rand < perc) {
				io_u->ioprio = prio->prio;
				io_u->clat_prio_index = prio->clat_prio_index;
				return true;
			}
		}
		break;
	default:
		assert(0);
	}

	/* When rand < p (total perc), we should always find a cmdprio_prio. */
	assert(0);
	return false;
}

static int fio_cmdprio_gen_perc(struct thread_data *td, struct cmdprio *cmdprio)
{
	struct cmdprio_options *options = cmdprio->options;
	struct cmdprio_prio *prio;
	struct cmdprio_values values[CMDPRIO_RWDIR_CNT] = {};
	struct thread_stat *ts = &td->ts;
	enum fio_ddir ddir;
	int ret;

	for (ddir = 0; ddir < CMDPRIO_RWDIR_CNT; ddir++) {
		/*
		 * Do not allocate a clat_prio array nor set the cmdprio struct
		 * if zero percent of the I/Os (for the ddir) should use a
		 * cmdprio priority value, or when the ddir is not enabled.
		 */
		if (!options->percentage[ddir] ||
		    (ddir == DDIR_READ && !td_read(td)) ||
		    (ddir == DDIR_WRITE && !td_write(td)))
			continue;

		ret = init_cmdprio_values(&values[ddir], 1, ts);
		if (ret)
			goto err;

		prio = &cmdprio->perc_entry[ddir];
		prio->perc = options->percentage[ddir];
		prio->prio = ioprio_value(options->class[ddir],
					  options->level[ddir],
					  options->hint[ddir]);
		assign_clat_prio_index(prio, &values[ddir]);

		ret = init_ts_clat_prio(ts, ddir, &values[ddir]);
		if (ret)
			goto err;

		free(values[ddir].prios);
		values[ddir].prios = NULL;
		values[ddir].nr_prios = 0;
	}

	return 0;

err:
	for (ddir = 0; ddir < CMDPRIO_RWDIR_CNT; ddir++)
		free(values[ddir].prios);
	free_clat_prio_stats(ts);

	return ret;
}

static int fio_cmdprio_parse_and_gen_bssplit(struct thread_data *td,
					     struct cmdprio *cmdprio)
{
	struct cmdprio_options *options = cmdprio->options;
	struct cmdprio_parse_result parse_res[CMDPRIO_RWDIR_CNT] = {};
	struct cmdprio_values values[CMDPRIO_RWDIR_CNT] = {};
	struct thread_stat *ts = &td->ts;
	int ret, implicit_cmdprio;
	enum fio_ddir ddir;

	ret = fio_cmdprio_bssplit_parse(td, options->bssplit_str,
					&parse_res[0]);
	if (ret)
		goto err;

	for (ddir = 0; ddir < CMDPRIO_RWDIR_CNT; ddir++) {
		/*
		 * Do not allocate a clat_prio array nor set the cmdprio structs
		 * if there are no non-zero entries (for the ddir), or when the
		 * ddir is not enabled.
		 */
		if (!parse_res[ddir].nr_entries ||
		    (ddir == DDIR_READ && !td_read(td)) ||
		    (ddir == DDIR_WRITE && !td_write(td))) {
			free(parse_res[ddir].entries);
			parse_res[ddir].entries = NULL;
			parse_res[ddir].nr_entries = 0;
			continue;
		}

		ret = init_cmdprio_values(&values[ddir],
					  parse_res[ddir].nr_entries, ts);
		if (ret)
			goto err;

		implicit_cmdprio = ioprio_value(options->class[ddir],
						options->level[ddir],
						options->hint[ddir]);

		ret = fio_cmdprio_generate_bsprio_desc(&cmdprio->bsprio_desc[ddir],
						       &parse_res[ddir],
						       &values[ddir],
						       implicit_cmdprio);
		if (ret)
			goto err;

		free(parse_res[ddir].entries);
		parse_res[ddir].entries = NULL;
		parse_res[ddir].nr_entries = 0;

		ret = init_ts_clat_prio(ts, ddir, &values[ddir]);
		if (ret)
			goto err;

		free(values[ddir].prios);
		values[ddir].prios = NULL;
		values[ddir].nr_prios = 0;
	}

	return 0;

err:
	for (ddir = 0; ddir < CMDPRIO_RWDIR_CNT; ddir++) {
		free(parse_res[ddir].entries);
		free(values[ddir].prios);
	}
	free_clat_prio_stats(ts);
	fio_cmdprio_cleanup(cmdprio);

	return ret;
}

static int fio_cmdprio_parse_and_gen(struct thread_data *td,
				     struct cmdprio *cmdprio)
{
	struct cmdprio_options *options = cmdprio->options;
	int i, ret;

	/*
	 * If cmdprio_percentage/cmdprio_bssplit is set and cmdprio_class
	 * is not set, default to RT priority class.
	 */
	for (i = 0; i < CMDPRIO_RWDIR_CNT; i++) {
		/*
		 * A cmdprio value is only used when fio_cmdprio_percentage()
		 * returns non-zero, so it is safe to set a class even for a
		 * DDIR that will never use it.
		 */
		if (!options->class[i])
			options->class[i] = IOPRIO_CLASS_RT;
	}

	switch (cmdprio->mode) {
	case CMDPRIO_MODE_BSSPLIT:
		ret = fio_cmdprio_parse_and_gen_bssplit(td, cmdprio);
		break;
	case CMDPRIO_MODE_PERC:
		ret = fio_cmdprio_gen_perc(td, cmdprio);
		break;
	default:
		assert(0);
		return 1;
	}

	return ret;
}

void fio_cmdprio_cleanup(struct cmdprio *cmdprio)
{
	enum fio_ddir ddir;
	int i;

	for (ddir = 0; ddir < CMDPRIO_RWDIR_CNT; ddir++) {
		for (i = 0; i < cmdprio->bsprio_desc[ddir].nr_bsprios; i++)
			free(cmdprio->bsprio_desc[ddir].bsprios[i].prios);
		free(cmdprio->bsprio_desc[ddir].bsprios);
		cmdprio->bsprio_desc[ddir].bsprios = NULL;
		cmdprio->bsprio_desc[ddir].nr_bsprios = 0;
	}

	/*
	 * options points to a cmdprio_options struct that is part of td->eo.
	 * td->eo itself will be freed by free_ioengine().
	 */
	cmdprio->options = NULL;
}

int fio_cmdprio_init(struct thread_data *td, struct cmdprio *cmdprio,
		     struct cmdprio_options *options)
{
	struct thread_options *to = &td->o;
	bool has_cmdprio_percentage = false;
	bool has_cmdprio_bssplit = false;
	int i;

	cmdprio->options = options;

	if (options->bssplit_str && strlen(options->bssplit_str))
		has_cmdprio_bssplit = true;

	for (i = 0; i < CMDPRIO_RWDIR_CNT; i++) {
		if (options->percentage[i])
			has_cmdprio_percentage = true;
	}

	/*
	 * Check for option conflicts
	 */
	if (has_cmdprio_percentage && has_cmdprio_bssplit) {
		log_err("%s: cmdprio_percentage and cmdprio_bssplit options "
			"are mutually exclusive\n",
			to->name);
		return 1;
	}

	if (has_cmdprio_bssplit)
		cmdprio->mode = CMDPRIO_MODE_BSSPLIT;
	else if (has_cmdprio_percentage)
		cmdprio->mode = CMDPRIO_MODE_PERC;
	else
		cmdprio->mode = CMDPRIO_MODE_NONE;

	/* Nothing left to do if cmdprio is not used */
	if (cmdprio->mode == CMDPRIO_MODE_NONE)
		return 0;

	return fio_cmdprio_parse_and_gen(td, cmdprio);
}
