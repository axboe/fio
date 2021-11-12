/*
 * IO priority handling helper functions common to the libaio and io_uring
 * engines.
 */

#include "cmdprio.h"

static int fio_cmdprio_bssplit_ddir(struct thread_options *to, void *cb_arg,
				    enum fio_ddir ddir, char *str, bool data)
{
	struct cmdprio *cmdprio = cb_arg;
	struct split split;
	unsigned int i;

	if (ddir == DDIR_TRIM)
		return 0;

	memset(&split, 0, sizeof(split));

	if (split_parse_ddir(to, &split, str, data, BSSPLIT_MAX))
		return 1;
	if (!split.nr)
		return 0;

	cmdprio->bssplit_nr[ddir] = split.nr;
	cmdprio->bssplit[ddir] = malloc(split.nr * sizeof(struct bssplit));
	if (!cmdprio->bssplit[ddir])
		return 1;

	for (i = 0; i < split.nr; i++) {
		cmdprio->bssplit[ddir][i].bs = split.val1[i];
		if (split.val2[i] == -1U) {
			cmdprio->bssplit[ddir][i].perc = 0;
		} else {
			if (split.val2[i] > 100)
				cmdprio->bssplit[ddir][i].perc = 100;
			else
				cmdprio->bssplit[ddir][i].perc = split.val2[i];
		}
	}

	return 0;
}

int fio_cmdprio_bssplit_parse(struct thread_data *td, const char *input,
			      struct cmdprio *cmdprio)
{
	char *str, *p;
	int ret = 0;

	p = str = strdup(input);

	strip_blank_front(&str);
	strip_blank_end(str);

	ret = str_split_parse(td, str, fio_cmdprio_bssplit_ddir, cmdprio,
			      false);

	free(p);
	return ret;
}

static int fio_cmdprio_percentage(struct cmdprio *cmdprio, struct io_u *io_u)
{
	enum fio_ddir ddir = io_u->ddir;
	struct cmdprio_options *options = cmdprio->options;
	int i;

	switch (cmdprio->mode) {
	case CMDPRIO_MODE_PERC:
		return options->percentage[ddir];
	case CMDPRIO_MODE_BSSPLIT:
		for (i = 0; i < cmdprio->bssplit_nr[ddir]; i++) {
			if (cmdprio->bssplit[ddir][i].bs == io_u->buflen)
				return cmdprio->bssplit[ddir][i].perc;
		}
		break;
	default:
		/*
		 * An I/O engine should never call this function if cmdprio
		 * is not is use.
		 */
		assert(0);
	}

	return 0;
}

/**
 * fio_cmdprio_set_ioprio - Set an io_u ioprio according to cmdprio options
 *
 * Generates a random percentage value to determine if an io_u ioprio needs
 * to be set. If the random percentage value is within the user specified
 * percentage of I/Os that should use a cmdprio priority value (rather than
 * the default priority), then this function updates the io_u with an ioprio
 * value as defined by the cmdprio/cmdprio_class or cmdprio_bssplit options.
 *
 * Return true if the io_u ioprio was changed and false otherwise.
 */
bool fio_cmdprio_set_ioprio(struct thread_data *td, struct cmdprio *cmdprio,
			    struct io_u *io_u)
{
	enum fio_ddir ddir = io_u->ddir;
	struct cmdprio_options *options = cmdprio->options;
	unsigned int p;
	unsigned int cmdprio_value =
		ioprio_value(options->class[ddir], options->level[ddir]);

	p = fio_cmdprio_percentage(cmdprio, io_u);
	if (p && rand_between(&td->prio_state, 0, 99) < p) {
		io_u->ioprio = cmdprio_value;
		if (!td->ioprio || cmdprio_value < td->ioprio) {
			/*
			 * The async IO priority is higher (has a lower value)
			 * than the default priority (which is either 0 or the
			 * value set by "prio" and "prioclass" options).
			 */
			io_u->flags |= IO_U_F_HIGH_PRIO;
		}
		return true;
	}

	if (td->ioprio && td->ioprio < cmdprio_value) {
		/*
		 * The IO will be executed with the default priority (which is
		 * either 0 or the value set by "prio" and "prioclass options),
		 * and this priority is higher (has a lower value) than the
		 * async IO priority.
		 */
		io_u->flags |= IO_U_F_HIGH_PRIO;
	}

	return false;
}

static int fio_cmdprio_parse_and_gen_bssplit(struct thread_data *td,
					     struct cmdprio *cmdprio)
{
	struct cmdprio_options *options = cmdprio->options;
	int ret;

	ret = fio_cmdprio_bssplit_parse(td, options->bssplit_str, cmdprio);
	if (ret)
		goto err;

	return 0;

err:
	fio_cmdprio_cleanup(cmdprio);

	return ret;
}

static int fio_cmdprio_parse_and_gen(struct thread_data *td,
				     struct cmdprio *cmdprio)
{
	struct cmdprio_options *options = cmdprio->options;
	int i, ret;

	switch (cmdprio->mode) {
	case CMDPRIO_MODE_BSSPLIT:
		ret = fio_cmdprio_parse_and_gen_bssplit(td, cmdprio);
		break;
	case CMDPRIO_MODE_PERC:
		ret = 0;
		break;
	default:
		assert(0);
		return 1;
	}

	/*
	 * If cmdprio_percentage/cmdprio_bssplit is set and cmdprio_class
	 * is not set, default to RT priority class.
	 */
	for (i = 0; i < CMDPRIO_RWDIR_CNT; i++) {
		if (options->percentage[i] || cmdprio->bssplit_nr[i]) {
			if (!options->class[i])
				options->class[i] = IOPRIO_CLASS_RT;
		}
	}

	return ret;
}

void fio_cmdprio_cleanup(struct cmdprio *cmdprio)
{
	int ddir;

	for (ddir = 0; ddir < CMDPRIO_RWDIR_CNT; ddir++) {
		free(cmdprio->bssplit[ddir]);
		cmdprio->bssplit[ddir] = NULL;
		cmdprio->bssplit_nr[ddir] = 0;
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
