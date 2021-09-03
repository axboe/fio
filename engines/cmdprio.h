/*
 * IO priority handling declarations and helper functions common to the
 * libaio and io_uring engines.
 */

#ifndef FIO_CMDPRIO_H
#define FIO_CMDPRIO_H

#include "../fio.h"

struct cmdprio {
	unsigned int percentage[DDIR_RWDIR_CNT];
	unsigned int class[DDIR_RWDIR_CNT];
	unsigned int level[DDIR_RWDIR_CNT];
	unsigned int bssplit_nr[DDIR_RWDIR_CNT];
	struct bssplit *bssplit[DDIR_RWDIR_CNT];
};

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

static int fio_cmdprio_bssplit_parse(struct thread_data *td, const char *input,
				     struct cmdprio *cmdprio)
{
	char *str, *p;
	int i, ret = 0;

	p = str = strdup(input);

	strip_blank_front(&str);
	strip_blank_end(str);

	ret = str_split_parse(td, str, fio_cmdprio_bssplit_ddir, cmdprio, false);

	if (parse_dryrun()) {
		for (i = 0; i < DDIR_RWDIR_CNT; i++) {
			free(cmdprio->bssplit[i]);
			cmdprio->bssplit[i] = NULL;
			cmdprio->bssplit_nr[i] = 0;
		}
	}

	free(p);
	return ret;
}

static inline int fio_cmdprio_percentage(struct cmdprio *cmdprio,
					 struct io_u *io_u)
{
	enum fio_ddir ddir = io_u->ddir;
	unsigned int p = cmdprio->percentage[ddir];
	int i;

	/*
	 * If cmdprio_percentage option was specified, then use that
	 * percentage. Otherwise, use cmdprio_bssplit percentages depending
	 * on the IO size.
	 */
	if (p)
		return p;

	for (i = 0; i < cmdprio->bssplit_nr[ddir]; i++) {
		if (cmdprio->bssplit[ddir][i].bs == io_u->buflen)
			return cmdprio->bssplit[ddir][i].perc;
	}

	return 0;
}

static int fio_cmdprio_init(struct thread_data *td, struct cmdprio *cmdprio,
			    bool *has_cmdprio)
{
	struct thread_options *to = &td->o;
	bool has_cmdprio_percentage = false;
	bool has_cmdprio_bssplit = false;
	int i;

	/*
	 * If cmdprio_percentage/cmdprio_bssplit is set and cmdprio_class
	 * is not set, default to RT priority class.
	 */
	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		if (cmdprio->percentage[i]) {
			if (!cmdprio->class[i])
				cmdprio->class[i] = IOPRIO_CLASS_RT;
			has_cmdprio_percentage = true;
		}
		if (cmdprio->bssplit_nr[i]) {
			if (!cmdprio->class[i])
				cmdprio->class[i] = IOPRIO_CLASS_RT;
			has_cmdprio_bssplit = true;
		}
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

	*has_cmdprio = has_cmdprio_percentage || has_cmdprio_bssplit;

	return 0;
}

#endif
