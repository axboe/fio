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
};

static int fio_cmdprio_init(struct thread_data *td, struct cmdprio *cmdprio,
			    bool *has_cmdprio)
{
	struct thread_options *to = &td->o;
	bool has_cmdprio_percentage = false;
	int i;

	/*
	 * If cmdprio_percentage is set and cmdprio_class is not set,
	 * default to RT priority class.
	 */
	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		if (cmdprio->percentage[i]) {
			if (!cmdprio->class[i])
				cmdprio->class[i] = IOPRIO_CLASS_RT;
			has_cmdprio_percentage = true;
		}
	}

	/*
	 * Check for option conflicts
	 */
	if (has_cmdprio_percentage &&
	    (fio_option_is_set(to, ioprio) ||
	     fio_option_is_set(to, ioprio_class))) {
		log_err("%s: cmdprio_percentage option and mutually exclusive "
			"prio or prioclass option is set, exiting\n",
			to->name);
		return 1;
	}

	*has_cmdprio = has_cmdprio_percentage;

	return 0;
}

#endif
