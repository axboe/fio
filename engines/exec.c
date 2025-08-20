/*
 * Exec engine
 *
 * Doesn't transfer any data, merely run 3rd party tools
 *
 */
#include "../fio.h"
#include "../optgroup.h"
#include <signal.h>

struct exec_options {
	void *pad;
	char *program;
	char *arguments;
	int grace_time;
	unsigned int std_redirect;
	pid_t pid;
};

static struct fio_option options[] = {
	{
		.name = "program",
		.lname = "Program",
		.type = FIO_OPT_STR_STORE,
		.off1 = offsetof(struct exec_options, program),
		.help = "Program to execute",
		.category = FIO_OPT_C_ENGINE,
		.group = FIO_OPT_G_INVALID,
	},
	{
		.name = "arguments",
		.lname = "Arguments",
		.type = FIO_OPT_STR_STORE,
		.off1 = offsetof(struct exec_options, arguments),
		.help = "Arguments to pass",
		.category = FIO_OPT_C_ENGINE,
		.group = FIO_OPT_G_INVALID,
	},
	{
		.name = "grace_time",
		.lname = "Grace time",
		.type = FIO_OPT_INT,
		.minval = 0,
		.def = "1",
		.off1 = offsetof(struct exec_options, grace_time),
		.help = "Grace time before sending a SIGKILL",
		.category = FIO_OPT_C_ENGINE,
		.group = FIO_OPT_G_INVALID,
	},
	{
		.name = "std_redirect",
		.lname = "Std redirect",
		.type = FIO_OPT_BOOL,
		.def = "1",
		.off1 = offsetof(struct exec_options, std_redirect),
		.help = "Redirect stdout & stderr to files",
		.category = FIO_OPT_C_ENGINE,
		.group = FIO_OPT_G_INVALID,
	},
	{
		.name = NULL,
	},
};

static char *str_replace(char *orig, const char *rep, const char *with)
{
	/*
	 * Replace a substring by another.
	 *
	 * Returns the new string if occurrences were found
	 * Returns orig if no occurrence is found
	 */
	char *result, *insert, *tmp;
	int len_rep, len_with, len_front, count;

	/* sanity checks and initialization */
	if (!orig || !rep)
		return orig;

	len_rep = strlen(rep);
	if (len_rep == 0)
		return orig;

	if (!with)
		with = "";
	len_with = strlen(with);

	insert = orig;
	for (count = 0; (tmp = strstr(insert, rep)); ++count) {
		insert = tmp + len_rep;
	}

	tmp = result = malloc(strlen(orig) + (len_with - len_rep) * count + 1);

	if (!result)
		return orig;

	while (count--) {
		insert = strstr(orig, rep);
		len_front = insert - orig;
		tmp = strncpy(tmp, orig, len_front) + len_front;
		tmp = strcpy(tmp, with) + len_with;
		orig += len_front + len_rep;
	}
	strcpy(tmp, orig);
	return result;
}

static char *expand_variables(const struct thread_options *o, char *arguments)
{
	char str[16];
	char *expanded_runtime, *expanded_name;
	snprintf(str, sizeof(str), "%lld", o->timeout / 1000000);

	/* %r is replaced by the runtime in seconds */
	expanded_runtime = str_replace(arguments, "%r", str);

	/* %n is replaced by the name of the running job */
	expanded_name = str_replace(expanded_runtime, "%n", o->name);

	free(expanded_runtime);
	return expanded_name;
}

static int exec_background(const struct thread_options *o, struct exec_options *eo)
{
	char *outfilename = NULL, *errfilename = NULL;
	int outfd = 0, errfd = 0;
	pid_t pid;
	char *expanded_arguments = NULL;
	/* For the arguments splitting */
	char **arguments_array = NULL;
	char *p;
	char *exec_cmd = NULL;
	size_t arguments_nb_items = 0, q;

	if (asprintf(&outfilename, "%s.stdout", o->name) < 0)
		return -1;

	if (asprintf(&errfilename, "%s.stderr", o->name) < 0) {
		free(outfilename);
		return -1;
	}

	/* If we have variables in the arguments, let's expand them */
	expanded_arguments = expand_variables(o, eo->arguments);

	if (eo->std_redirect) {
		log_info("%s : Saving output of %s %s : stdout=%s stderr=%s\n",
			 o->name, eo->program, expanded_arguments, outfilename,
			 errfilename);

		/* Creating the stderr & stdout output files */
		outfd = open(outfilename, O_CREAT | O_WRONLY | O_TRUNC, 0644);
		if (outfd < 0) {
			log_err("fio: cannot open output file %s : %s\n",
				outfilename, strerror(errno));
			free(outfilename);
			free(errfilename);
			free(expanded_arguments);
			return -1;
		}

		errfd = open(errfilename, O_CREAT | O_WRONLY | O_TRUNC, 0644);
		if (errfd < 0) {
			log_err("fio: cannot open output file %s : %s\n",
				errfilename, strerror(errno));
			free(outfilename);
			free(errfilename);
			free(expanded_arguments);
			close(outfd);
			return -1;
		}
	} else {
		log_info("%s : Running %s %s\n",
			 o->name, eo->program, expanded_arguments);
	}

	pid = fork();

	/* We are on the control thread (parent side of the fork */
	if (pid > 0) {
		eo->pid = pid;
		if (eo->std_redirect) {
			/* The output file is for the client side of the fork */
			close(outfd);
			close(errfd);
			free(outfilename);
			free(errfilename);
		}
		free(expanded_arguments);
		return 0;
	}

	/* If the fork failed */
	if (pid < 0) {
		log_err("fio: forking failed %s \n", strerror(errno));
		if (eo->std_redirect) {
			close(outfd);
			close(errfd);
			free(outfilename);
			free(errfilename);
		}
		free(expanded_arguments);
		return -1;
	}

	/* We are in the worker (child side of the fork) */
	if (pid == 0) {
		if (eo->std_redirect) {
			/* replace stdout by the output file we create */
			dup2(outfd, 1);
			/* replace stderr by the output file we create */
			dup2(errfd, 2);
			close(outfd);
			close(errfd);
			free(outfilename);
			free(errfilename);
		}

		/*
		 * Let's split the command line into a null terminated array to
		 * be passed to the exec'd program.
		 * But don't asprintf expanded_arguments if NULL as it would be
		 * converted to a '(null)' argument, while we want no arguments
		 * at all.
		 */
		if (expanded_arguments != NULL) {
			if (asprintf(&exec_cmd, "%s %s", eo->program, expanded_arguments) < 0) {
				free(expanded_arguments);
				return -1;
			}
		} else {
			if (asprintf(&exec_cmd, "%s", eo->program) < 0)
				return -1;
		}

		/*
		 * Let's build an argv array to based on the program name and
		 * arguments
		 */
		p = exec_cmd;
		for (;;) {
			p += strspn(p, " ");

			if (!(q = strcspn(p, " ")))
				break;

			if (q) {
				arguments_array =
				    realloc(arguments_array,
					    (arguments_nb_items +
					     1) * sizeof(char *));
				arguments_array[arguments_nb_items] =
				    malloc(q + 1);
				strncpy(arguments_array[arguments_nb_items], p,
					q);
				arguments_array[arguments_nb_items][q] = 0;
				arguments_nb_items++;
				p += q;
			}
		}

		/* Adding a null-terminated item to close the list */
		arguments_array =
		    realloc(arguments_array,
			    (arguments_nb_items + 1) * sizeof(char *));
		arguments_array[arguments_nb_items] = NULL;

		/*
		 * Replace the fio program from the child fork by the target
		 * program
		 */
		execvp(arguments_array[0], arguments_array);
	}
	/* We never reach this place */
	/* Let's free the malloc'ed structures to make static checkers happy */
	if (expanded_arguments)
		free(expanded_arguments);
	if (arguments_array)
		free(arguments_array);
	return 0;
}

static enum fio_q_status
fio_exec_queue(struct thread_data *td, struct io_u fio_unused * io_u)
{
	struct thread_options *o = &td->o;
	struct exec_options *eo = td->eo;

	/* Let's execute the program the first time we get queued */
	if (eo->pid == -1) {
		exec_background(o, eo);
	} else {
		/*
		 * The program is running in background, let's check on a
		 * regular basis
		 * if the time is over and if we need to stop the tool
		 */
		usleep(o->thinktime);
		if (utime_since_now(&td->start) > o->timeout) {
			/* Let's stop the child */
			kill(eo->pid, SIGTERM);
			/*
			 * Let's give grace_time (1 sec by default) to the 3rd
			 * party tool to stop
			 */
			sleep(eo->grace_time);
		}
	}

	return FIO_Q_COMPLETED;
}

static int fio_exec_init(struct thread_data *td)
{
	struct thread_options *o = &td->o;
	struct exec_options *eo = td->eo;
	int td_previous_state;

	eo->pid = -1;

	if (!eo->program) {
		td_vmsg(td, EINVAL,
			"no program is defined, it is mandatory to define one",
			"exec");
		return 1;
	}

	log_info("%s : program=%s, arguments=%s\n",
		 td->o.name, eo->program, eo->arguments);

	/* Saving the current thread state */
	td_previous_state = td->runstate;

	/*
	 * Reporting that we are preparing the engine
	 * This is useful as the qsort() calibration takes time
	 * This prevents the job from starting before init is completed
	 */
	td_set_runstate(td, TD_SETTING_UP);

	/*
	 * set thinktime_sleep and thinktime_spin appropriately
	 */
	o->thinktime_blocks = 1;
	o->thinktime_blocks_type = THINKTIME_BLOCKS_TYPE_COMPLETE;
	o->thinktime_spin = 0;
	/* 50ms pause when waiting for the program to complete */
	o->thinktime = 50000;

	o->nr_files = o->open_files = 1;

	/* Let's restore the previous state. */
	td_set_runstate(td, td_previous_state);
	return 0;
}

static void fio_exec_cleanup(struct thread_data *td)
{
	struct exec_options *eo = td->eo;
	/* Send a sigkill to ensure the job is well terminated */
	if (eo->pid > 0)
		kill(eo->pid, SIGKILL);
}

static int
fio_exec_open(struct thread_data fio_unused * td,
	      struct fio_file fio_unused * f)
{
	return 0;
}

static struct ioengine_ops ioengine = {
	.name = "exec",
	.version = FIO_IOOPS_VERSION,
	.queue = fio_exec_queue,
	.init = fio_exec_init,
	.cleanup = fio_exec_cleanup,
	.open_file = fio_exec_open,
	.flags = FIO_SYNCIO | FIO_DISKLESSIO | FIO_NOIO,
	.options = options,
	.option_struct_size = sizeof(struct exec_options),
};

static void fio_init fio_exec_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_exec_unregister(void)
{
	unregister_ioengine(&ioengine);
}
