/*
 * The io parts of the fio tool, includes workers for sync and mmap'ed
 * io, as well as both posix and linux libaio support.
 *
 * sync io is implemented on top of aio.
 *
 * This is not really specific to fio, if the get_io_u/put_io_u and
 * structures was pulled into this as well it would be a perfectly
 * generic io engine that could be used for other projects.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>

#include "fio.h"
#include "os.h"

static int check_engine_ops(struct ioengine_ops *ops)
{
	/*
	 * cpu thread doesn't need to provide anything
	 */
	if (ops->flags & FIO_CPUIO)
		return 0;

	if (!ops->event) {
		log_err("%s: no event handler)\n", ops->name);
		return 1;
	}
	if (!ops->getevents) {
		log_err("%s: no getevents handler)\n", ops->name);
		return 1;
	}
	if (!ops->queue) {
		log_err("%s: no queue handler)\n", ops->name);
		return 1;
	}
		
	return 0;
}

struct ioengine_ops *load_ioengine(struct thread_data *td, char *name)
{
	char engine[16], engine_lib[256];
	struct ioengine_ops *ops, *ret;
	void *dlhandle;

	strcpy(engine, name);

	/*
	 * linux libaio has alias names, so convert to what we want
	 */
	if (!strncmp(engine, "linuxaio", 8) || !strncmp(engine, "aio", 3))
		strcpy(engine, "libaio");

	sprintf(engine_lib, "%s/lib/fio/fio-engine-%s.o", fio_inst_prefix, engine);
	dlerror();
	dlhandle = dlopen(engine_lib, RTLD_LAZY);
	if (!dlhandle) {
		td_vmsg(td, -1, dlerror());
		return NULL;
	}

	ops = dlsym(dlhandle, "ioengine");
	if (!ops) {
		td_vmsg(td, -1, dlerror());
		dlclose(dlhandle);
		return NULL;
	}

	if (ops->version != FIO_IOOPS_VERSION) {
		log_err("bad ioops version %d (want %d)\n", ops->version, FIO_IOOPS_VERSION);
		dlclose(dlhandle);
		return NULL;
	}

	/*
	 * Check that the required methods are there.
	 */
	if (check_engine_ops(ops)) {
		dlclose(dlhandle);
		return NULL;
	}

	ret = malloc(sizeof(*ret));
	memcpy(ret, ops, sizeof(*ret));
	ret->data = NULL;
	ret->dlhandle = dlhandle;

	return ret;
}

void close_ioengine(struct thread_data *td)
{
	if (td->io_ops->cleanup)
		td->io_ops->cleanup(td);

	dlclose(td->io_ops->dlhandle);
	free(td->io_ops);
	td->io_ops = NULL;
}

int td_io_prep(struct thread_data *td, struct io_u *io_u)
{
	if (td->io_ops->prep && td->io_ops->prep(td, io_u))
		return 1;

	return 0;
}

int td_io_sync(struct thread_data *td, struct fio_file *f)
{
	if (td->io_ops->sync)
		return td->io_ops->sync(td, f);

	return 0;
}

int td_io_getevents(struct thread_data *td, int min, int max,
		    struct timespec *t)
{
	return td->io_ops->getevents(td, min, max, t);
}

int td_io_queue(struct thread_data *td, struct io_u *io_u)
{
	gettimeofday(&io_u->issue_time, NULL);

	return td->io_ops->queue(td, io_u);
}

int td_io_init(struct thread_data *td)
{
	if (td->io_ops->init)
		return td->io_ops->init(td);

	return 0;
}
