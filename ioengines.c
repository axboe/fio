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

static LIST_HEAD(engine_list);

static int check_engine_ops(struct ioengine_ops *ops)
{
	if (ops->version != FIO_IOOPS_VERSION) {
		log_err("bad ioops version %d (want %d)\n", ops->version, FIO_IOOPS_VERSION);
		return 1;
	}

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

void unregister_ioengine(struct ioengine_ops *ops)
{
	list_del(&ops->list);
	INIT_LIST_HEAD(&ops->list);
}

int register_ioengine(struct ioengine_ops *ops)
{
	if (check_engine_ops(ops))
		return 1;

	INIT_LIST_HEAD(&ops->list);
	list_add_tail(&ops->list, &engine_list);
	return 0;
}

static struct ioengine_ops *find_ioengine(const char *name)
{
	struct ioengine_ops *ops;
	struct list_head *entry;
	char engine[16];

	strncpy(engine, name, sizeof(engine) - 1);

	if (!strncmp(engine, "linuxaio", 8) || !strncmp(engine, "aio", 3))
		strcpy(engine, "libaio");

	list_for_each(entry, &engine_list) {
		ops = list_entry(entry, struct ioengine_ops, list);
		if (!strcmp(engine, ops->name))
			return ops;
	}

	return NULL;
}

static struct ioengine_ops *dlopen_ioengine(struct thread_data *td,
					    const char *engine_lib)
{
	struct ioengine_ops *ops;
	void *dlhandle;

	dlerror();
	dlhandle = dlopen(engine_lib, RTLD_LAZY);
	if (!dlhandle) {
		td_vmsg(td, -1, dlerror());
		return NULL;
	}

	/*
	 * Unlike the included modules, external engines should have a
	 * non-static ioengine structure that we can reference.
	 */
	ops = dlsym(dlhandle, "ioengine");
	if (!ops) {
		td_vmsg(td, -1, dlerror());
		dlclose(dlhandle);
		return NULL;
	}

	ops->dlhandle = dlhandle;
	return ops;
}

struct ioengine_ops *load_ioengine(struct thread_data *td, const char *name)
{
	struct ioengine_ops *ops, *ret;
	char engine[16];

	strncpy(engine, name, sizeof(engine) - 1);

	/*
	 * linux libaio has alias names, so convert to what we want
	 */
	if (!strncmp(engine, "linuxaio", 8) || !strncmp(engine, "aio", 3))
		strcpy(engine, "libaio");

	ops = find_ioengine(engine);
	if (!ops)
		ops = dlopen_ioengine(td, name);

	if (!ops) {
		log_err("fio: engine %s not loadable\n", name);
		return NULL;
	}

	/*
	 * Check that the required methods are there.
	 */
	if (check_engine_ops(ops))
		return NULL;

	ret = malloc(sizeof(*ret));
	memcpy(ret, ops, sizeof(*ret));
	ret->data = NULL;

	return ret;
}

void close_ioengine(struct thread_data *td)
{
	if (td->io_ops->cleanup)
		td->io_ops->cleanup(td);

	if (td->io_ops->dlhandle)
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

int td_io_getevents(struct thread_data *td, int min, int max,
		    struct timespec *t)
{
	return td->io_ops->getevents(td, min, max, t);
}

int td_io_queue(struct thread_data *td, struct io_u *io_u)
{
	fio_gettime(&io_u->issue_time, NULL);

	return td->io_ops->queue(td, io_u);
}

int td_io_init(struct thread_data *td)
{
	if (td->io_ops->init)
		return td->io_ops->init(td);

	return 0;
}
