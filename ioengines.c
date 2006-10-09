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

struct ioengine_ops *load_ioengine(struct thread_data *td, char *name)
{
	char engine[16], engine_lib[256];
	struct ioengine_ops *ops;
	void *dlhandle;

	strcpy(engine, name);

	/*
	 * linux libaio has alias names, so convert to what we want
	 */
	if (!strncmp(engine, "linuxaio", 8) || !strncmp(engine, "aio", 3))
		strcpy(engine, "libaio");

	sprintf(engine_lib, "/usr/local/lib/fio/fio-engine-%s.o", engine);
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

	ops->dlhandle = dlhandle;
	return ops;
}

void close_ioengine(struct thread_data *td)
{
	if (td->io_ops->cleanup)
		td->io_ops->cleanup(td);

	dlclose(td->io_ops->dlhandle);
}
