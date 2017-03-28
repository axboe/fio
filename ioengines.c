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
#include <fcntl.h>
#include <assert.h>

#include "fio.h"
#include "diskutil.h"

static FLIST_HEAD(engine_list);

static bool check_engine_ops(struct ioengine_ops *ops)
{
	if (ops->version != FIO_IOOPS_VERSION) {
		log_err("bad ioops version %d (want %d)\n", ops->version,
							FIO_IOOPS_VERSION);
		return true;
	}

	if (!ops->queue) {
		log_err("%s: no queue handler\n", ops->name);
		return true;
	}

	/*
	 * sync engines only need a ->queue()
	 */
	if (ops->flags & FIO_SYNCIO)
		return false;

	if (!ops->event || !ops->getevents) {
		log_err("%s: no event/getevents handler\n", ops->name);
		return true;
	}

	return false;
}

void unregister_ioengine(struct ioengine_ops *ops)
{
	dprint(FD_IO, "ioengine %s unregistered\n", ops->name);
	flist_del(&ops->list);
	INIT_FLIST_HEAD(&ops->list);
}

void register_ioengine(struct ioengine_ops *ops)
{
	dprint(FD_IO, "ioengine %s registered\n", ops->name);
	INIT_FLIST_HEAD(&ops->list);
	flist_add_tail(&ops->list, &engine_list);
}

static struct ioengine_ops *find_ioengine(const char *name)
{
	struct ioengine_ops *ops;
	struct flist_head *entry;

	flist_for_each(entry, &engine_list) {
		ops = flist_entry(entry, struct ioengine_ops, list);
		if (!strcmp(name, ops->name))
			return ops;
	}

	return NULL;
}

static struct ioengine_ops *dlopen_ioengine(struct thread_data *td,
					    const char *engine_lib)
{
	struct ioengine_ops *ops;
	void *dlhandle;

	dprint(FD_IO, "dload engine %s\n", engine_lib);

	dlerror();
	dlhandle = dlopen(engine_lib, RTLD_LAZY);
	if (!dlhandle) {
		td_vmsg(td, -1, dlerror(), "dlopen");
		return NULL;
	}

	/*
	 * Unlike the included modules, external engines should have a
	 * non-static ioengine structure that we can reference.
	 */
	ops = dlsym(dlhandle, engine_lib);
	if (!ops)
		ops = dlsym(dlhandle, "ioengine");

	/*
	 * For some external engines (like C++ ones) it is not that trivial
	 * to provide a non-static ionengine structure that we can reference.
	 * Instead we call a method which allocates the required ioengine
	 * structure.
	 */
	if (!ops) {
		get_ioengine_t get_ioengine = dlsym(dlhandle, "get_ioengine");

		if (get_ioengine)
			get_ioengine(&ops);
	}

	if (!ops) {
		td_vmsg(td, -1, dlerror(), "dlsym");
		dlclose(dlhandle);
		return NULL;
	}

	td->io_ops_dlhandle = dlhandle;
	return ops;
}

struct ioengine_ops *load_ioengine(struct thread_data *td, const char *name)
{
	struct ioengine_ops *ops;
	char engine[64];

	dprint(FD_IO, "load ioengine %s\n", name);

	engine[sizeof(engine) - 1] = '\0';
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

	return ops;
}

/*
 * For cleaning up an ioengine which never made it to init().
 */
void free_ioengine(struct thread_data *td)
{
	dprint(FD_IO, "free ioengine %s\n", td->io_ops->name);

	if (td->eo && td->io_ops->options) {
		options_free(td->io_ops->options, td->eo);
		free(td->eo);
		td->eo = NULL;
	}

	if (td->io_ops_dlhandle)
		dlclose(td->io_ops_dlhandle);

	td->io_ops = NULL;
}

void close_ioengine(struct thread_data *td)
{
	dprint(FD_IO, "close ioengine %s\n", td->io_ops->name);

	if (td->io_ops->cleanup) {
		td->io_ops->cleanup(td);
		td->io_ops_data = NULL;
	}

	free_ioengine(td);
}

int td_io_prep(struct thread_data *td, struct io_u *io_u)
{
	dprint_io_u(io_u, "prep");
	fio_ro_check(td, io_u);

	lock_file(td, io_u->file, io_u->ddir);

	if (td->io_ops->prep) {
		int ret = td->io_ops->prep(td, io_u);

		dprint(FD_IO, "->prep(%p)=%d\n", io_u, ret);
		if (ret)
			unlock_file(td, io_u->file);
		return ret;
	}

	return 0;
}

int td_io_getevents(struct thread_data *td, unsigned int min, unsigned int max,
		    const struct timespec *t)
{
	int r = 0;

	/*
	 * For ioengine=rdma one side operation RDMA_WRITE or RDMA_READ,
	 * server side gets a message from the client
	 * side that the task is finished, and
	 * td->done is set to 1 after td_io_commit(). In this case,
	 * there is no need to reap complete event in server side.
	 */
	if (td->done)
		return 0;

	if (min > 0 && td->io_ops->commit) {
		r = td->io_ops->commit(td);
		if (r < 0)
			goto out;
	}
	if (max > td->cur_depth)
		max = td->cur_depth;
	if (min > max)
		max = min;

	r = 0;
	if (max && td->io_ops->getevents)
		r = td->io_ops->getevents(td, min, max, t);
out:
	if (r >= 0) {
		/*
		 * Reflect that our submitted requests were retrieved with
		 * whatever OS async calls are in the underlying engine.
		 */
		td->io_u_in_flight -= r;
		io_u_mark_complete(td, r);
	} else
		td_verror(td, r, "get_events");

	dprint(FD_IO, "getevents: %d\n", r);
	return r;
}

int td_io_queue(struct thread_data *td, struct io_u *io_u)
{
	const enum fio_ddir ddir = acct_ddir(io_u);
	unsigned long buflen = io_u->xfer_buflen;
	int ret;

	dprint_io_u(io_u, "queue");
	fio_ro_check(td, io_u);

	assert((io_u->flags & IO_U_F_FLIGHT) == 0);
	io_u_set(td, io_u, IO_U_F_FLIGHT);

	assert(fio_file_open(io_u->file));

	/*
	 * If using a write iolog, store this entry.
	 */
	log_io_u(td, io_u);

	io_u->error = 0;
	io_u->resid = 0;

	if (td_ioengine_flagged(td, FIO_SYNCIO)) {
		if (fio_fill_issue_time(td))
			fio_gettime(&io_u->issue_time, NULL);

		/*
		 * only used for iolog
		 */
		if (td->o.read_iolog_file)
			memcpy(&td->last_issue, &io_u->issue_time,
					sizeof(struct timeval));
	}

	if (ddir_rw(ddir)) {
		td->io_issues[ddir]++;
		td->io_issue_bytes[ddir] += buflen;
		td->rate_io_issue_bytes[ddir] += buflen;
	}

	ret = td->io_ops->queue(td, io_u);

	unlock_file(td, io_u->file);

	if (ret == FIO_Q_BUSY && ddir_rw(ddir)) {
		td->io_issues[ddir]--;
		td->io_issue_bytes[ddir] -= buflen;
		td->rate_io_issue_bytes[ddir] -= buflen;
		io_u_clear(td, io_u, IO_U_F_FLIGHT);
	}

	/*
	 * If an error was seen and the io engine didn't propagate it
	 * back to 'td', do so.
	 */
	if (io_u->error && !td->error)
		td_verror(td, io_u->error, "td_io_queue");

	/*
	 * Add warning for O_DIRECT so that users have an easier time
	 * spotting potentially bad alignment. If this triggers for the first
	 * IO, then it's likely an alignment problem or because the host fs
	 * does not support O_DIRECT
	 */
	if (io_u->error == EINVAL && td->io_issues[io_u->ddir & 1] == 1 &&
	    td->o.odirect) {

		log_info("fio: first direct IO errored. File system may not "
			 "support direct IO, or iomem_align= is bad. Try "
			 "setting direct=0.\n");
	}

	if (!td->io_ops->commit || io_u->ddir == DDIR_TRIM) {
		io_u_mark_submit(td, 1);
		io_u_mark_complete(td, 1);
	}

	if (ret == FIO_Q_COMPLETED) {
		if (ddir_rw(io_u->ddir)) {
			io_u_mark_depth(td, 1);
			td->ts.total_io_u[io_u->ddir]++;
		}
	} else if (ret == FIO_Q_QUEUED) {
		int r;

		td->io_u_queued++;

		if (ddir_rw(io_u->ddir))
			td->ts.total_io_u[io_u->ddir]++;

		if (td->io_u_queued >= td->o.iodepth_batch) {
			r = td_io_commit(td);
			if (r < 0)
				return r;
		}
	}

	if (!td_ioengine_flagged(td, FIO_SYNCIO)) {
		if (fio_fill_issue_time(td))
			fio_gettime(&io_u->issue_time, NULL);

		/*
		 * only used for iolog
		 */
		if (td->o.read_iolog_file)
			memcpy(&td->last_issue, &io_u->issue_time,
					sizeof(struct timeval));
	}

	return ret;
}

int td_io_init(struct thread_data *td)
{
	int ret = 0;

	if (td->io_ops->init) {
		ret = td->io_ops->init(td);
		if (ret)
			log_err("fio: io engine %s init failed.%s\n",
				td->io_ops->name,
				td->o.iodepth > 1 ?
				" Perhaps try reducing io depth?" : "");
		else
			td->io_ops_init = 1;
		if (!td->error)
			td->error = ret;
	}

	return ret;
}

int td_io_commit(struct thread_data *td)
{
	int ret;

	dprint(FD_IO, "calling ->commit(), depth %d\n", td->cur_depth);

	if (!td->cur_depth || !td->io_u_queued)
		return 0;

	io_u_mark_depth(td, td->io_u_queued);

	if (td->io_ops->commit) {
		ret = td->io_ops->commit(td);
		if (ret)
			td_verror(td, -ret, "io commit");
	}

	/*
	 * Reflect that events were submitted as async IO requests.
	 */
	td->io_u_in_flight += td->io_u_queued;
	td->io_u_queued = 0;

	return 0;
}

int td_io_open_file(struct thread_data *td, struct fio_file *f)
{
	assert(!fio_file_open(f));
	assert(f->fd == -1);

	if (td->io_ops->open_file(td, f)) {
		if (td->error == EINVAL && td->o.odirect)
			log_err("fio: destination does not support O_DIRECT\n");
		if (td->error == EMFILE) {
			log_err("fio: try reducing/setting openfiles (failed"
				" at %u of %u)\n", td->nr_open_files,
							td->o.nr_files);
		}

		assert(f->fd == -1);
		assert(!fio_file_open(f));
		return 1;
	}

	fio_file_reset(td, f);
	fio_file_set_open(f);
	fio_file_clear_closing(f);
	disk_util_inc(f->du);

	td->nr_open_files++;
	get_file(f);

	if (f->filetype == FIO_TYPE_PIPE) {
		if (td_random(td)) {
			log_err("fio: can't seek on pipes (no random io)\n");
			goto err;
		}
	}

	if (td_ioengine_flagged(td, FIO_DISKLESSIO))
		goto done;

	if (td->o.invalidate_cache && file_invalidate_cache(td, f))
		goto err;

	if (td->o.fadvise_hint != F_ADV_NONE &&
	    (f->filetype == FIO_TYPE_BLOCK || f->filetype == FIO_TYPE_FILE)) {
		int flags;

		if (td->o.fadvise_hint == F_ADV_TYPE) {
			if (td_random(td))
				flags = POSIX_FADV_RANDOM;
			else
				flags = POSIX_FADV_SEQUENTIAL;
		} else if (td->o.fadvise_hint == F_ADV_RANDOM)
			flags = POSIX_FADV_RANDOM;
		else if (td->o.fadvise_hint == F_ADV_SEQUENTIAL)
			flags = POSIX_FADV_SEQUENTIAL;
		else {
			log_err("fio: unknown fadvise type %d\n",
							td->o.fadvise_hint);
			flags = POSIX_FADV_NORMAL;
		}

		if (posix_fadvise(f->fd, f->file_offset, f->io_size, flags) < 0) {
			td_verror(td, errno, "fadvise");
			goto err;
		}
	}
#ifdef FIO_HAVE_STREAMID
	if (td->o.fadvise_stream &&
	    (f->filetype == FIO_TYPE_BLOCK || f->filetype == FIO_TYPE_FILE)) {
		off_t stream = td->o.fadvise_stream;

		if (posix_fadvise(f->fd, stream, f->io_size, POSIX_FADV_STREAMID) < 0) {
			td_verror(td, errno, "fadvise streamid");
			goto err;
		}
	}
#endif

#ifdef FIO_OS_DIRECTIO
	/*
	 * Some OS's have a distinct call to mark the file non-buffered,
	 * instead of using O_DIRECT (Solaris)
	 */
	if (td->o.odirect) {
		int ret = fio_set_odirect(f->fd);

		if (ret) {
			td_verror(td, ret, "fio_set_odirect");
			if (ret == ENOTTY) { /* ENOTTY suggests RAW device or ZFS */
				log_err("fio: doing directIO to RAW devices or ZFS not supported\n");
			} else {
				log_err("fio: the file system does not seem to support direct IO\n");
			}

			goto err;
		}
	}
#endif

done:
	log_file(td, f, FIO_LOG_OPEN_FILE);
	return 0;
err:
	disk_util_dec(f->du);
	if (td->io_ops->close_file)
		td->io_ops->close_file(td, f);
	return 1;
}

int td_io_close_file(struct thread_data *td, struct fio_file *f)
{
	if (!fio_file_closing(f))
		log_file(td, f, FIO_LOG_CLOSE_FILE);

	/*
	 * mark as closing, do real close when last io on it has completed
	 */
	fio_file_set_closing(f);

	disk_util_dec(f->du);

	if (td->o.file_lock_mode != FILE_LOCK_NONE)
		unlock_file_all(td, f);

	return put_file(td, f);
}

int td_io_unlink_file(struct thread_data *td, struct fio_file *f)
{
	if (td->io_ops->unlink_file)
		return td->io_ops->unlink_file(td, f);
	else {
		int ret;

		ret = unlink(f->file_name);
		if (ret < 0)
			return errno;

		return 0;
	}
}

int td_io_get_file_size(struct thread_data *td, struct fio_file *f)
{
	if (!td->io_ops->get_file_size)
		return 0;

	return td->io_ops->get_file_size(td, f);
}

int fio_show_ioengine_help(const char *engine)
{
	struct flist_head *entry;
	struct thread_data td;
	struct ioengine_ops *io_ops;
	char *sep;
	int ret = 1;

	if (!engine || !*engine) {
		log_info("Available IO engines:\n");
		flist_for_each(entry, &engine_list) {
			io_ops = flist_entry(entry, struct ioengine_ops, list);
			log_info("\t%s\n", io_ops->name);
		}
		return 0;
	}
	sep = strchr(engine, ',');
	if (sep) {
		*sep = 0;
		sep++;
	}

	memset(&td, 0, sizeof(td));

	io_ops = load_ioengine(&td, engine);
	if (!io_ops) {
		log_info("IO engine %s not found\n", engine);
		return 1;
	}

	if (io_ops->options)
		ret = show_cmd_help(io_ops->options, sep);
	else
		log_info("IO engine %s has no options\n", io_ops->name);

	free_ioengine(&td);

	return ret;
}
