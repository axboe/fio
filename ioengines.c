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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>

#include "fio.h"
#include "diskutil.h"
#include "zbd.h"

static FLIST_HEAD(engine_list);

static inline bool async_ioengine_sync_trim(struct thread_data *td,
					    struct io_u	*io_u)
{
	return td_ioengine_flagged(td, FIO_ASYNCIO_SYNC_TRIM) &&
		io_u->ddir == DDIR_TRIM;
}

static bool check_engine_ops(struct thread_data *td, struct ioengine_ops *ops)
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

	/*
	 * async engines aren't reliable with offload
	 */
	if ((td->o.io_submit_mode == IO_MODE_OFFLOAD) &&
	    (ops->flags & FIO_NO_OFFLOAD)) {
		log_err("%s: can't be used with offloaded submit. Use a sync "
			"engine\n", ops->name);
		return true;
	}

	if (!ops->event || !ops->getevents) {
		log_err("%s: no event/getevents handler\n", ops->name);
		return true;
	}

	return false;
}

void unregister_ioengine(struct ioengine_ops *ops)
{
	dprint(FD_IO, "ioengine %s unregistered\n", ops->name);
	flist_del_init(&ops->list);
}

void register_ioengine(struct ioengine_ops *ops)
{
	dprint(FD_IO, "ioengine %s registered\n", ops->name);
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

#ifdef CONFIG_DYNAMIC_ENGINES
static void *dlopen_external(struct thread_data *td, const char *engine)
{
	char engine_path[PATH_MAX];
	void *dlhandle;

	sprintf(engine_path, "%s/fio-%s.so", FIO_EXT_ENG_DIR, engine);

	dprint(FD_IO, "dlopen external %s\n", engine_path);
	dlhandle = dlopen(engine_path, RTLD_LAZY);
	if (!dlhandle)
		log_info("Engine %s not found; Either name is invalid, was not built, or fio-engine-%s package is missing.\n",
			 engine, engine);

	return dlhandle;
}
#else
#define dlopen_external(td, engine) (NULL)
#endif

static struct ioengine_ops *dlopen_ioengine(struct thread_data *td,
					    const char *engine_lib)
{
	struct ioengine_ops *ops;
	void *dlhandle;

	if (!strncmp(engine_lib, "linuxaio", 8) ||
	    !strncmp(engine_lib, "aio", 3))
		engine_lib = "libaio";

	dprint(FD_IO, "dlopen engine %s\n", engine_lib);

	dlerror();
	dlhandle = dlopen(engine_lib, RTLD_LAZY);
	if (!dlhandle) {
		dlhandle = dlopen_external(td, engine_lib);
		if (!dlhandle) {
			td_vmsg(td, -1, dlerror(), "dlopen");
			return NULL;
		}
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

	ops->dlhandle = dlhandle;
	return ops;
}

static struct ioengine_ops *__load_ioengine(const char *engine)
{
	/*
	 * linux libaio has alias names, so convert to what we want
	 */
	if (!strncmp(engine, "linuxaio", 8) || !strncmp(engine, "aio", 3)) {
		dprint(FD_IO, "converting ioengine name: %s -> libaio\n",
		       engine);
		engine = "libaio";
	}

	dprint(FD_IO, "load ioengine %s\n", engine);
	return find_ioengine(engine);
}

struct ioengine_ops *load_ioengine(struct thread_data *td)
{
	struct ioengine_ops *ops = NULL;
	const char *name;

	/*
	 * Use ->ioengine_so_path if an external ioengine path is specified.
	 * In this case, ->ioengine is "external" which also means the prefix
	 * for external ioengines "external:" is properly used.
	 */
	name = td->o.ioengine_so_path ?: td->o.ioengine;

	/*
	 * Try to load ->ioengine first, and if failed try to dlopen(3) either
	 * ->ioengine or ->ioengine_so_path.  This is redundant for an external
	 * ioengine with prefix, and also leaves the possibility of unexpected
	 * behavior (e.g. if the "external" ioengine exists), but we do this
	 * so as not to break job files not using the prefix.
	 */
	ops = __load_ioengine(td->o.ioengine);

	/* We do re-dlopen existing handles, for reference counting */
	if (!ops || ops->dlhandle)
		ops = dlopen_ioengine(td, name);

	/*
	 * If ops is NULL, we failed to load ->ioengine, and also failed to
	 * dlopen(3) either ->ioengine or ->ioengine_so_path as a path.
	 */
	if (!ops) {
		log_err("fio: engine %s not loadable\n", name);
		return NULL;
	}

	/*
	 * Check that the required methods are there.
	 */
	if (check_engine_ops(td, ops))
		return NULL;

	return ops;
}

/*
 * For cleaning up an ioengine which never made it to init().
 */
void free_ioengine(struct thread_data *td)
{
	assert(td != NULL && td->io_ops != NULL);

	dprint(FD_IO, "free ioengine %s\n", td->io_ops->name);

	if (td->eo && td->io_ops->options) {
		options_free(td->io_ops->options, td->eo);
		free(td->eo);
		td->eo = NULL;
	}

	if (td->io_ops->dlhandle) {
		dprint(FD_IO, "dlclose ioengine %s\n", td->io_ops->name);
		dlclose(td->io_ops->dlhandle);
	}

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

		dprint(FD_IO, "prep: io_u %p: ret=%d\n", io_u, ret);

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

enum fio_q_status td_io_queue(struct thread_data *td, struct io_u *io_u)
{
	const enum fio_ddir ddir = acct_ddir(io_u);
	unsigned long long buflen = io_u->xfer_buflen;
	enum fio_q_status ret;

	dprint_io_u(io_u, "queue");
	fio_ro_check(td, io_u);

	assert((io_u->flags & IO_U_F_FLIGHT) == 0);
	io_u_set(td, io_u, IO_U_F_FLIGHT);

	/*
	 * If overlap checking was enabled in offload mode we
	 * can release this lock that was acquired when we
	 * started the overlap check because the IO_U_F_FLIGHT
	 * flag is now set
	 */
	if (td_offload_overlap(td)) {
		int res;

		res = pthread_mutex_unlock(&overlap_check);
		if (fio_unlikely(res != 0)) {
			log_err("failed to unlock overlap check mutex, err: %i:%s", errno, strerror(errno));
			abort();
		}
	}

	assert(fio_file_open(io_u->file));

	/*
	 * If using a write iolog, store this entry.
	 */
	log_io_u(td, io_u);

	io_u->error = 0;
	io_u->resid = 0;

	if (td_ioengine_flagged(td, FIO_SYNCIO) ||
		async_ioengine_sync_trim(td, io_u)) {
		if (fio_fill_issue_time(td)) {
			fio_gettime(&io_u->issue_time, NULL);

			/*
			 * only used for iolog
			 */
			if (td->o.read_iolog_file)
				memcpy(&td->last_issue, &io_u->issue_time,
						sizeof(io_u->issue_time));
		}
	}


	if (ddir_rw(ddir)) {
		if (!(io_u->flags & IO_U_F_VER_LIST)) {
			td->io_issues[ddir]++;
			td->io_issue_bytes[ddir] += buflen;
		}
		td->rate_io_issue_bytes[ddir] += buflen;
	}

	ret = td->io_ops->queue(td, io_u);
	zbd_queue_io_u(td, io_u, &ret);

	unlock_file(td, io_u->file);

	if (ret == FIO_Q_BUSY) {
	       if (ddir_rw(ddir)) {
			td->io_issues[ddir]--;
			td->io_issue_bytes[ddir] -= buflen;
			td->rate_io_issue_bytes[ddir] -= buflen;
		}
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
			 "support direct IO, or iomem_align= is bad, or "
			 "invalid block size. Try setting direct=0.\n");
	}

	if (zbd_unaligned_write(io_u->error) &&
	    td->io_issues[io_u->ddir & 1] == 1 &&
	    td->o.zone_mode != ZONE_MODE_ZBD) {
		log_info("fio: first I/O failed. If %s is a zoned block device, consider --zonemode=zbd\n",
			 io_u->file->file_name);
	}

	if (!td->io_ops->commit) {
		io_u_mark_submit(td, 1);
		io_u_mark_complete(td, 1);
	}

	if (ret == FIO_Q_COMPLETED) {
		if (ddir_rw(io_u->ddir) ||
		    (ddir_sync(io_u->ddir) && td->runstate != TD_FSYNCING)) {
			io_u_mark_depth(td, 1);
			td->ts.total_io_u[io_u->ddir]++;
		}

		td->last_ddir_issued = ddir;
	} else if (ret == FIO_Q_QUEUED) {
		td->io_u_queued++;

		if (ddir_rw(io_u->ddir) ||
		    (ddir_sync(io_u->ddir) && td->runstate != TD_FSYNCING))
			td->ts.total_io_u[io_u->ddir]++;

		if (td->io_u_queued >= td->o.iodepth_batch)
			td_io_commit(td);

		td->last_ddir_issued = ddir;
	}

	if (!td_ioengine_flagged(td, FIO_SYNCIO) &&
		!async_ioengine_sync_trim(td, io_u)) {
		if (fio_fill_issue_time(td) &&
			!td_ioengine_flagged(td, FIO_ASYNCIO_SETS_ISSUE_TIME)) {
			fio_gettime(&io_u->issue_time, NULL);

			/*
			 * only used for iolog
			 */
			if (td->o.read_iolog_file)
				memcpy(&td->last_issue, &io_u->issue_time,
						sizeof(io_u->issue_time));
		}
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

void td_io_commit(struct thread_data *td)
{
	int ret;

	dprint(FD_IO, "calling ->commit(), depth %d\n", td->cur_depth);

	if (!td->cur_depth || !td->io_u_queued)
		return;

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
}

int td_io_open_file(struct thread_data *td, struct fio_file *f)
{
	if (fio_file_closing(f)) {
		/*
		 * Open translates to undo closing.
		 */
		fio_file_clear_closing(f);
		get_file(f);
		return 0;
	}
	assert(!fio_file_open(f));
	assert(f->fd == -1);
	assert(td->io_ops->open_file);

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
#ifdef POSIX_FADV_NOREUSE
		else if (td->o.fadvise_hint == F_ADV_NOREUSE)
			flags = POSIX_FADV_NOREUSE;
#endif
		else {
			log_err("fio: unknown fadvise type %d\n",
							td->o.fadvise_hint);
			flags = POSIX_FADV_NORMAL;
		}

		if (posix_fadvise(f->fd, f->file_offset, f->io_size, flags) < 0) {
			if (!fio_did_warn(FIO_WARN_FADVISE))
				log_err("fio: fadvise hint failed\n");
		}
	}
#ifdef FIO_HAVE_WRITE_HINT
	if (fio_option_is_set(&td->o, write_hint) &&
	    (f->filetype == FIO_TYPE_BLOCK || f->filetype == FIO_TYPE_FILE)) {
		uint64_t hint = td->o.write_hint;
		int res;

		/*
		 * For direct IO, set the hint on the file descriptor if that is
		 * supported. Otherwise set it on the inode. For buffered IO, we
		 * need to set it on the inode.
		 */
		if (td->o.odirect) {
			res = fcntl(f->fd, F_SET_FILE_RW_HINT, &hint);
			if (res < 0)
				res = fcntl(f->fd, F_SET_RW_HINT, &hint);
		} else {
			res = fcntl(f->fd, F_SET_RW_HINT, &hint);
		}
		if (res < 0) {
			td_verror(td, errno, "fcntl write hint");
			goto err;
		}
	}
#endif

	if (td->o.odirect && !OS_O_DIRECT && fio_set_directio(td, f))
		goto err;

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

#ifdef CONFIG_DYNAMIC_ENGINES
/* Load all dynamic engines in FIO_EXT_ENG_DIR for enghelp command */
static void
fio_load_dynamic_engines(struct thread_data *td)
{
	DIR *dirhandle = NULL;
	struct dirent *dirent = NULL;
	char engine_path[PATH_MAX];

	dirhandle = opendir(FIO_EXT_ENG_DIR);
	if (!dirhandle)
		return;

	while ((dirent = readdir(dirhandle)) != NULL) {
		if (!strcmp(dirent->d_name, ".") ||
		    !strcmp(dirent->d_name, ".."))
			continue;

		sprintf(engine_path, "%s/%s", FIO_EXT_ENG_DIR, dirent->d_name);
		dlopen_ioengine(td, engine_path);
	}

	closedir(dirhandle);
}
#else
#define fio_load_dynamic_engines(td) do { } while (0)
#endif

int fio_show_ioengine_help(const char *engine)
{
	struct flist_head *entry;
	struct thread_data td;
	struct ioengine_ops *io_ops;
	char *sep;
	int ret = 1;

	memset(&td, 0, sizeof(struct thread_data));

	if (!engine || !*engine) {
		log_info("Available IO engines:\n");
		fio_load_dynamic_engines(&td);
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

	td.o.ioengine = (char *)engine;
	td.io_ops = load_ioengine(&td);

	if (!td.io_ops) {
		log_info("IO engine %s not found\n", engine);
		return 1;
	}

	if (td.io_ops->options)
		ret = show_cmd_help(td.io_ops->options, sep);
	else
		log_info("IO engine %s has no options\n", td.io_ops->name);

	free_ioengine(&td);
	return ret;
}
