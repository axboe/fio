/*
 * Code related to writing an iolog of what a thread is doing, and to
 * later read that back and replay
 */
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <assert.h>
#include "flist.h"
#include "fio.h"
#include "verify.h"
#include "trim.h"
#include "filelock.h"

static const char iolog_ver2[] = "fio version 2 iolog";

void queue_io_piece(struct thread_data *td, struct io_piece *ipo)
{
	flist_add_tail(&ipo->list, &td->io_log_list);
	td->total_io_size += ipo->len;
}

void log_io_u(struct thread_data *td, struct io_u *io_u)
{
	const char *act[] = { "read", "write", "sync", "datasync",
				"sync_file_range", "wait", "trim" };

	assert(io_u->ddir <= 6);

	if (!td->o.write_iolog_file)
		return;

	fprintf(td->iolog_f, "%s %s %llu %lu\n", io_u->file->file_name,
						act[io_u->ddir], io_u->offset,
						io_u->buflen);
}

void log_file(struct thread_data *td, struct fio_file *f,
	      enum file_log_act what)
{
	const char *act[] = { "add", "open", "close" };

	assert(what < 3);

	if (!td->o.write_iolog_file)
		return;


	/*
	 * this happens on the pre-open/close done before the job starts
	 */
	if (!td->iolog_f)
		return;

	fprintf(td->iolog_f, "%s %s\n", f->file_name, act[what]);
}

static void iolog_delay(struct thread_data *td, unsigned long delay)
{
	unsigned long usec = utime_since_now(&td->last_issue);
	unsigned long this_delay;

	if (delay < usec)
		return;

	delay -= usec;

	/*
	 * less than 100 usec delay, just regard it as noise
	 */
	if (delay < 100)
		return;

	while (delay && !td->terminate) {
		this_delay = delay;
		if (this_delay > 500000)
			this_delay = 500000;

		usec_sleep(td, this_delay);
		delay -= this_delay;
	}
}

static int ipo_special(struct thread_data *td, struct io_piece *ipo)
{
	struct fio_file *f;
	int ret;

	/*
	 * Not a special ipo
	 */
	if (ipo->ddir != DDIR_INVAL)
		return 0;

	f = td->files[ipo->fileno];

	switch (ipo->file_action) {
	case FIO_LOG_OPEN_FILE:
		ret = td_io_open_file(td, f);
		if (!ret)
			break;
		td_verror(td, ret, "iolog open file");
		return -1;
	case FIO_LOG_CLOSE_FILE:
		td_io_close_file(td, f);
		break;
	case FIO_LOG_UNLINK_FILE:
		unlink(f->file_name);
		break;
	default:
		log_err("fio: bad file action %d\n", ipo->file_action);
		break;
	}

	return 1;
}

int read_iolog_get(struct thread_data *td, struct io_u *io_u)
{
	struct io_piece *ipo;
	unsigned long elapsed;

	while (!flist_empty(&td->io_log_list)) {
		int ret;

		ipo = flist_entry(td->io_log_list.next, struct io_piece, list);
		flist_del(&ipo->list);
		remove_trim_entry(td, ipo);

		ret = ipo_special(td, ipo);
		if (ret < 0) {
			free(ipo);
			break;
		} else if (ret > 0) {
			free(ipo);
			continue;
		}

		io_u->ddir = ipo->ddir;
		if (ipo->ddir != DDIR_WAIT) {
			io_u->offset = ipo->offset;
			io_u->buflen = ipo->len;
			io_u->file = td->files[ipo->fileno];
			get_file(io_u->file);
			dprint(FD_IO, "iolog: get %llu/%lu/%s\n", io_u->offset,
						io_u->buflen, io_u->file->file_name);
			if (ipo->delay)
				iolog_delay(td, ipo->delay);
		} else {
			elapsed = mtime_since_genesis();
			if (ipo->delay > elapsed)
				usec_sleep(td, (ipo->delay - elapsed) * 1000);
		}

		free(ipo);

		if (io_u->ddir != DDIR_WAIT)
			return 0;
	}

	td->done = 1;
	return 1;
}

void prune_io_piece_log(struct thread_data *td)
{
	struct io_piece *ipo;
	struct rb_node *n;

	while ((n = rb_first(&td->io_hist_tree)) != NULL) {
		ipo = rb_entry(n, struct io_piece, rb_node);
		rb_erase(n, &td->io_hist_tree);
		remove_trim_entry(td, ipo);
		td->io_hist_len--;
		free(ipo);
	}

	while (!flist_empty(&td->io_hist_list)) {
		ipo = flist_entry(td->io_hist_list.next, struct io_piece, list);
		flist_del(&ipo->list);
		remove_trim_entry(td, ipo);
		td->io_hist_len--;
		free(ipo);
	}
}

/*
 * log a successful write, so we can unwind the log for verify
 */
void log_io_piece(struct thread_data *td, struct io_u *io_u)
{
	struct rb_node **p, *parent;
	struct io_piece *ipo, *__ipo;

	ipo = malloc(sizeof(struct io_piece));
	init_ipo(ipo);
	ipo->file = io_u->file;
	ipo->offset = io_u->offset;
	ipo->len = io_u->buflen;
	ipo->numberio = io_u->numberio;
	ipo->flags = IP_F_IN_FLIGHT;

	io_u->ipo = ipo;

	if (io_u_should_trim(td, io_u)) {
		flist_add_tail(&ipo->trim_list, &td->trim_list);
		td->trim_entries++;
	}

	/*
	 * We don't need to sort the entries, if:
	 *
	 *	Sequential writes, or
	 *	Random writes that lay out the file as it goes along
	 *
	 * For both these cases, just reading back data in the order we
	 * wrote it out is the fastest.
	 *
	 * One exception is if we don't have a random map AND we are doing
	 * verifies, in that case we need to check for duplicate blocks and
	 * drop the old one, which we rely on the rb insert/lookup for
	 * handling.
	 */
	if (((!td->o.verifysort) || !td_random(td) || !td->o.overwrite) &&
	      (file_randommap(td, ipo->file) || td->o.verify == VERIFY_NONE)) {
		INIT_FLIST_HEAD(&ipo->list);
		flist_add_tail(&ipo->list, &td->io_hist_list);
		ipo->flags |= IP_F_ONLIST;
		td->io_hist_len++;
		return;
	}

	RB_CLEAR_NODE(&ipo->rb_node);

	/*
	 * Sort the entry into the verification list
	 */
restart:
	p = &td->io_hist_tree.rb_node;
	parent = NULL;
	while (*p) {
		parent = *p;

		__ipo = rb_entry(parent, struct io_piece, rb_node);
		if (ipo->file < __ipo->file)
			p = &(*p)->rb_left;
		else if (ipo->file > __ipo->file)
			p = &(*p)->rb_right;
		else if (ipo->offset < __ipo->offset)
			p = &(*p)->rb_left;
		else if (ipo->offset > __ipo->offset)
			p = &(*p)->rb_right;
		else {
			dprint(FD_IO, "iolog: overlap %llu/%lu, %llu/%lu",
				__ipo->offset, __ipo->len,
				ipo->offset, ipo->len);
			td->io_hist_len--;
			rb_erase(parent, &td->io_hist_tree);
			remove_trim_entry(td, __ipo);
			free(__ipo);
			goto restart;
		}
	}

	rb_link_node(&ipo->rb_node, parent, p);
	rb_insert_color(&ipo->rb_node, &td->io_hist_tree);
	ipo->flags |= IP_F_ONRB;
	td->io_hist_len++;
}

void unlog_io_piece(struct thread_data *td, struct io_u *io_u)
{
	struct io_piece *ipo = io_u->ipo;

	if (!ipo)
		return;

	if (ipo->flags & IP_F_ONRB)
		rb_erase(&ipo->rb_node, &td->io_hist_tree);
	else if (ipo->flags & IP_F_ONLIST)
		flist_del(&ipo->list);

	free(ipo);
	io_u->ipo = NULL;
	td->io_hist_len--;
}

void trim_io_piece(struct thread_data *td, struct io_u *io_u)
{
	struct io_piece *ipo = io_u->ipo;

	if (!ipo)
		return;

	ipo->len = io_u->xfer_buflen - io_u->resid;
}

void write_iolog_close(struct thread_data *td)
{
	fflush(td->iolog_f);
	fclose(td->iolog_f);
	free(td->iolog_buf);
	td->iolog_f = NULL;
	td->iolog_buf = NULL;
}

/*
 * Read version 2 iolog data. It is enhanced to include per-file logging,
 * syncs, etc.
 */
static int read_iolog2(struct thread_data *td, FILE *f)
{
	unsigned long long offset;
	unsigned int bytes;
	int reads, writes, waits, fileno = 0, file_action = 0; /* stupid gcc */
	char *fname, *act;
	char *str, *p;
	enum fio_ddir rw;

	free_release_files(td);

	/*
	 * Read in the read iolog and store it, reuse the infrastructure
	 * for doing verifications.
	 */
	str = malloc(4096);
	fname = malloc(256+16);
	act = malloc(256+16);

	reads = writes = waits = 0;
	while ((p = fgets(str, 4096, f)) != NULL) {
		struct io_piece *ipo;
		int r;

		r = sscanf(p, "%256s %256s %llu %u", fname, act, &offset,
									&bytes);
		if (r == 4) {
			/*
			 * Check action first
			 */
			if (!strcmp(act, "wait"))
				rw = DDIR_WAIT;
			else if (!strcmp(act, "read"))
				rw = DDIR_READ;
			else if (!strcmp(act, "write"))
				rw = DDIR_WRITE;
			else if (!strcmp(act, "sync"))
				rw = DDIR_SYNC;
			else if (!strcmp(act, "datasync"))
				rw = DDIR_DATASYNC;
			else if (!strcmp(act, "trim"))
				rw = DDIR_TRIM;
			else {
				log_err("fio: bad iolog file action: %s\n",
									act);
				continue;
			}
			fileno = get_fileno(td, fname);
		} else if (r == 2) {
			rw = DDIR_INVAL;
			if (!strcmp(act, "add")) {
				fileno = add_file(td, fname, 0, 1);
				file_action = FIO_LOG_ADD_FILE;
				continue;
			} else if (!strcmp(act, "open")) {
				fileno = get_fileno(td, fname);
				file_action = FIO_LOG_OPEN_FILE;
			} else if (!strcmp(act, "close")) {
				fileno = get_fileno(td, fname);
				file_action = FIO_LOG_CLOSE_FILE;
			} else {
				log_err("fio: bad iolog file action: %s\n",
									act);
				continue;
			}
		} else {
			log_err("bad iolog2: %s", p);
			continue;
		}

		if (rw == DDIR_READ)
			reads++;
		else if (rw == DDIR_WRITE) {
			/*
			 * Don't add a write for ro mode
			 */
			if (read_only)
				continue;
			writes++;
		} else if (rw == DDIR_WAIT) {
			waits++;
		} else if (rw == DDIR_INVAL) {
		} else if (!ddir_sync(rw)) {
			log_err("bad ddir: %d\n", rw);
			continue;
		}

		/*
		 * Make note of file
		 */
		ipo = malloc(sizeof(*ipo));
		init_ipo(ipo);
		ipo->ddir = rw;
		if (rw == DDIR_WAIT) {
			ipo->delay = offset;
		} else {
			ipo->offset = offset;
			ipo->len = bytes;
			if (rw != DDIR_INVAL && bytes > td->o.max_bs[rw])
				td->o.max_bs[rw] = bytes;
			ipo->fileno = fileno;
			ipo->file_action = file_action;
		}

		queue_io_piece(td, ipo);
	}

	free(str);
	free(act);
	free(fname);

	if (writes && read_only) {
		log_err("fio: <%s> skips replay of %d writes due to"
			" read-only\n", td->o.name, writes);
		writes = 0;
	}

	if (!reads && !writes && !waits)
		return 1;
	else if (reads && !writes)
		td->o.td_ddir = TD_DDIR_READ;
	else if (!reads && writes)
		td->o.td_ddir = TD_DDIR_WRITE;
	else
		td->o.td_ddir = TD_DDIR_RW;

	return 0;
}

/*
 * open iolog, check version, and call appropriate parser
 */
static int init_iolog_read(struct thread_data *td)
{
	char buffer[256], *p;
	FILE *f;
	int ret;

	f = fopen(td->o.read_iolog_file, "r");
	if (!f) {
		perror("fopen read iolog");
		return 1;
	}

	p = fgets(buffer, sizeof(buffer), f);
	if (!p) {
		td_verror(td, errno, "iolog read");
		log_err("fio: unable to read iolog\n");
		fclose(f);
		return 1;
	}

	/*
	 * version 2 of the iolog stores a specific string as the
	 * first line, check for that
	 */
	if (!strncmp(iolog_ver2, buffer, strlen(iolog_ver2)))
		ret = read_iolog2(td, f);
	else {
		log_err("fio: iolog version 1 is no longer supported\n");
		ret = 1;
	}

	fclose(f);
	return ret;
}

/*
 * Set up a log for storing io patterns.
 */
static int init_iolog_write(struct thread_data *td)
{
	struct fio_file *ff;
	FILE *f;
	unsigned int i;

	f = fopen(td->o.write_iolog_file, "a");
	if (!f) {
		perror("fopen write iolog");
		return 1;
	}

	/*
	 * That's it for writing, setup a log buffer and we're done.
	  */
	td->iolog_f = f;
	td->iolog_buf = malloc(8192);
	setvbuf(f, td->iolog_buf, _IOFBF, 8192);

	/*
	 * write our version line
	 */
	if (fprintf(f, "%s\n", iolog_ver2) < 0) {
		perror("iolog init\n");
		return 1;
	}

	/*
	 * add all known files
	 */
	for_each_file(td, ff, i)
		log_file(td, ff, FIO_LOG_ADD_FILE);

	return 0;
}

int init_iolog(struct thread_data *td)
{
	int ret = 0;

	if (td->o.read_iolog_file) {
		int need_swap;

		/*
		 * Check if it's a blktrace file and load that if possible.
		 * Otherwise assume it's a normal log file and load that.
		 */
		if (is_blktrace(td->o.read_iolog_file, &need_swap))
			ret = load_blktrace(td, td->o.read_iolog_file, need_swap);
		else
			ret = init_iolog_read(td);
	} else if (td->o.write_iolog_file)
		ret = init_iolog_write(td);

	if (ret)
		td_verror(td, EINVAL, "failed initializing iolog");

	return ret;
}

void setup_log(struct io_log **log, unsigned long avg_msec, int log_type)
{
	struct io_log *l = malloc(sizeof(*l));

	memset(l, 0, sizeof(*l));
	l->nr_samples = 0;
	l->max_samples = 1024;
	l->log_type = log_type;
	l->log = malloc(l->max_samples * sizeof(struct io_sample));
	l->avg_msec = avg_msec;
	*log = l;
}

#ifdef CONFIG_SETVBUF
static void *set_file_buffer(FILE *f)
{
	size_t size = 1048576;
	void *buf;

	buf = malloc(size);
	setvbuf(f, buf, _IOFBF, size);
	return buf;
}

static void clear_file_buffer(void *buf)
{
	free(buf);
}
#else
static void *set_file_buffer(FILE *f)
{
	return NULL;
}

static void clear_file_buffer(void *buf)
{
}
#endif

void __finish_log(struct io_log *log, const char *name)
{
	unsigned int i;
	void *buf;
	FILE *f;

	f = fopen(name, "a");
	if (!f) {
		perror("fopen log");
		return;
	}

	buf = set_file_buffer(f);

	for (i = 0; i < log->nr_samples; i++) {
		fprintf(f, "%lu, %lu, %u, %u\n",
				(unsigned long) log->log[i].time,
				(unsigned long) log->log[i].val,
				log->log[i].ddir, log->log[i].bs);
	}

	fclose(f);
	clear_file_buffer(buf);
	free(log->log);
	free(log);
}

static int finish_log_named(struct thread_data *td, struct io_log *log,
			    const char *prefix, const char *postfix,
			    int trylock)
{
	char file_name[256];

	snprintf(file_name, sizeof(file_name), "%s_%s.log", prefix, postfix);

	if (trylock) {
		if (fio_trylock_file(file_name))
			return 1;
	} else
		fio_lock_file(file_name);

	if (td->client_type == FIO_CLIENT_TYPE_GUI) {
		fio_send_iolog(td, log, file_name);
		free(log->log);
		free(log);
	} else
		__finish_log(log, file_name);

	fio_unlock_file(file_name);
	return 0;
}

static int finish_log(struct thread_data *td, struct io_log *log,
		      const char *name, int trylock)
{
	return finish_log_named(td, log, td->o.name, name, trylock);
}

static int write_this_log(struct thread_data *td, struct io_log *log,
			  const char *log_file, const char *name, int try)
{
	int ret;

	if (!log)
		return 0;

	if (log_file)
		ret = finish_log_named(td, log, log_file, name, try);
	else
		ret = finish_log(td, log, name, try);

	return ret;
}

static int write_iops_log(struct thread_data *td, int try)
{
	struct thread_options *o = &td->o;

	return write_this_log(td, td->iops_log, o->iops_log_file, "iops", try);
}

static int write_slat_log(struct thread_data *td, int try)
{
	struct thread_options *o = &td->o;

	return write_this_log(td, td->slat_log, o->lat_log_file, "slat", try);
}

static int write_clat_log(struct thread_data *td, int try)
{
	struct thread_options *o = &td->o;

	return write_this_log(td, td->clat_log, o->lat_log_file, "clat" , try);
}

static int write_lat_log(struct thread_data *td, int try)
{
	struct thread_options *o = &td->o;

	return write_this_log(td, td->lat_log, o->lat_log_file, "lat", try);
}

static int write_bandw_log(struct thread_data *td, int try)
{
	struct thread_options *o = &td->o;

	return write_this_log(td, td->bw_log, o->bw_log_file, "bw", try);
}

enum {
	BW_LOG_MASK	= 1,
	LAT_LOG_MASK	= 2,
	SLAT_LOG_MASK	= 4,
	CLAT_LOG_MASK	= 8,
	IOPS_LOG_MASK	= 16,

	ALL_LOG_NR	= 5,
};

struct log_type {
	unsigned int mask;
	int (*fn)(struct thread_data *, int);
};

static struct log_type log_types[] = {
	{
		.mask	= BW_LOG_MASK,
		.fn	= write_bandw_log,
	},
	{
		.mask	= LAT_LOG_MASK,
		.fn	= write_lat_log,
	},
	{
		.mask	= SLAT_LOG_MASK,
		.fn	= write_slat_log,
	},
	{
		.mask	= CLAT_LOG_MASK,
		.fn	= write_clat_log,
	},
	{
		.mask	= IOPS_LOG_MASK,
		.fn	= write_iops_log,
	},
};

void fio_writeout_logs(struct thread_data *td)
{
	unsigned int log_mask = 0;
	unsigned int log_left = ALL_LOG_NR;
	int old_state, i;

	old_state = td_bump_runstate(td, TD_FINISHING);

	finalize_logs(td);

	while (log_left) {
		int prev_log_left = log_left;

		for (i = 0; i < ALL_LOG_NR && log_left; i++) {
			struct log_type *lt = &log_types[i];
			int ret;

			if (!(log_mask & lt->mask)) {
				ret = lt->fn(td, log_left != 1);
				if (!ret) {
					log_left--;
					log_mask |= lt->mask;
				}
			}
		}

		if (prev_log_left == log_left)
			usleep(5000);
	}

	td_restore_runstate(td, old_state);
}
