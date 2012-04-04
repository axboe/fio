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

	if (delay < usec)
		return;

	delay -= usec;

	/*
	 * less than 100 usec delay, just regard it as noise
	 */
	if (delay < 100)
		return;

	usec_sleep(td, delay);
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
	if ((!td_random(td) || !td->o.overwrite) &&
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
		} else if (r == 2) {
			rw = DDIR_INVAL;
			if (!strcmp(act, "add")) {
				td->o.nr_files++;
				fileno = add_file(td, fname);
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
			if (bytes > td->o.max_bs[rw])
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
		/*
		 * Check if it's a blktrace file and load that if possible.
		 * Otherwise assume it's a normal log file and load that.
		 */
		if (is_blktrace(td->o.read_iolog_file))
			ret = load_blktrace(td, td->o.read_iolog_file);
		else
			ret = init_iolog_read(td);
	} else if (td->o.write_iolog_file)
		ret = init_iolog_write(td);

	return ret;
}

void setup_log(struct io_log **log, unsigned long avg_msec)
{
	struct io_log *l = malloc(sizeof(*l));

	memset(l, 0, sizeof(*l));
	l->nr_samples = 0;
	l->max_samples = 1024;
	l->log = malloc(l->max_samples * sizeof(struct io_sample));
	l->avg_msec = avg_msec;
	*log = l;
}

void __finish_log(struct io_log *log, const char *name)
{
	unsigned int i;
	FILE *f;

	f = fopen(name, "a");
	if (!f) {
		perror("fopen log");
		return;
	}

	for (i = 0; i < log->nr_samples; i++) {
		fprintf(f, "%lu, %lu, %u, %u\n", log->log[i].time,
						log->log[i].val,
						log->log[i].ddir,
						log->log[i].bs);
	}

	fclose(f);
	free(log->log);
	free(log);
}

void finish_log_named(struct thread_data *td, struct io_log *log,
		       const char *prefix, const char *postfix)
{
	char file_name[256], *p;

	snprintf(file_name, 200, "%s_%s.log", prefix, postfix);
	p = basename(file_name);
	__finish_log(log, p);
}

void finish_log(struct thread_data *td, struct io_log *log, const char *name)
{
	finish_log_named(td, log, td->o.name, name);
}
