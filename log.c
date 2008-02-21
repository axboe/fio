/*
 * Code related to writing an iolog of what a thread is doing, and to
 * later read that back and replay
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "list.h"
#include "fio.h"

static const char iolog_ver2[] = "fio version 2 iolog";

void log_io_u(struct thread_data *td, struct io_u *io_u)
{
	const char *act[] = { "read", "write", "sync" };

	assert(io_u->ddir < 3);

	if (!td->o.write_iolog_file)
		return;

	fprintf(td->iolog_f, "%s %s %llu %lu\n", io_u->file->file_name, act[io_u->ddir], io_u->offset, io_u->buflen);
}

void log_file(struct thread_data *td, struct fio_file *f,
	      enum file_log_act what)
{
	const char *act[] = { "add", "open", "close" };

	assert(what < 3);

	if (!td->o.write_iolog_file)
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

int read_iolog_get(struct thread_data *td, struct io_u *io_u)
{
	struct io_piece *ipo;

	while (!list_empty(&td->io_log_list)) {
		ipo = list_entry(td->io_log_list.next, struct io_piece, list);
		list_del(&ipo->list);

		/*
		 * invalid ddir, this is a file action
		 */
		if (ipo->ddir == DDIR_INVAL) {
			struct fio_file *f = &td->files[ipo->fileno];

			if (ipo->file_action == FIO_LOG_OPEN_FILE) {
				assert(!td_io_open_file(td, f));
				free(ipo);
				continue;
			} else if (ipo->file_action == FIO_LOG_CLOSE_FILE) {
				td_io_close_file(td, f);
				free(ipo);
				continue;
			}
		}

		io_u->offset = ipo->offset;
		io_u->buflen = ipo->len;
		io_u->ddir = ipo->ddir;
		io_u->file = &td->files[ipo->fileno];
		get_file(io_u->file);

		dprint(FD_IO, "iolog: get %llu/%lu/%s\n", io_u->offset,
					io_u->buflen, io_u->file->file_name);

		if (ipo->delay)
			iolog_delay(td, ipo->delay);

		free(ipo);
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
	ipo->file = io_u->file;
	ipo->offset = io_u->offset;
	ipo->len = io_u->buflen;

	/*
	 * We don't need to sort the entries, if:
	 *
	 *	Sequential writes, or
	 *	Random writes that lay out the file as it goes along
	 *
	 * For both these cases, just reading back data in the order we
	 * wrote it out is the fastest.
	 */
	if (!td_random(td) || !td->o.overwrite) {
		INIT_LIST_HEAD(&ipo->list);
		list_add_tail(&ipo->list, &td->io_hist_list);
		return;
	}

	RB_CLEAR_NODE(&ipo->rb_node);
	p = &td->io_hist_tree.rb_node;
	parent = NULL;

	/*
	 * Sort the entry into the verification list
	 */
	while (*p) {
		parent = *p;

		__ipo = rb_entry(parent, struct io_piece, rb_node);
		if (ipo->offset <= __ipo->offset)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}

	rb_link_node(&ipo->rb_node, parent, p);
	rb_insert_color(&ipo->rb_node, &td->io_hist_tree);
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
	int reads, writes, fileno = 0, file_action = 0; /* stupid gcc */
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

	reads = writes = 0;
	while ((p = fgets(str, 4096, f)) != NULL) {
		struct io_piece *ipo;
		int r;

		r = sscanf(p, "%256s %256s %llu %u", fname, act, &offset, &bytes);
		if (r == 4) {
			/*
			 * Check action first
			 */
			if (!strcmp(act, "read"))
				rw = DDIR_READ;
			else if (!strcmp(act, "write"))
				rw = DDIR_WRITE;
			else if (!strcmp(act, "sync"))
				rw = DDIR_SYNC;
			else {
				log_err("fio: bad iolog file action: %s\n",act);
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
				log_err("fio: bad iolog file action: %s\n",act);
				continue;
			}
		} else {
			log_err("bad iolog2: %s", p);
			continue;
		}
			
		if (rw == DDIR_READ)
			reads++;
		else if (rw == DDIR_WRITE) {
			writes++;
			/*
			 * Don't add a write for ro mode
			 */
			if (read_only)
				continue;
		} else if (rw != DDIR_SYNC && rw != DDIR_INVAL) {
			log_err("bad ddir: %d\n", rw);
			continue;
		}

		/*
		 * Make note of file
		 */
		ipo = malloc(sizeof(*ipo));
		memset(ipo, 0, sizeof(*ipo));
		INIT_LIST_HEAD(&ipo->list);
		ipo->offset = offset;
		ipo->len = bytes;
		ipo->ddir = rw;
		if (bytes > td->o.max_bs[rw])
			td->o.max_bs[rw] = bytes;
		if (rw == DDIR_INVAL) {
			ipo->fileno = fileno;
			ipo->file_action = file_action;
		}
		list_add_tail(&ipo->list, &td->io_log_list);
		td->total_io_size += bytes;
	}

	free(str);
	free(act);
	free(fname);

	if (writes && read_only) {
		log_err("fio: <%s> skips replay of %d writes due to read-only\n", td->o.name, writes);
		writes = 0;
	}

	if (!reads && !writes)
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
 * Read version 1 iolog data.
 */
static int read_iolog(struct thread_data *td, FILE *f)
{
	unsigned long long offset;
	unsigned int bytes;
	char *str, *p;
	int reads, writes;
	int rw;

	/*
	 * Read in the read iolog and store it, reuse the infrastructure
	 * for doing verifications.
	 */
	str = malloc(4096);
	reads = writes = 0;
	while ((p = fgets(str, 4096, f)) != NULL) {
		struct io_piece *ipo;

		if (sscanf(p, "%d,%llu,%u", &rw, &offset, &bytes) != 3) {
			log_err("bad iolog: %s\n", p);
			continue;
		}
		if (rw == DDIR_READ)
			reads++;
		else if (rw == DDIR_WRITE) {
			writes++;
			/*
			 * Don't add a write for ro mode
			 */
			if (read_only)
				continue;
		} else if (rw != DDIR_SYNC) {
			log_err("bad ddir: %d\n", rw);
			continue;
		}

		ipo = malloc(sizeof(*ipo));
		memset(ipo, 0, sizeof(*ipo));
		INIT_LIST_HEAD(&ipo->list);
		ipo->offset = offset;
		ipo->len = bytes;
		ipo->ddir = (enum fio_ddir) rw;
		if (bytes > td->o.max_bs[rw])
			td->o.max_bs[rw] = bytes;
		list_add_tail(&ipo->list, &td->io_log_list);
		td->total_io_size += bytes;
	}

	free(str);

	if (writes && read_only) {
		log_err("fio: <%s> skips replay of %d writes due to read-only\n", td->o.name, writes);
		writes = 0;
	}

	if (!reads && !writes)
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
		return 1;
	}

	/*
	 * version 2 of the iolog stores a specific string as the
	 * first line, check for that
	 */
	if (!strncmp(iolog_ver2, buffer, strlen(iolog_ver2)))
		ret = read_iolog2(td, f);
	else {
		/*
		 * seek back to the beginning
		 */
		if (fseek(f, 0, SEEK_SET) < 0) {
			td_verror(td, errno, "iolog read");
			log_err("fio: unable to read iolog\n");
			return 1;
		}

		ret = read_iolog(td, f);
	}

	fclose(f);
	return ret;
}

/*
 * Setup a log for storing io patterns.
 */
static int init_iolog_write(struct thread_data *td)
{
	struct fio_file *ff;
	FILE *f;
	unsigned int i;

	f = fopen(td->o.write_iolog_file, "w+");
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

	if (td->io_ops->flags & FIO_DISKLESSIO)
		return 0;

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

void setup_log(struct io_log **log)
{
	struct io_log *l = malloc(sizeof(*l));

	l->nr_samples = 0;
	l->max_samples = 1024;
	l->log = malloc(l->max_samples * sizeof(struct io_sample));
	*log = l;
}

void __finish_log(struct io_log *log, const char *name)
{
	unsigned int i;
	FILE *f;

	f = fopen(name, "w");
	if (!f) {
		perror("fopen log");
		return;
	}

	for (i = 0; i < log->nr_samples; i++)
		fprintf(f, "%lu, %lu, %u\n", log->log[i].time, log->log[i].val, log->log[i].ddir);

	fclose(f);
	free(log->log);
	free(log);
}

void finish_log(struct thread_data *td, struct io_log *log, const char *name)
{
	char file_name[256];

	snprintf(file_name, 200, "client%d_%s.log", td->thread_number, name);
	__finish_log(log, file_name);
}
