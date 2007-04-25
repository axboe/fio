#include <stdio.h>
#include <stdlib.h>
#include "list.h"
#include "fio.h"

void write_iolog_put(struct thread_data *td, struct io_u *io_u)
{
	fprintf(td->iolog_f, "%u,%llu,%lu\n", io_u->ddir, io_u->offset, io_u->buflen);
}

int read_iolog_get(struct thread_data *td, struct io_u *io_u)
{
	struct io_piece *ipo;

	if (!list_empty(&td->io_log_list)) {
		ipo = list_entry(td->io_log_list.next, struct io_piece, list);
		list_del(&ipo->list);
		io_u->offset = ipo->offset;
		io_u->buflen = ipo->len;
		io_u->ddir = ipo->ddir;
		io_u->file = ipo->file;
		/*
		 * work around, this needs a format change to work for > 1 file
		 */
		if (!io_u->file)
			io_u->file = &td->files[0];
		free(ipo);
		return 0;
	}

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
	if (!td_random(td) || !td->o.overwrite ||
	     (io_u->file->flags & FIO_FILE_NOSORT)) {
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
}

/*
 * Open a stored log and read in the entries.
 */
static int init_iolog_read(struct thread_data *td)
{
	unsigned long long offset;
	unsigned int bytes;
	char *str, *p;
	FILE *f;
	int rw, reads, writes;

	f = fopen(td->o.read_iolog_file, "r");
	if (!f) {
		perror("fopen read iolog");
		return 1;
	}

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
		else if (rw == DDIR_WRITE)
			writes++;
		else if (rw != DDIR_SYNC) {
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
	}

	free(str);
	fclose(f);

	if (!reads && !writes)
		return 1;
	else if (reads && !writes)
		td->o.td_ddir = TD_DDIR_READ;
	else if (!reads && writes)
		td->o.td_ddir = TD_DDIR_READ;
	else
		td->o.td_ddir = TD_DDIR_RW;

	return 0;
}

/*
 * Setup a log for storing io patterns.
 */
static int init_iolog_write(struct thread_data *td)
{
	FILE *f;

	if (td->o.nr_files > 1) {
		log_err("fio: write_iolog only works with 1 file currently\n");
		return 1;
	}

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
	return 0;
}

int init_iolog(struct thread_data *td)
{
	int ret = 0;

	if (td->io_ops->flags & FIO_DISKLESSIO)
		return 0;

	if (td->o.read_iolog_file)
		ret = init_iolog_read(td);
	else if (td->o.write_iolog_file)
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
