#include <stdio.h>
#include <stdlib.h>
#include "list.h"
#include "fio.h"

void write_iolog_put(struct thread_data *td, struct io_u *io_u)
{
	fprintf(td->iolog_f, "%u,%llu,%u\n", io_u->ddir, io_u->offset, io_u->buflen);
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
		free(ipo);
		return 0;
	}

	return 1;
}

void prune_io_piece_log(struct thread_data *td)
{
	struct io_piece *ipo;

	while (!list_empty(&td->io_hist_list)) {
		ipo = list_entry(td->io_hist_list.next, struct io_piece, list);

		list_del(&ipo->list);
		free(ipo);
	}
}

/*
 * log a succesful write, so we can unwind the log for verify
 */
void log_io_piece(struct thread_data *td, struct io_u *io_u)
{
	struct io_piece *ipo = malloc(sizeof(struct io_piece));
	struct list_head *entry;

	INIT_LIST_HEAD(&ipo->list);
	ipo->file = io_u->file;
	ipo->offset = io_u->offset;
	ipo->len = io_u->buflen;

	/*
	 * for random io where the writes extend the file, it will typically
	 * be laid out with the block scattered as written. it's faster to
	 * read them in in that order again, so don't sort
	 */
	if (td->sequential || !td->overwrite) {
		list_add_tail(&ipo->list, &td->io_hist_list);
		return;
	}

	/*
	 * for random io, sort the list so verify will run faster
	 */
	entry = &td->io_hist_list;
	while ((entry = entry->prev) != &td->io_hist_list) {
		struct io_piece *__ipo = list_entry(entry, struct io_piece, list);

		if (__ipo->offset < ipo->offset)
			break;
	}

	list_add(&ipo->list, entry);
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

	f = fopen(td->read_iolog_file, "r");
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
		else {
			log_err("bad ddir: %d\n", rw);
			continue;
		}

		ipo = malloc(sizeof(*ipo));
		INIT_LIST_HEAD(&ipo->list);
		ipo->offset = offset;
		ipo->len = bytes;
		ipo->ddir = (enum fio_ddir) rw;
		if (bytes > td->max_bs[rw])
			td->max_bs[rw] = bytes;
		list_add_tail(&ipo->list, &td->io_log_list);
	}

	free(str);
	fclose(f);

	if (!reads && !writes)
		return 1;
	else if (reads && !writes)
		td->ddir = DDIR_READ;
	else if (!reads && writes)
		td->ddir = DDIR_READ;
	else
		td->iomix = 1;

	return 0;
}

/*
 * Setup a log for storing io patterns.
 */
static int init_iolog_write(struct thread_data *td)
{
	FILE *f;

	f = fopen(td->write_iolog_file, "w+");
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

	if (td->io_ops->flags & FIO_CPUIO)
		return 0;

	if (td->read_iolog_file)
		ret = init_iolog_read(td);
	else if (td->write_iolog_file)
		ret = init_iolog_write(td);

	return ret;
}

int setup_rate(struct thread_data *td)
{
	int nr_reads_per_sec;

	if (!td->rate)
		return 0;

	if (td->rate < td->ratemin) {
		log_err("min rate larger than nominal rate\n");
		return -1;
	}

	nr_reads_per_sec = (td->rate * 1024) / td->min_bs[DDIR_READ];
	td->rate_usec_cycle = 1000000 / nr_reads_per_sec;
	td->rate_pending_usleep = 0;
	return 0;
}

void setup_log(struct io_log **log)
{
	struct io_log *l = malloc(sizeof(*l));

	l->nr_samples = 0;
	l->max_samples = 1024;
	l->log = malloc(l->max_samples * sizeof(struct io_sample));
	*log = l;
}

void finish_log(struct thread_data *td, struct io_log *log, const char *name)
{
	char file_name[256];
	FILE *f;
	unsigned int i;

	snprintf(file_name, 200, "client%d_%s.log", td->thread_number, name);
	f = fopen(file_name, "w");
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
