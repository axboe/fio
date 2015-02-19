/*
 * Code related to writing an iolog of what a thread is doing, and to
 * later read that back and replay
 */
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef CONFIG_ZLIB
#include <zlib.h>
#endif

#include "flist.h"
#include "fio.h"
#include "verify.h"
#include "trim.h"
#include "filelock.h"
#include "lib/tp.h"

static const char iolog_ver2[] = "fio version 2 iolog";

void queue_io_piece(struct thread_data *td, struct io_piece *ipo)
{
	flist_add_tail(&ipo->list, &td->io_log_list);
	td->total_io_size += ipo->len;
}

void log_io_u(const struct thread_data *td, const struct io_u *io_u)
{
	if (!td->o.write_iolog_file)
		return;

	fprintf(td->iolog_f, "%s %s %llu %lu\n", io_u->file->file_name,
						io_ddir_name(io_u->ddir),
						io_u->offset, io_u->buflen);
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
	uint64_t usec = utime_since_now(&td->last_issue);
	uint64_t this_delay;
	struct timeval tv;

	if (delay < td->time_offset) {
		td->time_offset = 0;
		return;
	}

	delay -= td->time_offset;
	if (delay < usec)
		return;

	delay -= usec;

	fio_gettime(&tv, NULL);
	while (delay && !td->terminate) {
		this_delay = delay;
		if (this_delay > 500000)
			this_delay = 500000;

		usec_sleep(td, this_delay);
		delay -= this_delay;
	}

	usec = utime_since_now(&tv);
	if (usec > delay)
		td->time_offset = usec - delay;
	else
		td->time_offset = 0;
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
		td_io_unlink_file(td, f);
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

		ipo = flist_first_entry(&td->io_log_list, struct io_piece, list);
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
		ipo = flist_first_entry(&td->io_hist_list, struct io_piece, list);
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
		int overlap = 0;
		parent = *p;

		__ipo = rb_entry(parent, struct io_piece, rb_node);
		if (ipo->file < __ipo->file)
			p = &(*p)->rb_left;
		else if (ipo->file > __ipo->file)
			p = &(*p)->rb_right;
		else if (ipo->offset < __ipo->offset) {
			p = &(*p)->rb_left;
			overlap = ipo->offset + ipo->len > __ipo->offset;
		}
		else if (ipo->offset > __ipo->offset) {
			p = &(*p)->rb_right;
			overlap = __ipo->offset + __ipo->len > ipo->offset;
		}
		else
			overlap = 1;

		if (overlap) {
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

void trim_io_piece(struct thread_data *td, const struct io_u *io_u)
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
			td->o.size += bytes;
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

void setup_log(struct io_log **log, struct log_params *p,
	       const char *filename)
{
	struct io_log *l;

	l = calloc(1, sizeof(*l));
	l->nr_samples = 0;
	l->max_samples = 1024;
	l->log_type = p->log_type;
	l->log_offset = p->log_offset;
	l->log_gz = p->log_gz;
	l->log_gz_store = p->log_gz_store;
	l->log = malloc(l->max_samples * log_entry_sz(l));
	l->avg_msec = p->avg_msec;
	l->filename = strdup(filename);
	l->td = p->td;

	if (l->log_offset)
		l->log_ddir_mask = LOG_OFFSET_SAMPLE_BIT;

	INIT_FLIST_HEAD(&l->chunk_list);

	if (l->log_gz && !p->td)
		l->log_gz = 0;
	else if (l->log_gz) {
		pthread_mutex_init(&l->chunk_lock, NULL);
		p->td->flags |= TD_F_COMPRESS_LOG;
	}

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

void free_log(struct io_log *log)
{
	free(log->log);
	free(log->filename);
	free(log);
}

static void flush_samples(FILE *f, void *samples, uint64_t sample_size)
{
	struct io_sample *s;
	int log_offset;
	uint64_t i, nr_samples;

	if (!sample_size)
		return;

	s = __get_sample(samples, 0, 0);
	log_offset = (s->__ddir & LOG_OFFSET_SAMPLE_BIT) != 0;

	nr_samples = sample_size / __log_entry_sz(log_offset);

	for (i = 0; i < nr_samples; i++) {
		s = __get_sample(samples, log_offset, i);

		if (!log_offset) {
			fprintf(f, "%lu, %lu, %u, %u\n",
					(unsigned long) s->time,
					(unsigned long) s->val,
					io_sample_ddir(s), s->bs);
		} else {
			struct io_sample_offset *so = (void *) s;

			fprintf(f, "%lu, %lu, %u, %u, %llu\n",
					(unsigned long) s->time,
					(unsigned long) s->val,
					io_sample_ddir(s), s->bs,
					(unsigned long long) so->offset);
		}
	}
}

#ifdef CONFIG_ZLIB

struct iolog_flush_data {
	struct tp_work work;
	struct io_log *log;
	void *samples;
	uint64_t nr_samples;
};

struct iolog_compress {
	struct flist_head list;
	void *buf;
	size_t len;
	unsigned int seq;
};

#define GZ_CHUNK	131072

static struct iolog_compress *get_new_chunk(unsigned int seq)
{
	struct iolog_compress *c;

	c = malloc(sizeof(*c));
	INIT_FLIST_HEAD(&c->list);
	c->buf = malloc(GZ_CHUNK);
	c->len = 0;
	c->seq = seq;
	return c;
}

static void free_chunk(struct iolog_compress *ic)
{
	free(ic->buf);
	free(ic);
}

static int z_stream_init(z_stream *stream, int gz_hdr)
{
	int wbits = 15;

	stream->zalloc = Z_NULL;
	stream->zfree = Z_NULL;
	stream->opaque = Z_NULL;
	stream->next_in = Z_NULL;

	/*
	 * zlib magic - add 32 for auto-detection of gz header or not,
	 * if we decide to store files in a gzip friendly format.
	 */
	if (gz_hdr)
		wbits += 32;

	if (inflateInit2(stream, wbits) != Z_OK)
		return 1;

	return 0;
}

struct inflate_chunk_iter {
	unsigned int seq;
	int err;
	void *buf;
	size_t buf_size;
	size_t buf_used;
	size_t chunk_sz;
};

static void finish_chunk(z_stream *stream, FILE *f,
			 struct inflate_chunk_iter *iter)
{
	int ret;

	ret = inflateEnd(stream);
	if (ret != Z_OK)
		log_err("fio: failed to end log inflation (%d)\n", ret);

	flush_samples(f, iter->buf, iter->buf_used);
	free(iter->buf);
	iter->buf = NULL;
	iter->buf_size = iter->buf_used = 0;
}

/*
 * Iterative chunk inflation. Handles cases where we cross into a new
 * sequence, doing flush finish of previous chunk if needed.
 */
static size_t inflate_chunk(struct iolog_compress *ic, int gz_hdr, FILE *f,
			    z_stream *stream, struct inflate_chunk_iter *iter)
{
	size_t ret;

	dprint(FD_COMPRESS, "inflate chunk size=%lu, seq=%u",
				(unsigned long) ic->len, ic->seq);

	if (ic->seq != iter->seq) {
		if (iter->seq)
			finish_chunk(stream, f, iter);

		z_stream_init(stream, gz_hdr);
		iter->seq = ic->seq;
	}

	stream->avail_in = ic->len;
	stream->next_in = ic->buf;

	if (!iter->buf_size) {
		iter->buf_size = iter->chunk_sz;
		iter->buf = malloc(iter->buf_size);
	}

	while (stream->avail_in) {
		size_t this_out = iter->buf_size - iter->buf_used;
		int err;

		stream->avail_out = this_out;
		stream->next_out = iter->buf + iter->buf_used;

		err = inflate(stream, Z_NO_FLUSH);
		if (err < 0) {
			log_err("fio: failed inflating log: %d\n", err);
			iter->err = err;
			break;
		}

		iter->buf_used += this_out - stream->avail_out;

		if (!stream->avail_out) {
			iter->buf_size += iter->chunk_sz;
			iter->buf = realloc(iter->buf, iter->buf_size);
			continue;
		}

		if (err == Z_STREAM_END)
			break;
	}

	ret = (void *) stream->next_in - ic->buf;

	dprint(FD_COMPRESS, "inflated to size=%lu\n", (unsigned long) ret);

	return ret;
}

/*
 * Inflate stored compressed chunks, or write them directly to the log
 * file if so instructed.
 */
static int inflate_gz_chunks(struct io_log *log, FILE *f)
{
	struct inflate_chunk_iter iter = { .chunk_sz = log->log_gz, };
	z_stream stream;

	while (!flist_empty(&log->chunk_list)) {
		struct iolog_compress *ic;

		ic = flist_first_entry(&log->chunk_list, struct iolog_compress, list);
		flist_del(&ic->list);

		if (log->log_gz_store) {
			size_t ret;

			dprint(FD_COMPRESS, "log write chunk size=%lu, "
				"seq=%u\n", (unsigned long) ic->len, ic->seq);

			ret = fwrite(ic->buf, ic->len, 1, f);
			if (ret != 1 || ferror(f)) {
				iter.err = errno;
				log_err("fio: error writing compressed log\n");
			}
		} else
			inflate_chunk(ic, log->log_gz_store, f, &stream, &iter);

		free_chunk(ic);
	}

	if (iter.seq) {
		finish_chunk(&stream, f, &iter);
		free(iter.buf);
	}

	return iter.err;
}

/*
 * Open compressed log file and decompress the stored chunks and
 * write them to stdout. The chunks are stored sequentially in the
 * file, so we iterate over them and do them one-by-one.
 */
int iolog_file_inflate(const char *file)
{
	struct inflate_chunk_iter iter = { .chunk_sz = 64 * 1024 * 1024, };
	struct iolog_compress ic;
	z_stream stream;
	struct stat sb;
	ssize_t ret;
	size_t total;
	void *buf;
	FILE *f;

	f = fopen(file, "r");
	if (!f) {
		perror("fopen");
		return 1;
	}

	if (stat(file, &sb) < 0) {
		fclose(f);
		perror("stat");
		return 1;
	}

	ic.buf = buf = malloc(sb.st_size);
	ic.len = sb.st_size;
	ic.seq = 1;

	ret = fread(ic.buf, ic.len, 1, f);
	if (ret < 0) {
		perror("fread");
		fclose(f);
		free(buf);
		return 1;
	} else if (ret != 1) {
		log_err("fio: short read on reading log\n");
		fclose(f);
		free(buf);
		return 1;
	}

	fclose(f);

	/*
	 * Each chunk will return Z_STREAM_END. We don't know how many
	 * chunks are in the file, so we just keep looping and incrementing
	 * the sequence number until we have consumed the whole compressed
	 * file.
	 */
	total = ic.len;
	do {
		size_t iret;

		iret = inflate_chunk(&ic,  1, stdout, &stream, &iter);
		total -= iret;
		if (!total)
			break;
		if (iter.err)
			break;

		ic.seq++;
		ic.len -= iret;
		ic.buf += iret;
	} while (1);

	if (iter.seq) {
		finish_chunk(&stream, stdout, &iter);
		free(iter.buf);
	}

	free(buf);
	return iter.err;
}

#else

static int inflate_gz_chunks(struct io_log *log, FILE *f)
{
	return 0;
}

int iolog_file_inflate(const char *file)
{
	log_err("fio: log inflation not possible without zlib\n");
	return 1;
}

#endif

void flush_log(struct io_log *log)
{
	void *buf;
	FILE *f;

	f = fopen(log->filename, "w");
	if (!f) {
		perror("fopen log");
		return;
	}

	buf = set_file_buffer(f);

	inflate_gz_chunks(log, f);

	flush_samples(f, log->log, log->nr_samples * log_entry_sz(log));

	fclose(f);
	clear_file_buffer(buf);
}

static int finish_log(struct thread_data *td, struct io_log *log, int trylock)
{
	if (td->tp_data)
		iolog_flush(log, 1);

	if (trylock) {
		if (fio_trylock_file(log->filename))
			return 1;
	} else
		fio_lock_file(log->filename);

	if (td->client_type == FIO_CLIENT_TYPE_GUI)
		fio_send_iolog(td, log, log->filename);
	else
		flush_log(log);

	fio_unlock_file(log->filename);
	free_log(log);
	return 0;
}

#ifdef CONFIG_ZLIB

/*
 * Invoked from our compress helper thread, when logging would have exceeded
 * the specified memory limitation. Compresses the previously stored
 * entries.
 */
static int gz_work(struct tp_work *work)
{
	struct iolog_flush_data *data;
	struct iolog_compress *c;
	struct flist_head list;
	unsigned int seq;
	z_stream stream;
	size_t total = 0;
	int ret;

	INIT_FLIST_HEAD(&list);

	data = container_of(work, struct iolog_flush_data, work);

	stream.zalloc = Z_NULL;
	stream.zfree = Z_NULL;
	stream.opaque = Z_NULL;

	ret = deflateInit(&stream, Z_DEFAULT_COMPRESSION);
	if (ret != Z_OK) {
		log_err("fio: failed to init gz stream\n");
		return 0;
	}

	seq = ++data->log->chunk_seq;

	stream.next_in = (void *) data->samples;
	stream.avail_in = data->nr_samples * log_entry_sz(data->log);

	dprint(FD_COMPRESS, "deflate input size=%lu, seq=%u\n",
				(unsigned long) stream.avail_in, seq);
	do {
		c = get_new_chunk(seq);
		stream.avail_out = GZ_CHUNK;
		stream.next_out = c->buf;
		ret = deflate(&stream, Z_NO_FLUSH);
		if (ret < 0) {
			log_err("fio: deflate log (%d)\n", ret);
			free_chunk(c);
			goto err;
		}

		c->len = GZ_CHUNK - stream.avail_out;
		flist_add_tail(&c->list, &list);
		total += c->len;
	} while (stream.avail_in);

	stream.next_out = c->buf + c->len;
	stream.avail_out = GZ_CHUNK - c->len;

	ret = deflate(&stream, Z_FINISH);
	if (ret == Z_STREAM_END)
		c->len = GZ_CHUNK - stream.avail_out;
	else {
		do {
			c = get_new_chunk(seq);
			stream.avail_out = GZ_CHUNK;
			stream.next_out = c->buf;
			ret = deflate(&stream, Z_FINISH);
			c->len = GZ_CHUNK - stream.avail_out;
			total += c->len;
			flist_add_tail(&c->list, &list);
		} while (ret != Z_STREAM_END);
	}

	dprint(FD_COMPRESS, "deflated to size=%lu\n", (unsigned long) total);

	ret = deflateEnd(&stream);
	if (ret != Z_OK)
		log_err("fio: deflateEnd %d\n", ret);

	free(data->samples);

	if (!flist_empty(&list)) {
		pthread_mutex_lock(&data->log->chunk_lock);
		flist_splice_tail(&list, &data->log->chunk_list);
		pthread_mutex_unlock(&data->log->chunk_lock);
	}

	ret = 0;
done:
	if (work->wait) {
		work->done = 1;
		pthread_cond_signal(&work->cv);
	} else
		free(data);

	return ret;
err:
	while (!flist_empty(&list)) {
		c = flist_first_entry(list.next, struct iolog_compress, list);
		flist_del(&c->list);
		free_chunk(c);
	}
	ret = 1;
	goto done;
}

/*
 * Queue work item to compress the existing log entries. We copy the
 * samples, and reset the log sample count to 0 (so the logging will
 * continue to use the memory associated with the log). If called with
 * wait == 1, will not return until the log compression has completed.
 */
int iolog_flush(struct io_log *log, int wait)
{
	struct tp_data *tdat = log->td->tp_data;
	struct iolog_flush_data *data;
	size_t sample_size;

	data = malloc(sizeof(*data));
	if (!data)
		return 1;

	data->log = log;

	sample_size = log->nr_samples * log_entry_sz(log);
	data->samples = malloc(sample_size);
	if (!data->samples) {
		free(data);
		return 1;
	}

	memcpy(data->samples, log->log, sample_size);
	data->nr_samples = log->nr_samples;
	data->work.fn = gz_work;
	log->nr_samples = 0;

	if (wait) {
		pthread_mutex_init(&data->work.lock, NULL);
		pthread_cond_init(&data->work.cv, NULL);
		data->work.wait = 1;
	} else
		data->work.wait = 0;

	data->work.prio = 1;
	tp_queue_work(tdat, &data->work);

	if (wait) {
		pthread_mutex_lock(&data->work.lock);
		while (!data->work.done)
			pthread_cond_wait(&data->work.cv, &data->work.lock);
		pthread_mutex_unlock(&data->work.lock);
		free(data);
	}

	return 0;
}

#else

int iolog_flush(struct io_log *log, int wait)
{
	return 1;
}

#endif

static int write_iops_log(struct thread_data *td, int try)
{
	struct io_log *log = td->iops_log;

	if (!log)
		return 0;

	return finish_log(td, log, try);
}

static int write_slat_log(struct thread_data *td, int try)
{
	struct io_log *log = td->slat_log;

	if (!log)
		return 0;

	return finish_log(td, log, try);
}

static int write_clat_log(struct thread_data *td, int try)
{
	struct io_log *log = td->clat_log;

	if (!log)
		return 0;

	return finish_log(td, log, try);
}

static int write_lat_log(struct thread_data *td, int try)
{
	struct io_log *log = td->lat_log;

	if (!log)
		return 0;

	return finish_log(td, log, try);
}

static int write_bandw_log(struct thread_data *td, int try)
{
	struct io_log *log = td->bw_log;

	if (!log)
		return 0;

	return finish_log(td, log, try);
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
