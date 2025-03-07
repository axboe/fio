/*
 * Small tool to check for dedupable blocks in a file or device. Basically
 * just scans the filename for extents of the given size, checksums them,
 * and orders them up.
 */
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "../fio.h"
#include "../flist.h"
#include "../log.h"
#include "../fio_sem.h"
#include "../smalloc.h"
#include "../minmax.h"
#include "../crc/md5.h"
#include "../os/os.h"
#include "../gettime.h"
#include "../fio_time.h"
#include "../lib/rbtree.h"

#include "../lib/bloom.h"
#include "debug.h"
#include "zlib.h"

struct zlib_ctrl {
	z_stream stream;
	unsigned char *buf_in;
	unsigned char *buf_out;
};

struct worker_thread {
	struct zlib_ctrl zc;
	pthread_t thread;
	uint64_t cur_offset;
	uint64_t size;
	unsigned long long unique_capacity;
	unsigned long items;
	unsigned long dupes;
	int err;
	int fd;
	volatile int done;
};

struct extent {
	struct flist_head list;
	uint64_t offset;
};

struct chunk {
	struct fio_rb_node rb_node;
	uint64_t count;
	uint32_t hash[MD5_HASH_WORDS];
	struct flist_head extent_list[0];
};

struct item {
	uint64_t offset;
	uint32_t hash[MD5_HASH_WORDS];
};

static struct rb_root rb_root;
static struct bloom *bloom;
static struct fio_sem *rb_lock;

static unsigned int blocksize = 4096;
static unsigned int num_threads;
static unsigned int chunk_size = 1048576;
static unsigned int dump_output;
static unsigned int odirect;
static unsigned int collision_check;
static unsigned int print_progress = 1;
static unsigned int use_bloom = 1;
static unsigned int compression = 0;

static uint64_t total_size;
static uint64_t cur_offset;
static struct fio_sem *size_lock;

static struct fio_file file;

static uint64_t get_size(struct fio_file *f, struct stat *sb)
{
	uint64_t ret;

	if (S_ISBLK(sb->st_mode)) {
		unsigned long long bytes = 0;

		if (blockdev_size(f, &bytes)) {
			log_err("dedupe: failed getting bdev size\n");
			return 0;
		}
		ret = bytes;
	} else {
		ret = sb->st_size;
	}

	return (ret & ~((uint64_t)blocksize - 1));
}

static int get_work(uint64_t *offset, uint64_t *size)
{
	uint64_t this_chunk;
	int ret = 1;

	fio_sem_down(size_lock);

	if (cur_offset < total_size) {
		*offset = cur_offset;
		this_chunk = min((uint64_t)chunk_size, total_size - cur_offset);
		*size = this_chunk;
		cur_offset += this_chunk;
		ret = 0;
	}

	fio_sem_up(size_lock);
	return ret;
}

static int __read_block(int fd, void *buf, off_t offset, size_t count)
{
	ssize_t ret;

	ret = pread(fd, buf, count, offset);
	if (ret < 0) {
		perror("pread");
		return 1;
	} else if (!ret) {
		return 1;
	} else if (ret != count) {
		log_err("dedupe: short read on block\n");
		return 1;
	}

	return 0;
}

static int read_block(int fd, void *buf, off_t offset)
{
	return __read_block(fd, buf, offset, blocksize);
}

static int account_unique_capacity(uint64_t offset, uint64_t *unique_capacity,
				   struct zlib_ctrl *zc)
{
	z_stream *stream = &zc->stream;
	unsigned int compressed_len;
	int ret;

	if (read_block(file.fd, zc->buf_in, offset))
		return 1;

	stream->next_in = zc->buf_in;
	stream->avail_in = blocksize;
	stream->avail_out = deflateBound(stream, blocksize);
	stream->next_out = zc->buf_out;

	ret = deflate(stream, Z_FINISH);
	if (ret == Z_STREAM_ERROR)
		return 1;
	compressed_len = blocksize - stream->avail_out;

	if (dump_output)
		printf("offset 0x%lx compressed to %d blocksize %d ratio %.2f \n",
				(unsigned long) offset, compressed_len, blocksize,
				(float)compressed_len / (float)blocksize);

	*unique_capacity += compressed_len;
	deflateReset(stream);
	return 0;
}

static void add_item(struct chunk *c, struct item *i)
{
	/*	
	 * Save some memory and don't add extent items, if we don't
	 * use them.
	 */
	if (dump_output || collision_check) {
		struct extent *e;

		e = malloc(sizeof(*e));
		e->offset = i->offset;
		flist_add_tail(&e->list, &c->extent_list[0]);
	}

	c->count++;
}

static int col_check(struct chunk *c, struct item *i)
{
	struct extent *e;
	char *cbuf, *ibuf;
	int ret = 1;

	cbuf = fio_memalign(blocksize, blocksize, false);
	ibuf = fio_memalign(blocksize, blocksize, false);

	e = flist_entry(c->extent_list[0].next, struct extent, list);
	if (read_block(file.fd, cbuf, e->offset))
		goto out;

	if (read_block(file.fd, ibuf, i->offset))
		goto out;

	ret = memcmp(ibuf, cbuf, blocksize);
out:
	fio_memfree(cbuf, blocksize, false);
	fio_memfree(ibuf, blocksize, false);
	return ret;
}

static struct chunk *alloc_chunk(void)
{
	struct chunk *c;

	if (collision_check || dump_output) {
		c = malloc(sizeof(struct chunk) + sizeof(struct flist_head));
		INIT_FLIST_HEAD(&c->extent_list[0]);
	} else {
		c = malloc(sizeof(struct chunk));
	}

	return c;
}

static int insert_chunk(struct item *i, uint64_t *unique_capacity,
			struct zlib_ctrl *zc)
{
	struct fio_rb_node **p, *parent;
	struct chunk *c;
	int ret, diff;

	p = &rb_root.rb_node;
	parent = NULL;
	while (*p) {
		parent = *p;

		c = rb_entry(parent, struct chunk, rb_node);
		diff = memcmp(i->hash, c->hash, sizeof(i->hash));
		if (diff < 0) {
			p = &(*p)->rb_left;
		} else if (diff > 0) {
			p = &(*p)->rb_right;
		} else {
			if (!collision_check)
				goto add;

			fio_sem_up(rb_lock);
			ret = col_check(c, i);
			fio_sem_down(rb_lock);

			if (!ret)
				goto add;

			p = &(*p)->rb_right;
		}
	}

	c = alloc_chunk();
	RB_CLEAR_NODE(&c->rb_node);
	c->count = 0;
	memcpy(c->hash, i->hash, sizeof(i->hash));
	rb_link_node(&c->rb_node, parent, p);
	rb_insert_color(&c->rb_node, &rb_root);
	if (compression) {
		ret = account_unique_capacity(i->offset, unique_capacity, zc);
		if (ret)
			return ret;
	}
add:
	add_item(c, i);
	return 0;
}

static int insert_chunks(struct item *items, unsigned int nitems,
			 uint64_t *ndupes, uint64_t *unique_capacity,
			 struct zlib_ctrl *zc)
{
	int i, ret = 0;

	fio_sem_down(rb_lock);

	for (i = 0; i < nitems; i++) {
		if (bloom) {
			unsigned int s;
			int r;

			s = sizeof(items[i].hash) / sizeof(uint32_t);
			r = bloom_set(bloom, items[i].hash, s);
			*ndupes += r;
		} else {
			ret = insert_chunk(&items[i], unique_capacity, zc);
			if (ret)
				break;
		}
	}

	fio_sem_up(rb_lock);
	return ret;
}

static void crc_buf(void *buf, uint32_t *hash)
{
	struct fio_md5_ctx ctx = { .hash = hash };

	fio_md5_init(&ctx);
	fio_md5_update(&ctx, buf, blocksize);
	fio_md5_final(&ctx);
}

static unsigned int read_blocks(int fd, void *buf, off_t offset, size_t size)
{
	if (__read_block(fd, buf, offset, size))
		return 0;

	return size / blocksize;
}

static int do_work(struct worker_thread *thread, void *buf)
{
	unsigned int nblocks, i;
	off_t offset;
	int nitems = 0;
	uint64_t ndupes = 0;
	uint64_t unique_capacity = 0;
	struct item *items;
	int ret;

	offset = thread->cur_offset;

	nblocks = read_blocks(thread->fd, buf, offset,
				min(thread->size, (uint64_t) chunk_size));
	if (!nblocks)
		return 1;

	items = malloc(sizeof(*items) * nblocks);

	for (i = 0; i < nblocks; i++) {
		void *thisptr = buf + (i * blocksize);

		items[i].offset = offset;
		crc_buf(thisptr, items[i].hash);
		offset += blocksize;
		nitems++;
	}

	ret = insert_chunks(items, nitems, &ndupes, &unique_capacity, &thread->zc);

	free(items);
	if (!ret) {
		thread->items += nitems;
		thread->dupes += ndupes;
		thread->unique_capacity += unique_capacity;
		return 0;
	}

	return ret;
}

static void thread_init_zlib_control(struct worker_thread *thread)
{
	size_t sz;

	z_stream *stream = &thread->zc.stream;
	stream->zalloc = Z_NULL;
	stream->zfree = Z_NULL;
	stream->opaque = Z_NULL;

	if (deflateInit(stream, Z_DEFAULT_COMPRESSION) != Z_OK)
		return;

	thread->zc.buf_in = fio_memalign(blocksize, blocksize, false);
	sz = deflateBound(stream, blocksize);
	thread->zc.buf_out = fio_memalign(blocksize, sz, false);
}

static void *thread_fn(void *data)
{
	struct worker_thread *thread = data;
	void *buf;

	buf = fio_memalign(blocksize, chunk_size, false);
	thread_init_zlib_control(thread);

	do {
		if (get_work(&thread->cur_offset, &thread->size)) {
			thread->err = 1;
			break;
		}
		if (do_work(thread, buf)) {
			thread->err = 1;
			break;
		}
	} while (1);

	thread->done = 1;
	fio_memfree(buf, chunk_size, false);
	return NULL;
}

static void show_progress(struct worker_thread *threads, unsigned long total)
{
	unsigned long last_nitems = 0;
	struct timespec last_tv;

	fio_gettime(&last_tv, NULL);

	while (print_progress) {
		unsigned long this_items;
		unsigned long nitems = 0;
		uint64_t tdiff;
		float perc;
		int some_done = 0;
		int i;

		for (i = 0; i < num_threads; i++) {
			nitems += threads[i].items;
			some_done = threads[i].done;
			if (some_done)
				break;
		}

		if (some_done)
			break;

		perc = (float) nitems / (float) total;
		perc *= 100.0;
		this_items = nitems - last_nitems;
		this_items *= blocksize;
		tdiff = mtime_since_now(&last_tv);
		if (tdiff) {
			this_items = (this_items * 1000) / (tdiff * 1024);
			printf("%3.2f%% done (%luKiB/sec)\r", perc, this_items);
			last_nitems = nitems;
			fio_gettime(&last_tv, NULL);
		} else {
			printf("%3.2f%% done\r", perc);
		}
		fflush(stdout);
		usleep(250000);
	};
}

static int run_dedupe_threads(struct fio_file *f, uint64_t dev_size,
			      uint64_t *nextents, uint64_t *nchunks,
			      uint64_t *unique_capacity)
{
	struct worker_thread *threads;
	unsigned long nitems, total_items;
	int i, err = 0;

	total_size = dev_size;
	total_items = dev_size / blocksize;
	cur_offset = 0;
	size_lock = fio_sem_init(FIO_SEM_UNLOCKED);

	threads = malloc(num_threads * sizeof(struct worker_thread));
	for (i = 0; i < num_threads; i++) {
		memset(&threads[i], 0, sizeof(struct worker_thread));
		threads[i].fd = f->fd;

		err = pthread_create(&threads[i].thread, NULL, thread_fn, &threads[i]);
		if (err) {
			log_err("fio: thread startup failed\n");
			break;
		}
	}

	show_progress(threads, total_items);

	nitems = 0;
	*nextents = 0;
	*nchunks = 1;
	*unique_capacity = 0;
	for (i = 0; i < num_threads; i++) {
		void *ret;
		pthread_join(threads[i].thread, &ret);
		nitems += threads[i].items;
		*nchunks += threads[i].dupes;
		*unique_capacity += threads[i].unique_capacity;
	}

	printf("Threads(%u): %lu items processed\n", num_threads, nitems);

	*nextents = nitems;
	*nchunks = nitems - *nchunks;

	fio_sem_remove(size_lock);
	free(threads);
	return err;
}

static int dedupe_check(const char *filename, uint64_t *nextents,
			uint64_t *nchunks, uint64_t *unique_capacity)
{
	uint64_t dev_size;
	struct stat sb;
	int flags;

	flags = O_RDONLY;
	if (odirect)
		flags |= OS_O_DIRECT;

	memset(&file, 0, sizeof(file));
	file.file_name = strdup(filename);

	file.fd = open(filename, flags);
	if (file.fd == -1) {
		perror("open");
		goto err;
	}

	if (fstat(file.fd, &sb) < 0) {
		perror("fstat");
		goto err;
	}

	dev_size = get_size(&file, &sb);
	if (!dev_size)
		goto err;

	if (use_bloom) {
		uint64_t bloom_entries;

		bloom_entries = 8 * (dev_size / blocksize);
		bloom = bloom_new(bloom_entries);
	}

	printf("Will check <%s>, size <%llu>, using %u threads\n", filename,
				(unsigned long long) dev_size, num_threads);

	return run_dedupe_threads(&file, dev_size, nextents, nchunks,
					unique_capacity);
err:
	if (file.fd != -1)
		close(file.fd);
	free(file.file_name);
	return 1;
}

static void show_chunk(struct chunk *c)
{
	struct flist_head *n;
	struct extent *e;

	printf("c hash %8x %8x %8x %8x, count %lu\n", c->hash[0], c->hash[1],
			c->hash[2], c->hash[3], (unsigned long) c->count);
	flist_for_each(n, &c->extent_list[0]) {
		e = flist_entry(n, struct extent, list);
		printf("\toffset %llu\n", (unsigned long long) e->offset);
	}
}

static const char *capacity_unit[] = {"b","KB", "MB", "GB", "TB", "PB", "EB"};

static uint64_t bytes_to_human_readable_unit(uint64_t n, const char **unit_out)
{
	uint8_t i = 0;

	while (n >= 1024) {
		i++;
		n /= 1024;
	}

	*unit_out = capacity_unit[i];
	return n;
}

static void show_stat(uint64_t nextents, uint64_t nchunks, uint64_t ndupextents,
		      uint64_t unique_capacity)
{
	double perc, ratio;
	const char *unit;
	uint64_t uc_human;

	printf("Extents=%lu, Unique extents=%lu", (unsigned long) nextents,
						(unsigned long) nchunks);
	if (!bloom)
		printf(" Duplicated extents=%lu", (unsigned long) ndupextents);
	printf("\n");

	if (nchunks) {
		ratio = (double) nextents / (double) nchunks;
		printf("De-dupe ratio: 1:%3.2f\n", ratio - 1.0);
	} else {
		printf("De-dupe ratio: 1:infinite\n");
	}

	if (ndupextents) {
		printf("De-dupe working set at least: %3.2f%%\n",
			100.0 * (double) ndupextents / (double) nextents);
	}

	perc = 1.00 - ((double) nchunks / (double) nextents);
	perc *= 100.0;
	printf("Fio setting: dedupe_percentage=%u\n", (int) (perc + 0.50));


	if (compression) {
		uc_human = bytes_to_human_readable_unit(unique_capacity, &unit);
		printf("Unique capacity %lu%s\n", (unsigned long) uc_human, unit);
	}
}

static void iter_rb_tree(uint64_t *nextents, uint64_t *nchunks, uint64_t *ndupextents)
{
	struct fio_rb_node *n;
	*nchunks = *nextents = *ndupextents = 0;

	n = rb_first(&rb_root);
	if (!n)
		return;

	do {
		struct chunk *c;

		c = rb_entry(n, struct chunk, rb_node);
		(*nchunks)++;
		*nextents += c->count;
		*ndupextents += (c->count > 1);

		if (dump_output)
			show_chunk(c);

	} while ((n = rb_next(n)) != NULL);
}

static int usage(char *argv[])
{
	log_err("Check for dedupable blocks on a device/file\n\n");
	log_err("%s: [options] <device or file>\n", argv[0]);
	log_err("\t-b\tChunk size to use\n");
	log_err("\t-t\tNumber of threads to use\n");
	log_err("\t-d\tFull extent/chunk debug output\n");
	log_err("\t-o\tUse O_DIRECT\n");
	log_err("\t-c\tFull collision check\n");
	log_err("\t-B\tUse probabilistic bloom filter\n");
	log_err("\t-p\tPrint progress indicator\n");
	log_err("\t-C\tCalculate compressible size\n");
	return 1;
}

int main(int argc, char *argv[])
{
	uint64_t nextents = 0, nchunks = 0, ndupextents = 0, unique_capacity;
	int c, ret;

	arch_init(argv);
	debug_init();

	while ((c = getopt(argc, argv, "b:t:d:o:c:p:B:C:")) != -1) {
		switch (c) {
		case 'b':
			blocksize = atoi(optarg);
			break;
		case 't':
			num_threads = atoi(optarg);
			break;
		case 'd':
			dump_output = atoi(optarg);
			break;
		case 'o':
			odirect = atoi(optarg);
			break;
		case 'c':
			collision_check = atoi(optarg);
			break;
		case 'p':
			print_progress = atoi(optarg);
			break;
		case 'B':
			use_bloom = atoi(optarg);
			break;
		case 'C':
			compression = atoi(optarg);
			break;
		case '?':
		default:
			return usage(argv);
		}
	}

	if (collision_check || dump_output || compression)
		use_bloom = 0;

	if (!num_threads)
		num_threads = cpus_configured();

	if (argc == optind)
		return usage(argv);

	sinit();

	rb_root = RB_ROOT;
	rb_lock = fio_sem_init(FIO_SEM_UNLOCKED);

	ret = dedupe_check(argv[optind], &nextents, &nchunks, &unique_capacity);

	if (!ret) {
		if (!bloom)
			iter_rb_tree(&nextents, &nchunks, &ndupextents);

		show_stat(nextents, nchunks, ndupextents, unique_capacity);
	}

	fio_sem_remove(rb_lock);
	if (bloom)
		bloom_free(bloom);
	scleanup();
	return ret;
}
