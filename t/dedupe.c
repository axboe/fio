/*
 * Small tool to check for dedupable blocks in a file or device. Basically
 * just scans the filename for extents of the given size, checksums them,
 * and orders them up.
 */
#include <stdio.h>
#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <string.h>

#include "../lib/rbtree.h"
#include "../flist.h"
#include "../log.h"
#include "../mutex.h"
#include "../smalloc.h"
#include "../minmax.h"
#include "../crc/md5.h"
#include "../memalign.h"
#include "../os/os.h"

FILE *f_err;
struct timeval *fio_tv = NULL;
unsigned int fio_debug = 0;

void __dprint(int type, const char *str, ...)
{
}

struct worker_thread {
	pthread_t thread;

	volatile int done;

	int fd;
	uint64_t cur_offset;
	uint64_t size;

	unsigned long items;
	int err;
};

struct extent {
	struct flist_head list;
	uint64_t offset;
};

struct chunk {
	struct rb_node rb_node;
	struct flist_head extent_list;
	uint64_t count;
	uint32_t hash[MD5_HASH_WORDS];
};

struct item {
	uint64_t offset;
	uint32_t hash[MD5_HASH_WORDS];
};

static struct rb_root rb_root;
static struct fio_mutex *rb_lock;

static unsigned int blocksize = 4096;
static unsigned int num_threads;
static unsigned int chunk_size = 1048576;
static unsigned int dump_output;
static unsigned int odirect;
static unsigned int collision_check;
static unsigned int print_progress = 1;

static uint64_t total_size;
static uint64_t cur_offset;
static struct fio_mutex *size_lock;

static int dev_fd;

static uint64_t get_size(int fd, struct stat *sb)
{
	uint64_t ret;

	if (S_ISBLK(sb->st_mode)) {
		if (ioctl(fd, BLKGETSIZE64, &ret) < 0) {
			perror("ioctl");
			return 0;
		}
	} else
		ret = sb->st_size;

	return (ret & ~((uint64_t)blocksize - 1));
}

static int get_work(uint64_t *offset, uint64_t *size)
{
	uint64_t this_chunk;
	int ret = 1;

	fio_mutex_down(size_lock);

	if (cur_offset < total_size) {
		*offset = cur_offset;
		this_chunk = min((uint64_t)chunk_size, total_size - cur_offset);
		*size = this_chunk;
		cur_offset += this_chunk;
		ret = 0;
	}

	fio_mutex_up(size_lock);
	return ret;
}

static int read_block(int fd, void *buf, off_t offset)
{
	ssize_t ret;

	ret = pread(fd, buf, blocksize, offset);
	if (ret < 0) {
		perror("pread");
		return 1;
	} else if (!ret)
		return 1;
	else if (ret != blocksize) {
		log_err("dedupe: short read on block\n");
		return 1;
	}

	return 0;
}

static void add_item(struct chunk *c, struct item *i)
{
	struct extent *e;

	e = malloc(sizeof(*e));
	e->offset = i->offset;
	flist_add_tail(&e->list, &c->extent_list);
	c->count++;
}

static int col_check(struct chunk *c, struct item *i)
{
	struct extent *e;
	char *cbuf, *ibuf;
	int ret = 1;

	cbuf = fio_memalign(blocksize, blocksize);
	ibuf = fio_memalign(blocksize, blocksize);

	e = flist_entry(c->extent_list.next, struct extent, list);
	if (read_block(dev_fd, cbuf, e->offset))
		goto out;

	if (read_block(dev_fd, ibuf, i->offset))
		goto out;

	ret = memcmp(ibuf, cbuf, blocksize);
out:
	fio_memfree(cbuf, blocksize);
	fio_memfree(ibuf, blocksize);
	return ret;
}

static void insert_chunk(struct item *i)
{
	struct rb_node **p, *parent;
	struct chunk *c;
	int diff;

	p = &rb_root.rb_node;
	parent = NULL;
	while (*p) {
		parent = *p;

		c = rb_entry(parent, struct chunk, rb_node);
		diff = memcmp(i->hash, c->hash, sizeof(i->hash));
		if (diff < 0)
			p = &(*p)->rb_left;
		else if (diff > 0)
			p = &(*p)->rb_right;
		else {
			int ret;

			if (!collision_check)
				goto add;

			fio_mutex_up(rb_lock);
			ret = col_check(c, i);
			fio_mutex_down(rb_lock);

			if (!ret)
				goto add;

			p = &(*p)->rb_right;
		}
	}

	c = malloc(sizeof(*c));
	RB_CLEAR_NODE(&c->rb_node);
	INIT_FLIST_HEAD(&c->extent_list);
	c->count = 0;
	memcpy(c->hash, i->hash, sizeof(i->hash));
	rb_link_node(&c->rb_node, parent, p);
	rb_insert_color(&c->rb_node, &rb_root);
add:
	add_item(c, i);
}

static void insert_chunks(struct item *items, unsigned int nitems)
{
	int i;

	fio_mutex_down(rb_lock);

	for (i = 0; i < nitems; i++)
		insert_chunk(&items[i]);

	fio_mutex_up(rb_lock);
}

static void crc_buf(void *buf, uint32_t *hash)
{
	struct fio_md5_ctx ctx = { .hash = hash };

	fio_md5_init(&ctx);
	fio_md5_update(&ctx, buf, blocksize);
	fio_md5_final(&ctx);
}

static int do_work(struct worker_thread *thread, void *buf)
{
	unsigned int nblocks, i;
	off_t offset;
	int err = 0, nitems = 0;
	struct item *items;

	nblocks = thread->size / blocksize;
	offset = thread->cur_offset;
	items = malloc(sizeof(*items) * nblocks);

	for (i = 0; i < nblocks; i++) {
		if (read_block(thread->fd, buf, offset))
			break;
		items[i].offset = offset;
		crc_buf(buf, items[i].hash);
		offset += blocksize;
		nitems++;
	}

	insert_chunks(items, nitems);
	thread->items += nitems;
	free(items);
	return err;
}

static void *thread_fn(void *data)
{
	struct worker_thread *thread = data;
	void *buf;

	buf = fio_memalign(blocksize, blocksize);

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
	fio_memfree(buf, blocksize);
	return NULL;
}

static int __dedupe_check(int fd, uint64_t dev_size)
{
	struct worker_thread *threads;
	unsigned long nitems, total_items;
	int i, err = 0;

	total_size = dev_size;
	total_items = dev_size / blocksize;
	cur_offset = 0;
	size_lock = fio_mutex_init(FIO_MUTEX_UNLOCKED);

	threads = malloc(num_threads * sizeof(struct worker_thread));
	for (i = 0; i < num_threads; i++) {
		threads[i].fd = fd;
		threads[i].items = 0;
		threads[i].err = 0;
		threads[i].done = 0;

		err = pthread_create(&threads[i].thread, NULL, thread_fn, &threads[i]);
		if (err) {
			log_err("fio: thread startup failed\n");
			break;
		}
	}

	while (print_progress) {
		float perc;
		int some_done;

		nitems = 0;
		for (i = 0; i < num_threads; i++) {
			nitems += threads[i].items;
			some_done = threads[i].done;
			if (some_done)
				break;
		}

		if (some_done)
			break;

		perc = (float) nitems / (float) total_items;
		perc *= 100.0;
		printf("%3.2f%% done\r", perc);
		fflush(stdout);
		usleep(200000);
	};

	nitems = 0;
	for (i = 0; i < num_threads; i++) {
		void *ret;
		pthread_join(threads[i].thread, &ret);
		nitems += threads[i].items;
	}

	printf("Threads(%u): %lu items processed\n", num_threads, nitems);

	fio_mutex_remove(size_lock);
	return err;
}

static int dedupe_check(const char *filename)
{
	uint64_t dev_size;
	struct stat sb;
	int flags;

	flags = O_RDONLY;
	if (odirect)
		flags |= O_DIRECT;

	dev_fd = open(filename, flags);
	if (dev_fd == -1) {
		perror("open");
		return 1;
	}

	if (fstat(dev_fd, &sb) < 0) {
		perror("fstat");
		close(dev_fd);
		return 1;
	}

	dev_size = get_size(dev_fd, &sb);
	if (!dev_size) {
		close(dev_fd);
		return 1;
	}

	printf("Will check <%s>, size <%lu>\n", filename, dev_size);

	return __dedupe_check(dev_fd, dev_size);
}

static void show_chunk(struct chunk *c)
{
	struct flist_head *n;
	struct extent *e;

	printf("c hash %8x %8x %8x %8x, count %lu\n", c->hash[0], c->hash[1], c->hash[2], c->hash[3], c->count);
	flist_for_each(n, &c->extent_list) {
		e = flist_entry(n, struct extent, list);
		printf("\toffset %lu\n", e->offset);
	}
}

static void iter_rb_tree(void)
{
	struct rb_node *n;
	uint64_t nchunks;
	uint64_t nextents;
	double perc;

	nchunks = nextents = 0;

	n = rb_first(&rb_root);
	if (!n)
		return;

	do {
		struct chunk *c;

		c = rb_entry(n, struct chunk, rb_node);
		nchunks++;
		nextents += c->count;

		if (dump_output)
			show_chunk(c);

	} while ((n = rb_next(n)) != NULL);

	printf("Extents=%lu, Unique extents=%lu\n", nextents, nchunks);
	printf("De-dupe factor: %3.2f\n", (double) nextents / (double) nchunks);

	perc = 1.00 - ((double) nchunks / (double) nextents);
	perc *= 100.0;
	printf("Fio setting: dedupe_percentage=%u\n", (int) (perc + 0.50));
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
	log_err("\t-p\tPrint progress indicator\n");
	return 1;
}

int main(int argc, char *argv[])
{
	int c, ret;

	while ((c = getopt(argc, argv, "b:t:d:o:c:p:")) != -1) {
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
		case '?':
		default:
			return usage(argv);
		}
	}

	if (!num_threads)
		num_threads = cpus_online();

	if (argc == optind)
		return usage(argv);

	sinit();

	rb_root = RB_ROOT;
	rb_lock = fio_mutex_init(FIO_MUTEX_UNLOCKED);

	ret = dedupe_check(argv[optind]);

	iter_rb_tree();

	scleanup();
	return ret;
}
