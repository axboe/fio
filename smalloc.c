/*
 * simple memory allocator, backed by mmap() so that it hands out memory
 * that can be shared across processes and threads
 */
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <limits.h>

#include "mutex.h"

#define MP_SAFE			/* define to make thread safe */
#define SMALLOC_REDZONE		/* define to detect memory corruption */

#define SMALLOC_BPB	32	/* block size, bytes-per-bit in bitmap */
#define SMALLOC_BPI	(sizeof(unsigned int) * 8)
#define SMALLOC_BPL	(SMALLOC_BPB * SMALLOC_BPI)

#define INITIAL_SIZE	1024*1024	/* new pool size */
#define MAX_POOLS	4		/* maximum number of pools to setup */

#define SMALLOC_PRE_RED		0xdeadbeefU
#define SMALLOC_POST_RED	0x5aa55aa5U

unsigned int smalloc_pool_size = INITIAL_SIZE;

struct pool {
	struct fio_mutex *lock;			/* protects this pool */
	void *map;				/* map of blocks */
	unsigned int *bitmap;			/* blocks free/busy map */
	unsigned int free_blocks;		/* free blocks */
	unsigned int nr_blocks;			/* total blocks */
	unsigned int next_non_full;
	int fd;					/* memory backing fd */
	char file[PATH_MAX];			/* filename for fd */
	unsigned int mmap_size;
};

struct block_hdr {
	unsigned int size;
#ifdef SMALLOC_REDZONE
	unsigned int prered;
#endif
};

static struct pool mp[MAX_POOLS];
static unsigned int nr_pools;
static unsigned int last_pool;
static struct fio_mutex *lock;

static inline void pool_lock(struct pool *pool)
{
	if (pool->lock)
		fio_mutex_down(pool->lock);
}

static inline void pool_unlock(struct pool *pool)
{
	if (pool->lock)
		fio_mutex_up(pool->lock);
}

static inline void global_read_lock(void)
{
	if (lock)
		fio_mutex_down_read(lock);
}

static inline void global_read_unlock(void)
{
	if (lock)
		fio_mutex_up_read(lock);
}

static inline void global_write_lock(void)
{
	if (lock)
		fio_mutex_down_write(lock);
}

static inline void global_write_unlock(void)
{
	if (lock)
		fio_mutex_up_write(lock);
}

static inline int ptr_valid(struct pool *pool, void *ptr)
{
	unsigned int pool_size = pool->nr_blocks * SMALLOC_BPL;

	return (ptr >= pool->map) && (ptr < pool->map + pool_size);
}

static inline unsigned int size_to_blocks(unsigned int size)
{
	return (size + SMALLOC_BPB - 1) / SMALLOC_BPB;
}

static int blocks_iter(struct pool *pool, unsigned int pool_idx,
		       unsigned int idx, unsigned int nr_blocks,
		       int (*func)(unsigned int *map, unsigned int mask))
{

	while (nr_blocks) {
		unsigned int this_blocks, mask;
		unsigned int *map;

		if (pool_idx >= pool->nr_blocks)
			return 0;

		map = &pool->bitmap[pool_idx];

		this_blocks = nr_blocks;
		if (this_blocks + idx > SMALLOC_BPI) {
			this_blocks = SMALLOC_BPI - idx;
			idx = SMALLOC_BPI - this_blocks;
		}

		if (this_blocks == SMALLOC_BPI)
			mask = -1U;
		else
			mask = ((1U << this_blocks) - 1) << idx;

		if (!func(map, mask))
			return 0;

		nr_blocks -= this_blocks;
		idx = 0;
		pool_idx++;
	}

	return 1;
}

static int mask_cmp(unsigned int *map, unsigned int mask)
{
	return !(*map & mask);
}

static int mask_clear(unsigned int *map, unsigned int mask)
{
	assert((*map & mask) == mask);
	*map &= ~mask;
	return 1;
}

static int mask_set(unsigned int *map, unsigned int mask)
{
	assert(!(*map & mask));
	*map |= mask;
	return 1;
}

static int blocks_free(struct pool *pool, unsigned int pool_idx,
		       unsigned int idx, unsigned int nr_blocks)
{
	return blocks_iter(pool, pool_idx, idx, nr_blocks, mask_cmp);
}

static void set_blocks(struct pool *pool, unsigned int pool_idx,
		       unsigned int idx, unsigned int nr_blocks)
{
	blocks_iter(pool, pool_idx, idx, nr_blocks, mask_set);
}

static void clear_blocks(struct pool *pool, unsigned int pool_idx,
			 unsigned int idx, unsigned int nr_blocks)
{
	blocks_iter(pool, pool_idx, idx, nr_blocks, mask_clear);
}

static inline int __ffs(int word)
{
	int r = 0;

	if (!(word & 0xffff)) {
		word >>= 16;
		r += 16;
	}
	if (!(word & 0xff)) {
		word >>= 8;
		r += 8;
	}
	if (!(word & 0xf)) {
		word >>= 4;
		r += 4;
	}
	if (!(word & 3)) {
		word >>= 2;
		r += 2;
	}
	if (!(word & 1)) {
		word >>= 1;
		r += 1;
	}

	return r;
}

static int find_next_zero(int word, int start)
{
	assert(word != -1U);
	word >>= (start + 1);
	return __ffs(~word) + start + 1;
}

static int add_pool(struct pool *pool, unsigned int alloc_size)
{
	void *ptr;
	int fd, bitmap_blocks;

	strcpy(pool->file, "/tmp/.fio_smalloc.XXXXXX");
	fd = mkstemp(pool->file);
	if (fd < 0)
		goto out_close;

#ifdef SMALLOC_REDZONE
	alloc_size += sizeof(unsigned int);
#endif
	alloc_size += sizeof(struct block_hdr);
	if (alloc_size < INITIAL_SIZE)
		alloc_size = INITIAL_SIZE;

	/* round up to nearest full number of blocks */
	alloc_size = (alloc_size + SMALLOC_BPL - 1) & ~(SMALLOC_BPL - 1);
	bitmap_blocks = alloc_size / SMALLOC_BPL;
	alloc_size += bitmap_blocks * sizeof(unsigned int);
	pool->mmap_size = alloc_size;
	
	pool->nr_blocks = bitmap_blocks;
	pool->free_blocks = bitmap_blocks * SMALLOC_BPB;

	if (ftruncate(fd, alloc_size) < 0)
		goto out_unlink;

	ptr = mmap(NULL, alloc_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (ptr == MAP_FAILED)
		goto out_unlink;

	memset(ptr, 0, alloc_size);
	pool->map = ptr;
	pool->bitmap = (void *) ptr + (pool->nr_blocks * SMALLOC_BPL);

#ifdef MP_SAFE
	pool->lock = fio_mutex_init(1);
	if (!pool->lock)
		goto out_unlink;
#endif

	pool->fd = fd;

	global_write_lock();
	nr_pools++;
	global_write_unlock();
	return 0;
out_unlink:
	fprintf(stderr, "smalloc: failed adding pool\n");
	if (pool->map)
		munmap(pool->map, pool->mmap_size);
	unlink(pool->file);
out_close:
	if (fd >= 0)
		close(fd);
	return 1;
}

void sinit(void)
{
	int ret;

#ifdef MP_SAFE
	lock = fio_mutex_rw_init();
#endif
	ret = add_pool(&mp[0], INITIAL_SIZE);
	assert(!ret);
}

static void cleanup_pool(struct pool *pool)
{
	unlink(pool->file);
	close(pool->fd);
	munmap(pool->map, pool->mmap_size);

	if (pool->lock)
		fio_mutex_remove(pool->lock);
}

void scleanup(void)
{
	unsigned int i;

	for (i = 0; i < nr_pools; i++)
		cleanup_pool(&mp[i]);

	if (lock)
		fio_mutex_remove(lock);
}

static void fill_redzone(struct block_hdr *hdr)
{
#ifdef SMALLOC_REDZONE
	unsigned int *postred = (void *) hdr + hdr->size - sizeof(unsigned int);

	hdr->prered = SMALLOC_PRE_RED;
	*postred = SMALLOC_POST_RED;
#endif
}

static void sfree_check_redzone(struct block_hdr *hdr)
{
#ifdef SMALLOC_REDZONE
	unsigned int *postred = (void *) hdr + hdr->size - sizeof(unsigned int);

	if (hdr->prered != SMALLOC_PRE_RED) {
		fprintf(stderr, "smalloc pre redzone destroyed!\n");
		fprintf(stderr, "  ptr=%p, prered=%x, expected %x\n",
				hdr, hdr->prered, SMALLOC_PRE_RED);
		assert(0);
	}
	if (*postred != SMALLOC_POST_RED) {
		fprintf(stderr, "smalloc post redzone destroyed!\n");
		fprintf(stderr, "  ptr=%p, postred=%x, expected %x\n",
				hdr, *postred, SMALLOC_POST_RED);
		assert(0);
	}
#endif
}

static void sfree_pool(struct pool *pool, void *ptr)
{
	struct block_hdr *hdr;
	unsigned int i, idx;
	unsigned long offset;

	if (!ptr)
		return;

	ptr -= sizeof(*hdr);
	hdr = ptr;

	assert(ptr_valid(pool, ptr));

	sfree_check_redzone(hdr);

	offset = ptr - pool->map;
	i = offset / SMALLOC_BPL;
	idx = (offset % SMALLOC_BPL) / SMALLOC_BPB;

	pool_lock(pool);
	clear_blocks(pool, i, idx, size_to_blocks(hdr->size));
	if (i < pool->next_non_full)
		pool->next_non_full = i;
	pool->free_blocks += size_to_blocks(hdr->size);
	pool_unlock(pool);
}

void sfree(void *ptr)
{
	struct pool *pool = NULL;
	unsigned int i;

	if (!ptr)
		return;

	global_read_lock();

	for (i = 0; i < nr_pools; i++) {
		if (ptr_valid(&mp[i], ptr)) {
			pool = &mp[i];
			break;
		}
	}

	global_read_unlock();

	assert(pool);
	sfree_pool(pool, ptr);
}

static void *__smalloc_pool(struct pool *pool, unsigned int size)
{
	unsigned int nr_blocks;
	unsigned int i;
	unsigned int offset;
	unsigned int last_idx;
	void *ret = NULL;

	pool_lock(pool);

	nr_blocks = size_to_blocks(size);
	if (nr_blocks > pool->free_blocks)
		goto fail;

	i = pool->next_non_full;
	last_idx = 0;
	offset = -1U;
	while (i < pool->nr_blocks) {
		unsigned int idx;

		if (pool->bitmap[i] == -1U) {
			i++;
			pool->next_non_full = i;
			last_idx = 0;
			continue;
		}

		idx = find_next_zero(pool->bitmap[i], last_idx);
		if (!blocks_free(pool, i, idx, nr_blocks)) {
			idx += nr_blocks;
			if (idx < SMALLOC_BPI)
				last_idx = idx;
			else {
				last_idx = 0;
				while (idx >= SMALLOC_BPI) {
					i++;
					idx -= SMALLOC_BPI;
				}
			}
			continue;
		}
		set_blocks(pool, i, idx, nr_blocks);
		offset = i * SMALLOC_BPL + idx * SMALLOC_BPB;
		break;
	}

	if (i < pool->nr_blocks) {
		pool->free_blocks -= nr_blocks;
		ret = pool->map + offset;
	}
fail:
	pool_unlock(pool);
	return ret;
}

static void *smalloc_pool(struct pool *pool, unsigned int size)
{
	struct block_hdr *hdr;
	unsigned int alloc_size;
	void *ptr;

	alloc_size = size + sizeof(*hdr);
#ifdef SMALLOC_REDZONE
	alloc_size += sizeof(unsigned int);
#endif

	ptr = __smalloc_pool(pool, alloc_size);
	if (!ptr)
		return NULL;

	hdr = ptr;
	hdr->size = alloc_size;
	ptr += sizeof(*hdr);

	fill_redzone(hdr);

	memset(ptr, 0, size);
	return ptr;
}

void *smalloc(unsigned int size)
{
	unsigned int i;

	global_read_lock();
	i = last_pool;

	do {
		for (; i < nr_pools; i++) {
			void *ptr = smalloc_pool(&mp[i], size);

			if (ptr) {
				last_pool = i;
				global_read_unlock();
				return ptr;
			}
		}
		if (last_pool) {
			last_pool = 0;
			continue;
		}

		if (nr_pools + 1 > MAX_POOLS)
			break;
		else {
			i = nr_pools;
			global_read_unlock();
			if (add_pool(&mp[nr_pools], size))
				goto out;
			global_read_lock();
		}
	} while (1);

	global_read_unlock();
out:
	return NULL;
}

char *smalloc_strdup(const char *str)
{
	char *ptr;

	ptr = smalloc(strlen(str) + 1);
	strcpy(ptr, str);
	return ptr;
}
