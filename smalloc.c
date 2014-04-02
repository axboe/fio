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
#include <inttypes.h>
#include <sys/types.h>
#include <limits.h>
#include <fcntl.h>

#include "mutex.h"
#include "arch/arch.h"
#include "os/os.h"
#include "smalloc.h"

#define SMALLOC_REDZONE		/* define to detect memory corruption */

#define SMALLOC_BPB	32	/* block size, bytes-per-bit in bitmap */
#define SMALLOC_BPI	(sizeof(unsigned int) * 8)
#define SMALLOC_BPL	(SMALLOC_BPB * SMALLOC_BPI)

#define INITIAL_SIZE	8192*1024	/* new pool size */
#define MAX_POOLS	128		/* maximum number of pools to setup */

#define SMALLOC_PRE_RED		0xdeadbeefU
#define SMALLOC_POST_RED	0x5aa55aa5U

unsigned int smalloc_pool_size = INITIAL_SIZE;
static const int int_mask = sizeof(int) - 1;

struct pool {
	struct fio_mutex *lock;			/* protects this pool */
	void *map;				/* map of blocks */
	unsigned int *bitmap;			/* blocks free/busy map */
	size_t free_blocks;		/* free blocks */
	size_t nr_blocks;			/* total blocks */
	size_t next_non_full;
	size_t mmap_size;
};

struct block_hdr {
	size_t size;
#ifdef SMALLOC_REDZONE
	unsigned int prered;
#endif
};

static struct pool mp[MAX_POOLS];
static unsigned int nr_pools;
static unsigned int last_pool;
static struct fio_rwlock *lock;

static inline void pool_lock(struct pool *pool)
{
	fio_mutex_down(pool->lock);
}

static inline void pool_unlock(struct pool *pool)
{
	fio_mutex_up(pool->lock);
}

static inline void global_read_lock(void)
{
	fio_rwlock_read(lock);
}

static inline void global_read_unlock(void)
{
	fio_rwlock_unlock(lock);
}

static inline void global_write_lock(void)
{
	fio_rwlock_write(lock);
}

static inline void global_write_unlock(void)
{
	fio_rwlock_unlock(lock);
}

static inline int ptr_valid(struct pool *pool, void *ptr)
{
	unsigned int pool_size = pool->nr_blocks * SMALLOC_BPL;

	return (ptr >= pool->map) && (ptr < pool->map + pool_size);
}

static inline size_t size_to_blocks(size_t size)
{
	return (size + SMALLOC_BPB - 1) / SMALLOC_BPB;
}

static int blocks_iter(struct pool *pool, unsigned int pool_idx,
		       unsigned int idx, size_t nr_blocks,
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
		       unsigned int idx, size_t nr_blocks)
{
	return blocks_iter(pool, pool_idx, idx, nr_blocks, mask_cmp);
}

static void set_blocks(struct pool *pool, unsigned int pool_idx,
		       unsigned int idx, size_t nr_blocks)
{
	blocks_iter(pool, pool_idx, idx, nr_blocks, mask_set);
}

static void clear_blocks(struct pool *pool, unsigned int pool_idx,
			 unsigned int idx, size_t nr_blocks)
{
	blocks_iter(pool, pool_idx, idx, nr_blocks, mask_clear);
}

static int find_next_zero(int word, int start)
{
	assert(word != -1U);
	word >>= start;
	return ffz(word) + start;
}

static int add_pool(struct pool *pool, unsigned int alloc_size)
{
	int bitmap_blocks;
	void *ptr;

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

	ptr = mmap(NULL, alloc_size, PROT_READ|PROT_WRITE,
			MAP_SHARED | OS_MAP_ANON, -1, 0);
	if (ptr == MAP_FAILED)
		goto out_fail;

	memset(ptr, 0, alloc_size);
	pool->map = ptr;
	pool->bitmap = (void *) ptr + (pool->nr_blocks * SMALLOC_BPL);

	pool->lock = fio_mutex_init(FIO_MUTEX_UNLOCKED);
	if (!pool->lock)
		goto out_fail;

	nr_pools++;
	return 0;
out_fail:
	fprintf(stderr, "smalloc: failed adding pool\n");
	if (pool->map)
		munmap(pool->map, pool->mmap_size);
	return 1;
}

void sinit(void)
{
	int ret;

	lock = fio_rwlock_init();
	ret = add_pool(&mp[0], INITIAL_SIZE);
	assert(!ret);
}

static void cleanup_pool(struct pool *pool)
{
	/*
	 * This will also remove the temporary file we used as a backing
	 * store, it was already unlinked
	 */
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
		fio_rwlock_remove(lock);
}

#ifdef SMALLOC_REDZONE
static void *postred_ptr(struct block_hdr *hdr)
{
	uintptr_t ptr;

	ptr = (uintptr_t) hdr + hdr->size - sizeof(unsigned int);
	ptr = (ptr + int_mask) & ~int_mask;

	return (void *) ptr;
}

static void fill_redzone(struct block_hdr *hdr)
{
	unsigned int *postred = postred_ptr(hdr);

	hdr->prered = SMALLOC_PRE_RED;
	*postred = SMALLOC_POST_RED;
}

static void sfree_check_redzone(struct block_hdr *hdr)
{
	unsigned int *postred = postred_ptr(hdr);

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
}
#else
static void fill_redzone(struct block_hdr *hdr)
{
}

static void sfree_check_redzone(struct block_hdr *hdr)
{
}
#endif

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

static void *__smalloc_pool(struct pool *pool, size_t size)
{
	size_t nr_blocks;
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

static void *smalloc_pool(struct pool *pool, size_t size)
{
	size_t alloc_size = size + sizeof(struct block_hdr);
	void *ptr;

	/*
	 * Round to int alignment, so that the postred pointer will
	 * be naturally aligned as well.
	 */
#ifdef SMALLOC_REDZONE
	alloc_size += sizeof(unsigned int);
	alloc_size = (alloc_size + int_mask) & ~int_mask;
#endif

	ptr = __smalloc_pool(pool, alloc_size);
	if (ptr) {
		struct block_hdr *hdr = ptr;

		hdr->size = alloc_size;
		fill_redzone(hdr);

		ptr += sizeof(*hdr);
		memset(ptr, 0, size);
	}

	return ptr;
}

void *smalloc(size_t size)
{
	unsigned int i;

	if (size != (unsigned int) size)
		return NULL;

	global_write_lock();
	i = last_pool;

	do {
		for (; i < nr_pools; i++) {
			void *ptr = smalloc_pool(&mp[i], size);

			if (ptr) {
				last_pool = i;
				global_write_unlock();
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
			if (add_pool(&mp[nr_pools], size))
				goto out;
		}
	} while (1);

out:
	global_write_unlock();
	return NULL;
}

char *smalloc_strdup(const char *str)
{
	char *ptr;

	ptr = smalloc(strlen(str) + 1);
	strcpy(ptr, str);
	return ptr;
}
