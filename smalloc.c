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

#undef ENABLE_RESIZE		/* define to enable pool resizing */
#define MP_SAFE			/* define to made allocator thread safe */

#define INITIAL_SIZE	65536	/* new pool size */
#define MAX_POOLS	32	/* maximum number of pools to setup */

#ifdef ENABLE_RESIZE
#define MAX_SIZE	8 * INITIAL_SIZE
static unsigned int resize_error;
#endif

struct pool {
	struct fio_mutex *lock;			/* protects this pool */
	void *map;				/* map of blocks */
	void *last;				/* next free block hint */
	unsigned int size;			/* size of pool */
	unsigned int room;			/* size left in pool */
	unsigned int largest_block;		/* largest block free */
	unsigned int free_since_compact;	/* sfree() since compact() */
	int fd;					/* memory backing fd */
	char file[PATH_MAX];			/* filename for fd */
};

static struct pool mp[MAX_POOLS];
static unsigned int nr_pools;
static unsigned int last_pool;
static struct fio_mutex *lock;

struct mem_hdr {
	unsigned int size;
};

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

#define hdr_free(hdr)		((hdr)->size & 0x80000000)
#define hdr_size(hdr)		((hdr)->size & ~0x80000000)
#define hdr_mark_free(hdr)	((hdr)->size |= 0x80000000)

static inline int ptr_valid(struct pool *pool, void *ptr)
{
	return (ptr >= pool->map) && (ptr < pool->map + pool->size);
}

static inline int __hdr_valid(struct pool *pool, struct mem_hdr *hdr,
			      unsigned int size)
{
	return ptr_valid(pool, hdr) && ptr_valid(pool, (void *) hdr + size - 1);
}

static inline int hdr_valid(struct pool *pool, struct mem_hdr *hdr)
{
	return __hdr_valid(pool, hdr, hdr_size(hdr));
}

static inline int region_free(struct mem_hdr *hdr)
{
	return hdr_free(hdr) || (!hdr_free(hdr) && !hdr_size(hdr));
}

static inline struct mem_hdr *__hdr_nxt(struct pool *pool, struct mem_hdr *hdr,
					unsigned int size)
{
	struct mem_hdr *nxt = (void *) hdr + size + sizeof(*hdr);

	if (__hdr_valid(pool, nxt, size))
		return nxt;

	return NULL;
}

static inline struct mem_hdr *hdr_nxt(struct pool *pool, struct mem_hdr *hdr)
{
	return __hdr_nxt(pool, hdr, hdr_size(hdr));
}

static void merge(struct pool *pool, struct mem_hdr *hdr, struct mem_hdr *nxt)
{
	unsigned int hfree = hdr_free(hdr);
	unsigned int nfree = hdr_free(nxt);

	hdr->size = hdr_size(hdr) + hdr_size(nxt) + sizeof(*nxt);
	nxt->size = 0;

	if (hfree)
		hdr_mark_free(hdr);
	if (nfree)
		hdr_mark_free(nxt);

	if (pool->last == nxt)
		pool->last = hdr;
}

static int combine(struct pool *pool, struct mem_hdr *prv, struct mem_hdr *hdr)
{
	if (prv && hdr_free(prv) && hdr_free(hdr)) {
		merge(pool, prv, hdr);
		return 1;
	}

	return 0;
}

static int compact_pool(struct pool *pool)
{
	struct mem_hdr *hdr = pool->map, *nxt;
	unsigned int compacted = 0;

	if (pool->free_since_compact < 50)
		return 1;

	while (hdr) {
		nxt = hdr_nxt(pool, hdr);
		if (!nxt)
			break;
		if (hdr_free(nxt) && hdr_free(hdr)) {
			merge(pool, hdr, nxt);
			compacted++;
			continue;
		}
		hdr = hdr_nxt(pool, hdr);
	}

	pool->free_since_compact = 0;
	return !!compacted;
}

static int resize_pool(struct pool *pool)
{
#ifdef ENABLE_RESIZE
	unsigned int new_size = pool->size << 1;
	struct mem_hdr *hdr, *last_hdr;
	void *ptr;

	if (new_size >= MAX_SIZE || resize_error)
		return 1;

	if (ftruncate(pool->fd, new_size) < 0)
		goto fail;

	ptr = mremap(pool->map, pool->size, new_size, 0);
	if (ptr == MAP_FAILED)
		goto fail;

	pool->map = ptr;
	hdr = pool;
	do {
		last_hdr = hdr;
	} while ((hdr = hdr_nxt(hdr)) != NULL);

	if (hdr_free(last_hdr)) {
		last_hdr->size = hdr_size(last_hdr) + new_size - pool_size;
		hdr_mark_free(last_hdr);
	} else {
		struct mem_hdr *nxt;

		nxt = (void *) last_hdr + hdr_size(last_hdr) + sizeof(*hdr);
		nxt->size = new_size - pool_size - sizeof(*hdr);
		hdr_mark_free(nxt);
	}

	pool_room += new_size - pool_size;
	pool_size = new_size;
	return 0;
fail:
	perror("resize");
	resize_error = 1;
#else
	return 1;
#endif
}

static int add_pool(struct pool *pool)
{
	struct mem_hdr *hdr;
	void *ptr;
	int fd;

	strcpy(pool->file, "/tmp/.fio_smalloc.XXXXXX");
	fd = mkstemp(pool->file);
	if (fd < 0)
		goto out_close;

	pool->size = INITIAL_SIZE;
	if (ftruncate(fd, pool->size) < 0)
		goto out_unlink;

	ptr = mmap(NULL, pool->size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (ptr == MAP_FAILED)
		goto out_unlink;

	memset(ptr, 0, pool->size);
	pool->map = pool->last = ptr;

#ifdef MP_SAFE
	pool->lock = fio_mutex_init(1);
	if (!pool->lock)
		goto out_unlink;
#endif

	pool->fd = fd;

	hdr = pool->map;
	pool->room = hdr->size = pool->size - sizeof(*hdr);
	pool->largest_block = pool->room;
	hdr_mark_free(hdr);
	global_write_lock();
	nr_pools++;
	global_write_unlock();
	return 0;
out_unlink:
	if (pool->map)
		munmap(pool->map, pool->size);
	unlink(pool->file);
out_close:
	if (fd >= 0)
		close(fd);
	return 1;
}

void sinit(void)
{
	int ret = add_pool(&mp[0]);

#ifdef MP_SAFE
	lock = fio_mutex_init(1);
#endif
	assert(!ret);
}

static void cleanup_pool(struct pool *pool)
{
	unlink(pool->file);
	close(pool->fd);
	munmap(pool->map, pool->size);

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

static void sfree_pool(struct pool *pool, void *ptr)
{
	struct mem_hdr *hdr, *nxt;

	if (!ptr)
		return;

	assert(ptr_valid(pool, ptr));

	pool_lock(pool);
	hdr = ptr - sizeof(*hdr);
	assert(!hdr_free(hdr));
	hdr_mark_free(hdr);
	pool->room -= hdr_size(hdr);

	nxt = hdr_nxt(pool, hdr);
	if (nxt && hdr_free(nxt))
		merge(pool, hdr, nxt);

	if (hdr_size(hdr) > pool->largest_block)
		pool->largest_block = hdr_size(hdr);

	pool->free_since_compact++;
	pool_unlock(pool);
}

void sfree(void *ptr)
{
	struct pool *pool = NULL;
	unsigned int i;

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

static void *smalloc_pool(struct pool *pool, unsigned int size)
{
	struct mem_hdr *hdr, *prv;
	int did_restart = 0;
	void *ret;

	/*
	 * slight chance of race with sfree() here, but acceptable
	 */
	if (!size || size > pool->room + sizeof(*hdr) ||
	    ((size > pool->largest_block) && pool->largest_block))
		return NULL;

	pool_lock(pool);
restart:
	hdr = pool->last;
	prv = NULL;
	do {
		if (combine(pool, prv, hdr))
			hdr = prv;
			
		if (hdr_free(hdr) && hdr_size(hdr) >= size)
			break;

		prv = hdr;
	} while ((hdr = hdr_nxt(pool, hdr)) != NULL);

	if (!hdr)
		goto fail;

	/*
	 * more room, adjust next header if any
	 */
	if (hdr_size(hdr) - size >= 2 * sizeof(*hdr)) {
		struct mem_hdr *nxt = __hdr_nxt(pool, hdr, size);

		if (nxt) {
			nxt->size = hdr_size(hdr) - size - sizeof(*hdr);
			if (hdr_size(hdr) == pool->largest_block)
				pool->largest_block = hdr_size(nxt);
			hdr_mark_free(nxt);
		} else
			size = hdr_size(hdr);
	} else
		size = hdr_size(hdr);

	if (size == hdr_size(hdr) && size == pool->largest_block)
		pool->largest_block = 0;

	/*
	 * also clears free bit
	 */
	hdr->size = size;
	pool->last = hdr_nxt(pool, hdr);
	if (!pool->last)
		pool->last = pool->map;
	pool->room -= size;
	pool_unlock(pool);

	ret = (void *) hdr + sizeof(*hdr);
	memset(ret, 0, size);
	return ret;
fail:
	/*
	 * if we fail to allocate, first compact the entries that we missed.
	 * if that also fails, increase the size of the pool
	 */
	++did_restart;
	if (did_restart <= 1) {
		if (!compact_pool(pool)) {
			pool->last = pool->map;
			goto restart;
		}
	}
	++did_restart;
	if (did_restart <= 2) {
		if (!resize_pool(pool)) {
			pool->last = pool->map;
			goto restart;
		}
	}
	pool_unlock(pool);
	return NULL;
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

		if (nr_pools + 1 >= MAX_POOLS)
			break;
		else {
			i = nr_pools;
			global_read_unlock();
			if (add_pool(&mp[nr_pools]))
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
