#include <stdlib.h>
#include <assert.h>

#include "fio.h"
#include "flist.h"
#include "hash.h"
#include "filehash.h"
#include "smalloc.h"
#include "lib/bloom.h"

#define HASH_BUCKETS	512
#define HASH_MASK	(HASH_BUCKETS - 1)

#define BLOOM_SIZE	16*1024*1024

static unsigned int file_hash_size = HASH_BUCKETS * sizeof(struct flist_head);
static unsigned int sem_hash_size = HASH_BUCKETS * sizeof(struct fio_sem *);

static struct flist_head *file_hash;
static struct fio_sem **hash_locks;
static struct bloom *file_bloom;

static unsigned short hash(const char *name)
{
	return jhash(name, strlen(name), 0) & HASH_MASK;
}

static unsigned int file_bucket(const char *file_name, struct flist_head *bucket)
{
	struct flist_head *head;

	head = &file_hash[hash(file_name)];
	if (bucket)
		bucket = head;

	return head - file_hash;
}

void fio_file_hash_lock(const char *file_name)
{
	unsigned int buckidx = file_bucket(file_name, NULL);

	if (hash_locks)
		fio_sem_down(hash_locks[buckidx]);
}

void fio_file_hash_unlock(const char *file_name)
{
	unsigned int buckidx = file_bucket(file_name, NULL);

	if (hash_locks)
		fio_sem_up(hash_locks[buckidx]);
}

void remove_file_hash(struct fio_file *f)
{
	unsigned long buckidx = file_bucket(f->file_name, NULL);

	fio_sem_down(hash_locks[buckidx]);

	if (fio_file_hashed(f)) {
		assert(!flist_empty(&f->hash_list));
		flist_del_init(&f->hash_list);
		fio_file_clear_hashed(f);
	}

	fio_sem_up(hash_locks[buckidx]);
}

static struct fio_file *__lookup_file_hash(const char *name)
{
	struct flist_head *bucket = &file_hash[hash(name)];
	struct flist_head *n;

	flist_for_each(n, bucket) {
		struct fio_file *f = flist_entry(n, struct fio_file, hash_list);

		if (!f->file_name)
			continue;

		if (!strcmp(f->file_name, name))
			return f;
	}

	return NULL;
}

struct fio_file *lookup_file_hash(const char *name)
{
	struct fio_file *f;

	fio_file_hash_lock(name);
	f = __lookup_file_hash(name);
	fio_file_hash_unlock(name);
	return f;
}

struct fio_file *add_file_hash(struct fio_file *f)
{
	struct fio_file *alias;

	if (fio_file_hashed(f))
		return NULL;

	INIT_FLIST_HEAD(&f->hash_list);

	fio_file_hash_lock(f->file_name);

	alias = __lookup_file_hash(f->file_name);
	if (!alias) {
		fio_file_set_hashed(f);
		flist_add_tail(&f->hash_list, &file_hash[hash(f->file_name)]);
	}

	fio_file_hash_unlock(f->file_name);
	return alias;
}

bool file_bloom_exists(const char *fname, bool set)
{
	return bloom_string(file_bloom, fname, strlen(fname), set);
}

void file_hash_exit(void)
{
	unsigned int i, has_entries = 0;

	for (i = 0; i < HASH_BUCKETS; i++) {
		fio_sem_down(hash_locks[i]);
		has_entries += !flist_empty(&file_hash[i]);
		fio_sem_up(hash_locks[i]);
		fio_sem_remove(hash_locks[i]);
	}

	if (has_entries)
		log_err("fio: file hash not empty on exit\n");

	sfree(file_hash);
	file_hash = NULL;
	hash_locks = NULL;
	bloom_free(file_bloom);
	file_bloom = NULL;
}

void file_hash_init(void)
{
	unsigned int i;

	file_hash = smalloc(file_hash_size);
	hash_locks = smalloc(sem_hash_size);

	for (i = 0; i < HASH_BUCKETS; i++) {
		INIT_FLIST_HEAD(&file_hash[i]);
		hash_locks[i] = fio_sem_init(FIO_SEM_UNLOCKED);
	}

	file_bloom = bloom_new(BLOOM_SIZE);
}
