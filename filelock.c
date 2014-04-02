/*
 * Really simple exclusive file locking based on filename.
 * No hash indexing, just a list, so only works well for < 100 files or
 * so. But that's more than what fio needs, so should be fine.
 */
#include <inttypes.h>
#include <string.h>
#include <assert.h>

#include "flist.h"
#include "filelock.h"
#include "smalloc.h"
#include "mutex.h"
#include "hash.h"
#include "log.h"

struct fio_filelock {
	uint32_t hash;
	struct fio_mutex lock;
	struct flist_head list;
	unsigned int references;
};
	
static struct flist_head *filelock_list;
static struct fio_mutex *filelock_lock;

int fio_filelock_init(void)
{
	filelock_list = smalloc(sizeof(*filelock_list));
	if (!filelock_list)
		return 1;

	INIT_FLIST_HEAD(filelock_list);
	filelock_lock = fio_mutex_init(FIO_MUTEX_UNLOCKED);
	if (!filelock_lock) {
		sfree(filelock_list);
		return 1;
	}

	return 0;
}

void fio_filelock_exit(void)
{
	if (!filelock_list)
		return;

	assert(flist_empty(filelock_list));
	sfree(filelock_list);
	filelock_list = NULL;
	fio_mutex_remove(filelock_lock);
	filelock_lock = NULL;
}

static struct fio_filelock *fio_hash_find(uint32_t hash)
{
	struct flist_head *entry;
	struct fio_filelock *ff;

	flist_for_each(entry, filelock_list) {
		ff = flist_entry(entry, struct fio_filelock, list);
		if (ff->hash == hash)
			return ff;
	}

	return NULL;
}

static struct fio_filelock *fio_hash_get(uint32_t hash)
{
	struct fio_filelock *ff;

	ff = fio_hash_find(hash);
	if (!ff) {
		ff = smalloc(sizeof(*ff));
		ff->hash = hash;
		__fio_mutex_init(&ff->lock, FIO_MUTEX_UNLOCKED);
		ff->references = 0;
		flist_add(&ff->list, filelock_list);
	}

	return ff;
}

int fio_trylock_file(const char *fname)
{
	struct fio_filelock *ff;
	uint32_t hash;

	hash = jhash(fname, strlen(fname), 0);

	fio_mutex_down(filelock_lock);
	ff = fio_hash_get(hash);
	ff->references++;
	fio_mutex_up(filelock_lock);

	if (!fio_mutex_down_trylock(&ff->lock))
		return 0;

	fio_mutex_down(filelock_lock);

	/*
	 * If we raced and the only reference to the lock is us, we can
	 * grab it
	 */
	if (ff->references != 1) {
		ff->references--;
		ff = NULL;
	}

	fio_mutex_up(filelock_lock);

	if (ff) {
		fio_mutex_down(&ff->lock);
		return 0;
	}

	return 1;
}

void fio_lock_file(const char *fname)
{
	struct fio_filelock *ff;
	uint32_t hash;

	hash = jhash(fname, strlen(fname), 0);

	fio_mutex_down(filelock_lock);
	ff = fio_hash_get(hash);
	ff->references++;
	fio_mutex_up(filelock_lock);

	fio_mutex_down(&ff->lock);
}

void fio_unlock_file(const char *fname)
{
	struct fio_filelock *ff;
	uint32_t hash;

	hash = jhash(fname, strlen(fname), 0);

	fio_mutex_down(filelock_lock);

	ff = fio_hash_find(hash);
	if (ff) {
		ff->references--;
		fio_mutex_up(&ff->lock);
		if (!ff->references) {
			flist_del(&ff->list);
			sfree(ff);
		}
	} else
		log_err("fio: file not found for unlocking\n");

	fio_mutex_up(filelock_lock);
}
