/*
 * Really simple exclusive file locking based on filename.
 * No hash indexing, just a list, so only works well for < 100 files or
 * so. But that's more than what fio needs, so should be fine.
 */
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "flist.h"
#include "filelock.h"
#include "smalloc.h"
#include "fio_sem.h"
#include "hash.h"
#include "log.h"

struct fio_filelock {
	uint32_t hash;
	struct fio_sem lock;
	struct flist_head list;
	unsigned int references;
};

#define MAX_FILELOCKS	1024
	
static struct filelock_data {
	struct flist_head list;
	struct fio_sem lock;

	struct flist_head free_list;
	struct fio_filelock ffs[MAX_FILELOCKS];
} *fld;

static void put_filelock(struct fio_filelock *ff)
{
	flist_add(&ff->list, &fld->free_list);
}

static struct fio_filelock *__get_filelock(void)
{
	struct fio_filelock *ff;

	if (flist_empty(&fld->free_list))
		return NULL;

	ff = flist_first_entry(&fld->free_list, struct fio_filelock, list);
	flist_del_init(&ff->list);
	return ff;
}

static struct fio_filelock *get_filelock(int trylock, int *retry)
{
	struct fio_filelock *ff;

	do {
		ff = __get_filelock();
		if (ff || trylock)
			break;

		fio_sem_up(&fld->lock);
		usleep(1000);
		fio_sem_down(&fld->lock);
		*retry = 1;
	} while (1);

	return ff;
}

int fio_filelock_init(void)
{
	int i;

	fld = smalloc(sizeof(*fld));
	if (!fld)
		return 1;

	INIT_FLIST_HEAD(&fld->list);
	INIT_FLIST_HEAD(&fld->free_list);

	if (__fio_sem_init(&fld->lock, FIO_SEM_UNLOCKED))
		goto err;

	for (i = 0; i < MAX_FILELOCKS; i++) {
		struct fio_filelock *ff = &fld->ffs[i];

		if (__fio_sem_init(&ff->lock, FIO_SEM_UNLOCKED))
			goto err;
		flist_add_tail(&ff->list, &fld->free_list);
	}

	return 0;
err:
	fio_filelock_exit();
	return 1;
}

void fio_filelock_exit(void)
{
	if (!fld)
		return;

	assert(flist_empty(&fld->list));
	__fio_sem_remove(&fld->lock);

	while (!flist_empty(&fld->free_list)) {
		struct fio_filelock *ff;

		ff = flist_first_entry(&fld->free_list, struct fio_filelock, list);

		flist_del_init(&ff->list);
		__fio_sem_remove(&ff->lock);
	}

	sfree(fld);
	fld = NULL;
}

static struct fio_filelock *fio_hash_find(uint32_t hash)
{
	struct flist_head *entry;
	struct fio_filelock *ff;

	flist_for_each(entry, &fld->list) {
		ff = flist_entry(entry, struct fio_filelock, list);
		if (ff->hash == hash)
			return ff;
	}

	return NULL;
}

static struct fio_filelock *fio_hash_get(uint32_t hash, int trylock)
{
	struct fio_filelock *ff;

	ff = fio_hash_find(hash);
	if (!ff) {
		int retry = 0;

		ff = get_filelock(trylock, &retry);
		if (!ff)
			return NULL;

		/*
		 * If we dropped the main lock, re-lookup the hash in case
		 * someone else added it meanwhile. If it's now there,
		 * just return that.
		 */
		if (retry) {
			struct fio_filelock *__ff;

			__ff = fio_hash_find(hash);
			if (__ff) {
				put_filelock(ff);
				return __ff;
			}
		}

		ff->hash = hash;
		ff->references = 0;
		flist_add(&ff->list, &fld->list);
	}

	return ff;
}

static bool __fio_lock_file(const char *fname, int trylock)
{
	struct fio_filelock *ff;
	uint32_t hash;

	hash = jhash(fname, strlen(fname), 0);

	fio_sem_down(&fld->lock);
	ff = fio_hash_get(hash, trylock);
	if (ff)
		ff->references++;
	fio_sem_up(&fld->lock);

	if (!ff) {
		assert(!trylock);
		return true;
	}

	if (!trylock) {
		fio_sem_down(&ff->lock);
		return false;
	}

	if (!fio_sem_down_trylock(&ff->lock))
		return false;

	fio_sem_down(&fld->lock);

	/*
	 * If we raced and the only reference to the lock is us, we can
	 * grab it
	 */
	if (ff->references != 1) {
		ff->references--;
		ff = NULL;
	}

	fio_sem_up(&fld->lock);

	if (ff) {
		fio_sem_down(&ff->lock);
		return false;
	}

	return true;
}

bool fio_trylock_file(const char *fname)
{
	return __fio_lock_file(fname, 1);
}

void fio_lock_file(const char *fname)
{
	__fio_lock_file(fname, 0);
}

void fio_unlock_file(const char *fname)
{
	struct fio_filelock *ff;
	uint32_t hash;

	hash = jhash(fname, strlen(fname), 0);

	fio_sem_down(&fld->lock);

	ff = fio_hash_find(hash);
	if (ff) {
		int refs = --ff->references;
		fio_sem_up(&ff->lock);
		if (!refs) {
			flist_del_init(&ff->list);
			put_filelock(ff);
		}
	} else
		log_err("fio: file not found for unlocking\n");

	fio_sem_up(&fld->lock);
}
