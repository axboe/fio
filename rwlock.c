#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <assert.h>

#include "log.h"
#include "rwlock.h"
#include "os/os.h"

void fio_rwlock_write(struct fio_rwlock *lock)
{
	assert(lock->magic == FIO_RWLOCK_MAGIC);
	pthread_rwlock_wrlock(&lock->lock);
}

void fio_rwlock_read(struct fio_rwlock *lock)
{
	assert(lock->magic == FIO_RWLOCK_MAGIC);
	pthread_rwlock_rdlock(&lock->lock);
}

void fio_rwlock_unlock(struct fio_rwlock *lock)
{
	assert(lock->magic == FIO_RWLOCK_MAGIC);
	pthread_rwlock_unlock(&lock->lock);
}

void fio_rwlock_remove(struct fio_rwlock *lock)
{
	assert(lock->magic == FIO_RWLOCK_MAGIC);
	pthread_rwlock_destroy(&lock->lock);
	munmap((void *) lock, sizeof(*lock));
}

struct fio_rwlock *fio_rwlock_init(void)
{
	struct fio_rwlock *lock;
	pthread_rwlockattr_t attr;
	int ret;

	lock = (void *) mmap(NULL, sizeof(struct fio_rwlock),
				PROT_READ | PROT_WRITE,
				OS_MAP_ANON | MAP_SHARED, -1, 0);
	if (lock == MAP_FAILED) {
		perror("mmap rwlock");
		lock = NULL;
		goto err;
	}

	lock->magic = FIO_RWLOCK_MAGIC;

	ret = pthread_rwlockattr_init(&attr);
	if (ret) {
		log_err("pthread_rwlockattr_init: %s\n", strerror(ret));
		goto err;
	}
#ifdef CONFIG_PSHARED
	ret = pthread_rwlockattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
	if (ret) {
		log_err("pthread_rwlockattr_setpshared: %s\n", strerror(ret));
		goto destroy_attr;
	}

	ret = pthread_rwlock_init(&lock->lock, &attr);
#else
	ret = pthread_rwlock_init(&lock->lock, NULL);
#endif

	if (ret) {
		log_err("pthread_rwlock_init: %s\n", strerror(ret));
		goto destroy_attr;
	}

	pthread_rwlockattr_destroy(&attr);

	return lock;
destroy_attr:
	pthread_rwlockattr_destroy(&attr);
err:
	if (lock)
		fio_rwlock_remove(lock);
	return NULL;
}
