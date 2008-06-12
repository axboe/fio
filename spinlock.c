#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>

#include "arch/arch.h"
#include "spinlock.h"

void fio_spinlock_remove(struct fio_spinlock *lock)
{
	close(lock->lock_fd);
	munmap((void *) lock, sizeof(*lock));
}

struct fio_spinlock *fio_spinlock_init(void)
{
	char spinlock_name[] = "/tmp/.fio_spinlock.XXXXXX";
	struct fio_spinlock *lock = NULL;
	int fd;

	fd = mkstemp(spinlock_name);
	if (fd < 0) {
		perror("open spinlock");
		return NULL;
	}

	if (ftruncate(fd, sizeof(struct fio_spinlock)) < 0) {
		perror("ftruncate spinlock");
		goto err;
	}

	lock = (void *) mmap(NULL, sizeof(struct fio_spinlock),
				PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (lock == MAP_FAILED) {
		perror("mmap spinlock");
		close(fd);
		lock = NULL;
		goto err;
	}

	unlink(spinlock_name);
	lock->lock_fd = fd;
	spin_lock_init(&lock->slock);

	return lock;
err:
	if (lock)
		fio_spinlock_remove(lock);

	unlink(spinlock_name);
	return NULL;
}
