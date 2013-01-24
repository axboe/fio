#ifndef FIO_HELPERS_H
#define FIO_HELPERS_H

#include "compiler/compiler.h"

#include <sys/types.h>
#include <time.h>

extern int fallocate(int fd, int mode, off_t offset, off_t len);
extern int posix_fallocate(int fd, off_t offset, off_t len);
extern int sync_file_range(int fd, off64_t offset, off64_t nbytes,
					unsigned int flags);
extern int posix_fadvise(int fd, off_t offset, off_t len, int advice);

#endif /* FIO_HELPERS_H_ */
