#ifndef FIO_HELPERS_H
#define FIO_HELPERS_H

#include <sys/types.h>

#include "os/os.h"

extern int fallocate(int fd, int mode, off_t offset, off_t len);
extern int posix_fallocate(int fd, off_t offset, off_t len);
#ifndef CONFIG_SYNC_FILE_RANGE
extern int sync_file_range(int fd, uint64_t offset, uint64_t nbytes,
					unsigned int flags);
#endif
extern int posix_fadvise(int fd, off_t offset, off_t len, int advice);

#endif /* FIO_HELPERS_H_ */
