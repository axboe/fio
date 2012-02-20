#ifndef FIO_HELPERS_H
#define FIO_HELPERS_H

#include "compiler/compiler.h"

#include <sys/types.h>
#include <time.h>

struct in_addr;

extern int _weak fallocate(int fd, int mode, off_t offset, off_t len);
extern int _weak posix_memalign(void **ptr, size_t align, size_t size);
extern int _weak posix_fallocate(int fd, off_t offset, off_t len);
extern int _weak inet_aton(const char *cp, struct in_addr *inp);
extern int _weak clock_gettime(clockid_t clk_id, struct timespec *ts);
extern int _weak sync_file_range(int fd, off64_t offset, off64_t nbytes,
					unsigned int flags);

#endif /* FIO_HELPERS_H_ */
