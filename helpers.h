#ifndef FIO_HELPERS_H
#define FIO_HELPERS_H

#include "compiler/compiler.h"

#include <time.h>

struct in_addr;

extern int __weak posix_memalign(void **ptr, size_t align, size_t size);
extern int __weak posix_fallocate(int fd, off_t offset, off_t len);
extern int __weak inet_aton(const char *cp, struct in_addr *inp);
extern int __weak clock_gettime(clockid_t clk_id, struct timespec *ts);
extern int __weak sync_file_range(int fd, off64_t offset, off64_t nbytes,
					unsigned int flags);

#endif /* FIO_HELPERS_H_ */
