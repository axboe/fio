#ifndef FIO_HELPERS_H
#define FIO_HELPERS_H

struct in_addr;

extern int __weak posix_memalign(void **ptr, size_t align, size_t size);
extern int __weak posix_fallocate(int fd, off_t offset, off_t len);
extern int __weak inet_aton(const char *cp, struct in_addr *inp);

#endif
