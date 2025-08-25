#ifndef FIO_MAC_POSIX_H
#define FIO_MAC_POSIX_H

#define POSIX_FADV_NORMAL       (0)
#define POSIX_FADV_RANDOM       (1)
#define POSIX_FADV_SEQUENTIAL   (2)
#define POSIX_FADV_DONTNEED     (4)

extern int posix_fadvise(int fd, off_t offset, off_t len, int advice);

#endif
