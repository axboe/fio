#ifndef FIO_WINDOWS_POSIX_H
#define FIO_WINDOWS_POSIX_H

typedef off_t off64_t;
typedef int clockid_t;

extern int clock_gettime(clockid_t clock_id, struct timespec *tp);
extern int inet_aton(const char *, struct in_addr *);
extern int win_to_posix_error(DWORD winerr);

#endif
