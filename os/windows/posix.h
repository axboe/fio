#ifndef FIO_WINDOWS_POSIX_H
#define FIO_WINDOWS_POSIX_H

typedef int clockid_t;

extern int inet_aton(const char *, struct in_addr *);
extern int win_to_posix_error(DWORD winerr);

#endif
