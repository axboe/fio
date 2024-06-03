#ifndef FIO_INET_ATON_LIB_H
#define FIO_INET_ATON_LIB_H

#include <arpa/inet.h>
#if defined(__QNX__)
#include <sys/socket.h>
#endif
int inet_aton(const char *cp, struct in_addr *inp);

#endif
