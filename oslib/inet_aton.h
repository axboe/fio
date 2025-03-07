#ifndef FIO_INET_ATON_LIB_H
#define FIO_INET_ATON_LIB_H

#include <arpa/inet.h>

int inet_aton(const char *cp, struct in_addr *inp);

#endif
