#ifndef ARPA_INET_H
#define ARPA_INET_H

#include <winsock2.h>
#include <inttypes.h>

typedef int socklen_t;

const char *inet_ntop(int af, const void *restrict src,
        char *restrict dst, socklen_t size);
int inet_pton(int af, const char *restrict src, void *restrict dst);

#endif /* ARPA_INET_H */
