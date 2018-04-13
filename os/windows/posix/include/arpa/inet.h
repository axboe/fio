#ifndef ARPA_INET_H
#define ARPA_INET_H

#include <ws2tcpip.h>
#include <inttypes.h>

typedef int socklen_t;
typedef int in_addr_t;

/* EAI_SYSTEM isn't used on Windows, so map it to EAI_FAIL */
#define EAI_SYSTEM EAI_FAIL

in_addr_t inet_network(const char *cp);

#ifdef CONFIG_WINDOWS_XP
const char *inet_ntop(int af, const void *restrict src,
        char *restrict dst, socklen_t size);
int inet_pton(int af, const char *restrict src, void *restrict dst);
#endif

#endif /* ARPA_INET_H */
