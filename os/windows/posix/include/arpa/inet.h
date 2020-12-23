#ifndef ARPA_INET_H
#define ARPA_INET_H

#include <ws2tcpip.h>
#include <inttypes.h>

typedef int socklen_t;
typedef int in_addr_t;

/* EAI_SYSTEM isn't used on Windows, so map it to EAI_FAIL */
#define EAI_SYSTEM EAI_FAIL

in_addr_t inet_network(const char *cp);

#endif /* ARPA_INET_H */
