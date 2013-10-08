#ifndef ARPA_INET_H
#define ARPA_INET_H

#include <winsock2.h>
#include <inttypes.h>

typedef int socklen_t;
typedef int in_addr_t;

#define IP_MULTICAST_IF 2
#define IP_MULTICAST_TTL 3
#define IP_ADD_MEMBERSHIP 5

struct ip_mreq
{
	struct in_addr imr_multiaddr;
	struct in_addr imr_interface;
};

in_addr_t inet_network(const char *cp);

const char *inet_ntop(int af, const void *restrict src,
        char *restrict dst, socklen_t size);
int inet_pton(int af, const char *restrict src, void *restrict dst);

#endif /* ARPA_INET_H */
