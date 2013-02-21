#ifndef NETINET_IN_H
#define NETINET_IN_H

#include <inttypes.h>
#include <sys/un.h>

struct in6_addr
{
	uint8_t s6_addr[16];
};

struct sockaddr_in6
{
	sa_family_t		sin6_family;   /* AF_INET6 */
	in_port_t		sin6_port;     /* Port number */
	uint32_t		sin6_flowinfo; /* IPv6 traffic class and flow information */
	struct in6_addr	sin6_addr;     /* IPv6 address */
	uint32_t		sin6_scope_id; /* Set of interfaces for a scope */
};

#endif /* NETINET_IN_H */
