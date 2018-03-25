#ifndef POLL_H
#define POLL_H

#include <winsock2.h>

typedef int nfds_t;

#ifdef CONFIG_WINDOWS_XP
struct pollfd
{
	int fd;
	short events;
	short revents;
};

#define POLLOUT	1
#define POLLIN	2
#define POLLERR	0
#define POLLHUP	1
#endif /* CONFIG_WINDOWS_XP */

int poll(struct pollfd fds[], nfds_t nfds, int timeout);

#endif /* POLL_H */
