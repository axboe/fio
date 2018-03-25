#ifndef POLL_H
#define POLL_H

typedef int nfds_t;

struct pollfd
{
	int fd;
	short events;
	short revents;
};

int poll(struct pollfd fds[], nfds_t nfds, int timeout);

#define POLLOUT	1
#define POLLIN	2
#define POLLERR	0
#define POLLHUP	1

#endif /* POLL_H */
