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

#endif /* POLL_H */
