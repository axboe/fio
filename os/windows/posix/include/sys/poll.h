#ifndef SYS_POLL_H
#define SYS_POLL_H

typedef int nfds_t;

struct pollfd
{
	int fd;
	short events;
	short revents;
};

int poll(struct pollfd fds[], nfds_t nfds, int timeout);

#endif /* SYS_POLL_H */
