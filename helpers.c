#include <malloc.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "compiler/compiler.h"

int __weak posix_memalign(void **ptr, size_t align, size_t size)
{
	*ptr = memalign(align, size);
	if (*ptr)
		return 0;

	return ENOMEM;
}

int __weak posix_fallocate(int fd, off_t offset, off_t len)
{
	return 0;
}

int __weak inet_aton(const char *cp, struct in_addr *inp)
{
	return 0;
}

int __weak clock_gettime(clockid_t clk_id, struct timespec *ts)
{
	struct timeval tv;
	int ret;

	ret = gettimeofday(&tv, NULL);

	ts->ts_sec = tv.tv_sec;
	ts->ts_nsec = tv.tv_usec * 1000;

	return ret;
}
