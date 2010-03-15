#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <unistd.h>

#include "compiler/compiler.h"
#include "os/os.h"

#ifndef __NR_fallocate
int __weak posix_fallocate(int fd, off_t offset, off_t len)
{
	return 0;
}
#endif

int __weak inet_aton(const char *cp, struct in_addr *inp)
{
	return 0;
}

int __weak clock_gettime(clockid_t clk_id, struct timespec *ts)
{
	struct timeval tv;
	int ret;

	ret = gettimeofday(&tv, NULL);

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = tv.tv_usec * 1000;

	return ret;
}

#ifndef __NR_sync_file_range
int __weak sync_file_range(int fd, off64_t offset, off64_t nbytes,
			   unsigned int flags)
{
	errno = ENOSYS;
	return -1;
}
#endif
