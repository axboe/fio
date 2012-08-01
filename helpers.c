#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <unistd.h>

#include "compiler/compiler.h"
#include "arch/arch.h"
#include "os/os.h"

#ifndef FIO_HAVE_LINUX_FALLOCATE 
int _weak fallocate(int fd, int mode, off_t offset, off_t len)
{
	errno = ENOSYS;
	return -1;
}
#endif

#ifndef __NR_fallocate
int _weak posix_fallocate(int fd, off_t offset, off_t len)
{
	return 0;
}
#endif

int _weak inet_aton(const char *cp, struct in_addr *inp)
{
	return 0;
}

int _weak clock_gettime(clockid_t clk_id, struct timespec *ts)
{
	struct timeval tv;
	int ret;

	ret = gettimeofday(&tv, NULL);

	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = tv.tv_usec * 1000;

	return ret;
}

#ifndef __NR_sync_file_range
int _weak sync_file_range(int fd, off64_t offset, off64_t nbytes,
			   unsigned int flags)
{
	errno = ENOSYS;
	return -1;
}
#endif
