#ifndef FIO_OS_WINDOWS_H
#define FIO_OS_WINDOWS_H

#define FIO_OS	os_windows

#include <sys/types.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <errno.h>
#include <winsock2.h>
#include <windows.h>
#include <psapi.h>
#include <stdlib.h>

#include "../smalloc.h"
#include "../debug.h"
#include "../file.h"
#include "../log.h"
#include "../lib/hweight.h"
#include "../oslib/strcasestr.h"
#include "../lib/types.h"

#include "windows/posix.h"

#ifndef PTHREAD_STACK_MIN
#define PTHREAD_STACK_MIN 65535
#endif

#define FIO_HAVE_ODIRECT
#define FIO_HAVE_CPU_AFFINITY
#define FIO_HAVE_CHARDEV_SIZE
#define FIO_HAVE_GETTID
#define FIO_EMULATED_MKDIR_TWO

#define FIO_PREFERRED_ENGINE		"windowsaio"
#define FIO_PREFERRED_CLOCK_SOURCE	CS_CGETTIME
#define FIO_OS_PATH_SEPARATOR		'\\'

#define OS_MAP_ANON		MAP_ANON

#define fio_swap16(x)	_byteswap_ushort(x)
#define fio_swap32(x)	_byteswap_ulong(x)
#define fio_swap64(x)	_byteswap_uint64(x)

#define _SC_PAGESIZE			0x1
#define _SC_NPROCESSORS_ONLN	0x2
#define _SC_PHYS_PAGES			0x4

#define SA_RESTART	0
#define SIGPIPE		0

/*
 * Windows doesn't have O_DIRECT or O_SYNC, so define them
 * here so we can reject them at runtime when using the _open
 * interface (windowsaio uses CreateFile)
 */
#define O_DIRECT	0x1000000
#define O_SYNC		0x2000000

/* Windows doesn't support madvise, so any values will work */
#define POSIX_MADV_DONTNEED		0
#define POSIX_MADV_SEQUENTIAL	0
#define POSIX_MADV_RANDOM		0

#define F_SETFL			0x1
#define F_GETFL			0x2
#define O_NONBLOCK		FIONBIO

/* Winsock doesn't support MSG_WAIT */
#define OS_MSG_DONTWAIT	0

#ifndef S_ISSOCK
#define S_ISSOCK(x) 0
#endif

#define SIGCONT	0
#define SIGUSR1	1
#define SIGUSR2 2

typedef int sigset_t;
typedef int siginfo_t;

struct sigaction
{
	void (*sa_handler)(int);
	sigset_t sa_mask;
	int sa_flags;
	void* (*sa_sigaction)(int, siginfo_t *, void*);
};

long sysconf(int name);

int kill(pid_t pid, int sig);
pid_t setsid(void);
int setgid(gid_t gid);
int setuid(uid_t uid);
int nice(int incr);
int sigaction(int sig, const struct sigaction *act,
		struct sigaction *oact);
int fsync(int fildes);
int fork(void);
int fcntl(int fildes, int cmd, ...);
int fdatasync(int fildes);
int lstat(const char * path, struct stat * buf);
uid_t geteuid(void);
char* ctime_r(const time_t *t, char *buf);
int nanosleep(const struct timespec *rqtp, struct timespec *rmtp);
ssize_t pread(int fildes, void *buf, size_t nbyte, off_t offset);
ssize_t pwrite(int fildes, const void *buf, size_t nbyte,
		off_t offset);

static inline int blockdev_size(struct fio_file *f, unsigned long long *bytes)
{
	int rc = 0;
	HANDLE hFile;
	GET_LENGTH_INFORMATION info;
	DWORD outBytes;

	if (f->hFile == NULL) {
		hFile = CreateFile(f->file_name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
				NULL, OPEN_EXISTING, 0, NULL);
	} else {
		hFile = f->hFile;
	}

	if (DeviceIoControl(hFile, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &info, sizeof(info), &outBytes, NULL))
		*bytes = info.Length.QuadPart;
	else
		rc = EIO;

	/* If we were passed a POSIX fd,
	 * close the HANDLE we created via CreateFile */
	if (hFile != INVALID_HANDLE_VALUE && f->hFile == NULL)
		CloseHandle(hFile);

	return rc;
}

static inline int chardev_size(struct fio_file *f, unsigned long long *bytes)
{
	return blockdev_size(f, bytes);
}

static inline int blockdev_invalidate_cache(struct fio_file *f)
{
	return ENOTSUP;
}

static inline unsigned long long os_phys_mem(void)
{
	long pagesize, pages;

	pagesize = sysconf(_SC_PAGESIZE);
	pages = sysconf(_SC_PHYS_PAGES);
	if (pages == -1 || pagesize == -1)
		return 0;

	return (unsigned long long) pages * (unsigned long long) pagesize;
}

#ifndef CONFIG_HAVE_GETTID
static inline int gettid(void)
{
	return GetCurrentThreadId();
}
#endif

static inline int init_random_seeds(uint64_t *rand_seeds, int size)
{
	HCRYPTPROV hCryptProv;

	if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		errno = GetLastError();
		log_err("CryptAcquireContext() failed: error %d\n", errno);
		return 1;
	}

	if (!CryptGenRandom(hCryptProv, size, (BYTE*)rand_seeds)) {
		errno = GetLastError();
		log_err("CryptGenRandom() failed, error %d\n", errno);
		CryptReleaseContext(hCryptProv, 0);
		return 1;
	}

	CryptReleaseContext(hCryptProv, 0);
	return 0;
}

static inline int fio_set_sched_idle(void)
{
	/* SetThreadPriority returns nonzero for success */
	return (SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_IDLE))? 0 : -1;
}

static inline int fio_mkdir(const char *path, mode_t mode) {
	DWORD dwAttr = GetFileAttributesA(path);

	if (dwAttr != INVALID_FILE_ATTRIBUTES &&
	    (dwAttr & FILE_ATTRIBUTE_DIRECTORY)) {
		errno = EEXIST;
		return -1;
	}

	if (CreateDirectoryA(path, NULL) == 0) {
		log_err("CreateDirectoryA = %d\n", GetLastError());
		errno = win_to_posix_error(GetLastError());
		return -1;
	}

	return 0;
}

#ifdef CONFIG_WINDOWS_XP
#include "os-windows-xp.h"
#else
#define FIO_HAVE_CPU_ONLINE_SYSCONF
unsigned int cpus_online(void);
#include "os-windows-7.h"
#endif

int first_set_cpu(os_cpu_mask_t *cpumask);
int fio_setaffinity(int pid, os_cpu_mask_t cpumask);
int fio_cpuset_init(os_cpu_mask_t *mask);
int fio_getaffinity(int pid, os_cpu_mask_t *mask);
void fio_cpu_clear(os_cpu_mask_t *mask, int cpu);
void fio_cpu_set(os_cpu_mask_t *mask, int cpu);
int fio_cpu_isset(os_cpu_mask_t *mask, int cpu);
int fio_cpu_count(os_cpu_mask_t *mask);
int fio_cpuset_exit(os_cpu_mask_t *mask);

#endif /* FIO_OS_WINDOWS_H */
