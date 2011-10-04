#ifndef FIO_OS_WINDOWS_H
#define FIO_OS_WINDOWS_H

#include <sys/types.h>
#include <errno.h>
#include <windows.h>
#include <psapi.h>
#include <stdlib.h>

#include "../smalloc.h"
#include "../file.h"
#include "../log.h"

#define FIO_HAVE_ODIRECT
#define FIO_HAVE_CPU_AFFINITY
#define FIO_HAVE_CHARDEV_SIZE
#define FIO_HAVE_FALLOCATE
#define FIO_HAVE_FDATASYNC
#define FIO_HAVE_WINDOWSAIO
#define FIO_HAVE_GETTID

#define FIO_USE_GENERIC_RAND

#define OS_MAP_ANON		MAP_ANON

#define OS_CLOCK CLOCK_REALTIME

#define FIO_PREFERRED_ENGINE	"windowsaio"

#define FIO_LITTLE_ENDIAN
#define fio_swap16(x)	_byteswap_ushort(x)
#define fio_swap32(x)	_byteswap_ulong(x)
#define fio_swap64(x)	_byteswap_uint64(x)

typedef off_t off64_t;

typedef struct {
  LARGE_INTEGER Length;
} GET_LENGTH_INFORMATION;

#define IOCTL_DISK_GET_LENGTH_INFO 0x7405C

pid_t cygwin_winpid_to_pid(int winpid);

static inline int blockdev_size(struct fio_file *f, unsigned long long *bytes)
{
	int rc = 0;
	HANDLE hFile;

	if (f->hFile == NULL) {
		hFile = CreateFile(f->file_name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
				NULL, OPEN_EXISTING, 0, NULL);
	} else {
		hFile = f->hFile;
	}

	GET_LENGTH_INFORMATION info;
	DWORD outBytes;
	LARGE_INTEGER size;
	size.QuadPart = 0;
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
	/* There's no way to invalidate the cache in Windows
	 * so just pretend to succeed */
	return 0;
}

static inline unsigned long long os_phys_mem(void)
{
	SYSTEM_INFO sysInfo;
	unsigned long addr;
	GetSystemInfo(&sysInfo);
	addr = (unsigned long)sysInfo.lpMaximumApplicationAddress;
	return addr;
}

static inline void os_get_tmpdir(char *path, int len)
{
	GetTempPath(len, path);
}

typedef DWORD_PTR os_cpu_mask_t;

static inline int gettid(void)
{
	return GetCurrentThreadId();
}

static inline int pid_to_winpid(int pid)
{
	int winpid = 0;
	DWORD outbytes = 0;
	DWORD *ids = NULL;
	size_t allocsize;
	
	allocsize = sizeof(DWORD) * 1024;
	
	do {
		if (allocsize == outbytes)
			allocsize *= 2;

		ids = realloc(ids, allocsize);
		EnumProcesses(ids, allocsize, &outbytes);
	} while (allocsize == outbytes);
	
	for (int i = 0; i < (outbytes/sizeof(DWORD)); i++) {
		if (cygwin_winpid_to_pid(ids[i]) == pid) {
			winpid = ids[i];
			break;
		}
	}
	
	free(ids);
	return winpid;
}

HANDLE WINAPI OpenThread(
    DWORD dwDesiredAccess,
    BOOL bInheritHandle,
    DWORD dwThreadId);
    
DWORD WINAPI GetProcessIdOfThread(HANDLE Thread);

static inline int fio_setaffinity(int pid, os_cpu_mask_t cpumask)
{
	HANDLE h;
	BOOL bSuccess;
	int winpid;
	
	h = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION, TRUE, pid);
	if (h != NULL) {
		bSuccess = SetThreadAffinityMask(h, cpumask);
	} else {
		// then we might have a process id instead of a thread id
		winpid = pid_to_winpid(pid);
		h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION, TRUE, winpid);
		if (h == NULL)
			return -1;

		bSuccess = SetProcessAffinityMask(h, cpumask);
	}

	CloseHandle(h);

	return (bSuccess)? 0 : -1;
}

static inline void fio_getaffinity(int pid, os_cpu_mask_t *mask)
{
	os_cpu_mask_t systemMask;
	int winpid;
	
	HANDLE h = OpenThread(THREAD_QUERY_INFORMATION, TRUE, pid);
	if (h != NULL)
		winpid = GetProcessIdOfThread(h);
	else
		winpid = pid_to_winpid(pid);
	
	h = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, winpid);

	if (h != NULL) {
		GetProcessAffinityMask(h, mask, &systemMask);
		CloseHandle(h);
	} else {
		fprintf(stderr, "fio_getaffinity failed: failed to get handle for pid %d\n", pid);
	}
	
}

static inline void fio_cpu_clear(os_cpu_mask_t *mask, int cpu)
{
	*mask ^= 1 << (cpu-1);
}

static inline void fio_cpu_set(os_cpu_mask_t *mask, int cpu)
{
	*mask |= 1 << (cpu-1);
}

static inline int fio_cpuset_init(os_cpu_mask_t *mask)
{
	*mask = 0;
	return 0;
}

static inline int fio_cpuset_exit(os_cpu_mask_t *mask)
{
	return 0;
}

#define FIO_MAX_CPUS			MAXIMUM_PROCESSORS

#ifdef MADV_FREE
#define FIO_MADV_FREE	MADV_FREE
#endif

#endif /* FIO_OS_WINDOWS_H */
