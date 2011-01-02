#ifndef FIO_OS_WINDOWS_H
#define FIO_OS_WINDOWS_H


#include <sys/types.h>
#include <errno.h>


#define FIO_HAVE_ODIRECT
#define FIO_USE_GENERIC_RAND
#define FIO_HAVE_CHARDEV_SIZE
#define FIO_USE_GENERIC_RAND

#define FIO_HAVE_FALLOCATE
#define FIO_HAVE_FDATASYNC
#define FIO_HAVE_WINDOWSAIO

/* TODO add support for FIO_HAVE_CPU_AFFINITY */

#define OS_MAP_ANON		MAP_ANON

typedef off_t off64_t;


#define FIO_NOTUNIX

#include <windows.h>
#include <io.h>

typedef void* HANDLE;

BOOL WINAPI GetFileSizeEx(
   HANDLE hFile,
   PLARGE_INTEGER lpFileSize
);

long _get_osfhandle(
   int fd
);

typedef struct {
  LARGE_INTEGER Length;
} GET_LENGTH_INFORMATION;

#define IOCTL_DISK_GET_LENGTH_INFO 0x7405C


static inline int blockdev_size(int fd, unsigned long long *bytes)
{
	int rc = 0;
	HANDLE hFile = (HANDLE)_get_osfhandle(fd);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		GET_LENGTH_INFORMATION info;
		DWORD outBytes;
		LARGE_INTEGER size;
		size.QuadPart = 0;
		if (DeviceIoControl(hFile, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &info, sizeof(info), &outBytes, NULL))
			*bytes = info.Length.QuadPart;
		else
			rc = EIO;
	}

	return 0;
}

static inline int chardev_size(int fd, unsigned long long *bytes)
{
	return blockdev_size(fd, bytes);
}

static inline int blockdev_invalidate_cache(int fd)
{
	int rc = 0;
	HANDLE hFile = (HANDLE)_get_osfhandle(fd);

	if (hFile != INVALID_HANDLE_VALUE)
		FlushFileBuffers(hFile);
	else
		rc = EIO;

	return rc;
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

#ifdef MADV_FREE
#define FIO_MADV_FREE	MADV_FREE
#endif


#endif /* FIO_OS_WINDOWS_H */
