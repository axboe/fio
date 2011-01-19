#ifndef FIO_OS_WINDOWS_H
#define FIO_OS_WINDOWS_H

#include <sys/types.h>
#include <errno.h>
#include <windows.h>

#include "../smalloc.h"
#include "../file.h"
#include "../log.h"

#define FIO_HAVE_ODIRECT
#define FIO_USE_GENERIC_RAND
#define FIO_HAVE_CHARDEV_SIZE
#define FIO_USE_GENERIC_RAND

#define FIO_HAVE_FALLOCATE
#define FIO_HAVE_FDATASYNC
#define FIO_HAVE_WINDOWSAIO

#define OS_MAP_ANON		MAP_ANON

#define OS_CLOCK CLOCK_REALTIME

#define FIO_PREFERRED_ENGINE	"windowsaio"

typedef off_t off64_t;

typedef struct {
  LARGE_INTEGER Length;
} GET_LENGTH_INFORMATION;

#define IOCTL_DISK_GET_LENGTH_INFO 0x7405C

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

#ifdef MADV_FREE
#define FIO_MADV_FREE	MADV_FREE
#endif

#endif /* FIO_OS_WINDOWS_H */
