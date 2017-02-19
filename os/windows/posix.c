/* This file contains functions which implement those POSIX and Linux functions
 * that MinGW and Microsoft don't provide. The implementations contain just enough
 * functionality to support fio.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <windows.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <pthread.h>
#include <time.h>
#include <semaphore.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/resource.h>
#include <sys/poll.h>
#include <sys/wait.h>
#include <setjmp.h>

#include "../os-windows.h"
#include "../../lib/hweight.h"

extern unsigned long mtime_since_now(struct timeval *);
extern void fio_gettime(struct timeval *, void *);

/* These aren't defined in the MinGW headers */
HRESULT WINAPI StringCchCopyA(
  char *pszDest,
  size_t cchDest,
  const char *pszSrc);

HRESULT WINAPI StringCchPrintfA(
  char *pszDest,
  size_t cchDest,
  const char *pszFormat,
  ...);

int win_to_posix_error(DWORD winerr)
{
	switch (winerr)
	{
	case ERROR_FILE_NOT_FOUND:		return ENOENT;
	case ERROR_PATH_NOT_FOUND:		return ENOENT;
	case ERROR_ACCESS_DENIED:		return EACCES;
	case ERROR_INVALID_HANDLE:		return EBADF;
	case ERROR_NOT_ENOUGH_MEMORY:	return ENOMEM;
	case ERROR_INVALID_DATA:		return EINVAL;
	case ERROR_OUTOFMEMORY:			return ENOMEM;
	case ERROR_INVALID_DRIVE:		return ENODEV;
	case ERROR_NOT_SAME_DEVICE:		return EXDEV;
	case ERROR_WRITE_PROTECT:		return EROFS;
	case ERROR_BAD_UNIT:			return ENODEV;
	case ERROR_SHARING_VIOLATION:	return EACCES;
	case ERROR_LOCK_VIOLATION:		return EACCES;
	case ERROR_SHARING_BUFFER_EXCEEDED:	return ENOLCK;
	case ERROR_HANDLE_DISK_FULL:	return ENOSPC;
	case ERROR_NOT_SUPPORTED:		return ENOSYS;
	case ERROR_FILE_EXISTS:			return EEXIST;
	case ERROR_CANNOT_MAKE:			return EPERM;
	case ERROR_INVALID_PARAMETER:	return EINVAL;
	case ERROR_NO_PROC_SLOTS:		return EAGAIN;
	case ERROR_BROKEN_PIPE:			return EPIPE;
	case ERROR_OPEN_FAILED:			return EIO;
	case ERROR_NO_MORE_SEARCH_HANDLES:	return ENFILE;
	case ERROR_CALL_NOT_IMPLEMENTED:	return ENOSYS;
	case ERROR_INVALID_NAME:		return ENOENT;
	case ERROR_WAIT_NO_CHILDREN:	return ECHILD;
	case ERROR_CHILD_NOT_COMPLETE:	return EBUSY;
	case ERROR_DIR_NOT_EMPTY:		return ENOTEMPTY;
	case ERROR_SIGNAL_REFUSED:		return EIO;
	case ERROR_BAD_PATHNAME:		return ENOENT;
	case ERROR_SIGNAL_PENDING:		return EBUSY;
	case ERROR_MAX_THRDS_REACHED:	return EAGAIN;
	case ERROR_BUSY:				return EBUSY;
	case ERROR_ALREADY_EXISTS:		return EEXIST;
	case ERROR_NO_SIGNAL_SENT:		return EIO;
	case ERROR_FILENAME_EXCED_RANGE:	return EINVAL;
	case ERROR_META_EXPANSION_TOO_LONG:	return EINVAL;
	case ERROR_INVALID_SIGNAL_NUMBER:	return EINVAL;
	case ERROR_THREAD_1_INACTIVE:	return EINVAL;
	case ERROR_BAD_PIPE:			return EINVAL;
	case ERROR_PIPE_BUSY:			return EBUSY;
	case ERROR_NO_DATA:				return EPIPE;
	case ERROR_MORE_DATA:			return EAGAIN;
	case ERROR_DIRECTORY:			return ENOTDIR;
	case ERROR_PIPE_CONNECTED:		return EBUSY;
	case ERROR_NO_TOKEN:			return EINVAL;
	case ERROR_PROCESS_ABORTED:		return EFAULT;
	case ERROR_BAD_DEVICE:			return ENODEV;
	case ERROR_BAD_USERNAME:		return EINVAL;
	case ERROR_OPEN_FILES:			return EAGAIN;
	case ERROR_ACTIVE_CONNECTIONS:	return EAGAIN;
	case ERROR_DEVICE_IN_USE:		return EAGAIN;
	case ERROR_INVALID_AT_INTERRUPT_TIME:	return EINTR;
	case ERROR_IO_DEVICE:			return EIO;
	case ERROR_NOT_OWNER:			return EPERM;
	case ERROR_END_OF_MEDIA:		return ENOSPC;
	case ERROR_EOM_OVERFLOW:		return ENOSPC;
	case ERROR_BEGINNING_OF_MEDIA:	return ESPIPE;
	case ERROR_SETMARK_DETECTED:	return ESPIPE;
	case ERROR_NO_DATA_DETECTED:	return ENOSPC;
	case ERROR_POSSIBLE_DEADLOCK:	return EDEADLOCK;
	case ERROR_CRC:					return EIO;
	case ERROR_NEGATIVE_SEEK:		return EINVAL;
	case ERROR_DISK_FULL:			return ENOSPC;
	case ERROR_NOACCESS:			return EFAULT;
	case ERROR_FILE_INVALID:		return ENXIO;
	}

	return winerr;
}

int GetNumLogicalProcessors(void)
{
	SYSTEM_LOGICAL_PROCESSOR_INFORMATION *processor_info = NULL;
	DWORD len = 0;
	DWORD num_processors = 0;
	DWORD error = 0;
	DWORD i;

	while (!GetLogicalProcessorInformation(processor_info, &len)) {
		error = GetLastError();
		if (error == ERROR_INSUFFICIENT_BUFFER)
			processor_info = malloc(len);
		else {
			log_err("Error: GetLogicalProcessorInformation failed: %d\n", error);
			return -1;
		}

		if (processor_info == NULL) {
			log_err("Error: failed to allocate memory for GetLogicalProcessorInformation");
			return -1;
		}
	}

	for (i = 0; i < len / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION); i++)
	{
		if (processor_info[i].Relationship == RelationProcessorCore)
			num_processors += hweight64(processor_info[i].ProcessorMask);
	}

	free(processor_info);
	return num_processors;
}

long sysconf(int name)
{
	long val = -1;
	long val2 = -1;
	SYSTEM_INFO sysInfo;
	MEMORYSTATUSEX status;

	switch (name)
	{
	case _SC_NPROCESSORS_ONLN:
		val = GetNumLogicalProcessors();
		if (val == -1)
			log_err("sysconf(_SC_NPROCESSORS_ONLN) failed\n");

		break;

	case _SC_PAGESIZE:
		GetSystemInfo(&sysInfo);
		val = sysInfo.dwPageSize;
		break;

	case _SC_PHYS_PAGES:
		status.dwLength = sizeof(status);
		val2 = sysconf(_SC_PAGESIZE);
		if (GlobalMemoryStatusEx(&status) && val2 != -1)
			val = status.ullTotalPhys / val2;
		else
			log_err("sysconf(_SC_PHYS_PAGES) failed\n");
		break;
	default:
		log_err("sysconf(%d) is not implemented\n", name);
		break;
	}

	return val;
}

char *dl_error = NULL;

int dlclose(void *handle)
{
	return !FreeLibrary((HMODULE)handle);
}

void *dlopen(const char *file, int mode)
{
	HMODULE hMod;

	hMod = LoadLibrary(file);
	if (hMod == INVALID_HANDLE_VALUE)
		dl_error = (char*)"LoadLibrary failed";
	else
		dl_error = NULL;

	return hMod;
}

void *dlsym(void *handle, const char *name)
{
	FARPROC fnPtr;

	fnPtr = GetProcAddress((HMODULE)handle, name);
	if (fnPtr == NULL)
		dl_error = (char*)"GetProcAddress failed";
	else
		dl_error = NULL;

	return fnPtr;
}

char *dlerror(void)
{
	return dl_error;
}

/* Copied from http://blogs.msdn.com/b/joshpoley/archive/2007/12/19/date-time-formats-and-conversions.aspx */
void Time_tToSystemTime(time_t dosTime, SYSTEMTIME *systemTime)
{
    FILETIME utcFT;
    LONGLONG jan1970;

    jan1970 = Int32x32To64(dosTime, 10000000) + 116444736000000000;
    utcFT.dwLowDateTime = (DWORD)jan1970;
    utcFT.dwHighDateTime = jan1970 >> 32;

    FileTimeToSystemTime((FILETIME*)&utcFT, systemTime);
}

char* ctime_r(const time_t *t, char *buf)
{
    SYSTEMTIME systime;
    const char * const dayOfWeek[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    const char * const monthOfYear[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    Time_tToSystemTime(*t, &systime);
    /* We don't know how long `buf` is, but assume it's rounded up from the minimum of 25 to 32 */
    StringCchPrintfA(buf, 31, "%s %s %d %02d:%02d:%02d %04d\n", dayOfWeek[systime.wDayOfWeek % 7], monthOfYear[(systime.wMonth - 1) % 12],
										 systime.wDay, systime.wHour, systime.wMinute, systime.wSecond, systime.wYear);
    return buf;
}

int gettimeofday(struct timeval *restrict tp, void *restrict tzp)
{
	FILETIME fileTime;
	uint64_t unix_time, windows_time;
	const uint64_t MILLISECONDS_BETWEEN_1601_AND_1970 = 11644473600000;

	/* Ignore the timezone parameter */
	(void)tzp;

	/*
	 * Windows time is stored as the number 100 ns intervals since January 1 1601.
	 * Conversion details from http://www.informit.com/articles/article.aspx?p=102236&seqNum=3
	 * Its precision is 100 ns but accuracy is only one clock tick, or normally around 15 ms.
	 */
	GetSystemTimeAsFileTime(&fileTime);
	windows_time = ((uint64_t)fileTime.dwHighDateTime << 32) + fileTime.dwLowDateTime;
	/* Divide by 10,000 to convert to ms and subtract the time between 1601 and 1970 */
	unix_time = (((windows_time)/10000) - MILLISECONDS_BETWEEN_1601_AND_1970);
	/* unix_time is now the number of milliseconds since 1970 (the Unix epoch) */
	tp->tv_sec = unix_time / 1000;
	tp->tv_usec = (unix_time % 1000) * 1000;
	return 0;
}

int sigaction(int sig, const struct sigaction *act,
		struct sigaction *oact)
{
	int rc = 0;
	void (*prev_handler)(int);

	prev_handler = signal(sig, act->sa_handler);
	if (oact != NULL)
		oact->sa_handler = prev_handler;

	if (prev_handler == SIG_ERR)
		rc = -1;

	return rc;
}

int lstat(const char * path, struct stat * buf)
{
	return stat(path, buf);
}

void *mmap(void *addr, size_t len, int prot, int flags,
		int fildes, off_t off)
{
	DWORD vaProt = 0;
	DWORD mapAccess = 0;
	DWORD lenlow;
	DWORD lenhigh;
	HANDLE hMap;
	void* allocAddr = NULL;

	if (prot & PROT_NONE)
		vaProt |= PAGE_NOACCESS;

	if ((prot & PROT_READ) && !(prot & PROT_WRITE)) {
		vaProt |= PAGE_READONLY;
		mapAccess = FILE_MAP_READ;
	}

	if (prot & PROT_WRITE) {
		vaProt |= PAGE_READWRITE;
		mapAccess |= FILE_MAP_WRITE;
	}

	lenlow = len & 0xFFFF;
	lenhigh = len >> 16;
	/* If the low DWORD is zero and the high DWORD is non-zero, `CreateFileMapping`
	   will return ERROR_INVALID_PARAMETER. To avoid this, set both to zero. */
	if (lenlow == 0) {
		lenhigh = 0;
	}

	if (flags & MAP_ANON || flags & MAP_ANONYMOUS)
	{
		allocAddr = VirtualAlloc(addr, len, MEM_COMMIT, vaProt);
		if (allocAddr == NULL)
			errno = win_to_posix_error(GetLastError());
	}
	else
	{
		hMap = CreateFileMapping((HANDLE)_get_osfhandle(fildes), NULL, vaProt, lenhigh, lenlow, NULL);

		if (hMap != NULL)
		{
			allocAddr = MapViewOfFile(hMap, mapAccess, off >> 16, off & 0xFFFF, len);
		}

		if (hMap == NULL || allocAddr == NULL)
			errno = win_to_posix_error(GetLastError());

	}

	return allocAddr;
}

int munmap(void *addr, size_t len)
{
	BOOL success;

	/* We may have allocated the memory with either MapViewOfFile or
		 VirtualAlloc. Therefore, try calling UnmapViewOfFile first, and if that
		 fails, call VirtualFree. */
	success = UnmapViewOfFile(addr);

	if (!success)
	{
		success = VirtualFree(addr, 0, MEM_RELEASE);
	}

	return !success;
}

int msync(void *addr, size_t len, int flags)
{
	return !FlushViewOfFile(addr, len);
}

int fork(void)
{
	log_err("%s is not implemented\n", __func__);
	errno = ENOSYS;
	return -1;
}

pid_t setsid(void)
{
	log_err("%s is not implemented\n", __func__);
	errno = ENOSYS;
	return -1;
}

static HANDLE log_file = INVALID_HANDLE_VALUE;

void openlog(const char *ident, int logopt, int facility)
{
	if (log_file == INVALID_HANDLE_VALUE)
		log_file = CreateFileA("syslog.txt", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, 0, NULL);
}

void closelog(void)
{
	CloseHandle(log_file);
	log_file = INVALID_HANDLE_VALUE;
}

void syslog(int priority, const char *message, ... /* argument */)
{
	va_list v;
	int len;
	char *output;
	DWORD bytes_written;

	if (log_file == INVALID_HANDLE_VALUE) {
		log_file = CreateFileA("syslog.txt", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, 0, NULL);
	}

	if (log_file == INVALID_HANDLE_VALUE) {
		log_err("syslog: failed to open log file\n");
		return;
	}

	va_start(v, message);
	len = _vscprintf(message, v);
	output = malloc(len + sizeof(char));
	vsprintf(output, message, v);
	WriteFile(log_file, output, len, &bytes_written, NULL);
	va_end(v);
	free(output);
}

int kill(pid_t pid, int sig)
{
	errno = ESRCH;
	return -1;
}

/*
 * This is assumed to be used only by the network code,
 * and so doesn't try and handle any of the other cases
 */
int fcntl(int fildes, int cmd, ...)
{
	/*
	 * non-blocking mode doesn't work the same as in BSD sockets,
	 * so ignore it.
	 */
#if 0
	va_list ap;
	int val, opt, status;

	if (cmd == F_GETFL)
		return 0;
	else if (cmd != F_SETFL) {
		errno = EINVAL;
		return -1;
	}

	va_start(ap, 1);

	opt = va_arg(ap, int);
	if (opt & O_NONBLOCK)
		val = 1;
	else
		val = 0;

	status = ioctlsocket((SOCKET)fildes, opt, &val);

	if (status == SOCKET_ERROR) {
		errno = EINVAL;
		val = -1;
	}

	va_end(ap);

	return val;
#endif
return 0;
}

/*
 * Get the value of a local clock source.
 * This implementation supports 2 clocks: CLOCK_MONOTONIC provides high-accuracy
 * relative time, while CLOCK_REALTIME provides a low-accuracy wall time.
 */
int clock_gettime(clockid_t clock_id, struct timespec *tp)
{
	int rc = 0;

	if (clock_id == CLOCK_MONOTONIC)
	{
		static LARGE_INTEGER freq = {{0,0}};
		LARGE_INTEGER counts;
		uint64_t t;

		QueryPerformanceCounter(&counts);
		if (freq.QuadPart == 0)
			QueryPerformanceFrequency(&freq);

		tp->tv_sec = counts.QuadPart / freq.QuadPart;
		/* Get the difference between the number of ns stored
		 * in 'tv_sec' and that stored in 'counts' */
		t = tp->tv_sec * freq.QuadPart;
		t = counts.QuadPart - t;
		/* 't' now contains the number of cycles since the last second.
		 * We want the number of nanoseconds, so multiply out by 1,000,000,000
		 * and then divide by the frequency. */
		t *= 1000000000;
		tp->tv_nsec = t / freq.QuadPart;
	}
	else if (clock_id == CLOCK_REALTIME)
	{
		/* clock_gettime(CLOCK_REALTIME,...) is just an alias for gettimeofday with a
		 * higher-precision field. */
		struct timeval tv;
		gettimeofday(&tv, NULL);
		tp->tv_sec = tv.tv_sec;
		tp->tv_nsec = tv.tv_usec * 1000;
	} else {
		errno = EINVAL;
		rc = -1;
	}

	return rc;
}

int mlock(const void * addr, size_t len)
{
	SIZE_T min, max;
	BOOL success;
	HANDLE process = GetCurrentProcess();

	success = GetProcessWorkingSetSize(process, &min, &max);
	if (!success) {
		errno = win_to_posix_error(GetLastError());
		return -1;
	}

	min += len;
	max += len;
	success = SetProcessWorkingSetSize(process, min, max);
	if (!success) {
		errno = win_to_posix_error(GetLastError());
		return -1;
	}

	success = VirtualLock((LPVOID)addr, len);
	if (!success) {
		errno = win_to_posix_error(GetLastError());
		return -1;
	}

	return 0;
}

int munlock(const void * addr, size_t len)
{
	BOOL success = VirtualUnlock((LPVOID)addr, len);
	if (!success) {
		errno = win_to_posix_error(GetLastError());
		return -1;
	}

	return 0;
}

pid_t waitpid(pid_t pid, int *stat_loc, int options)
{
	log_err("%s is not implemented\n", __func__);
	errno = ENOSYS;
	return -1;
}

int usleep(useconds_t useconds)
{
	Sleep(useconds / 1000);
	return 0;
}

char *basename(char *path)
{
	static char name[MAX_PATH];
	int i;

	if (path == NULL || strlen(path) == 0)
		return (char*)".";

	i = strlen(path) - 1;

	while (path[i] != '\\' && path[i] != '/' && i >= 0)
		i--;

	strncpy(name, path + i + 1, MAX_PATH);

	return name;
}

int fsync(int fildes)
{
	HANDLE hFile = (HANDLE)_get_osfhandle(fildes);
	if (!FlushFileBuffers(hFile)) {
		errno = win_to_posix_error(GetLastError());
		return -1;
	}

	return 0;
}

int nFileMappings = 0;
HANDLE fileMappings[1024];

int shmget(key_t key, size_t size, int shmflg)
{
	int mapid = -1;
	uint32_t size_low = size & 0xFFFFFFFF;
	uint32_t size_high = ((uint64_t)size) >> 32;
	HANDLE hMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, (PAGE_EXECUTE_READWRITE | SEC_RESERVE), size_high, size_low, NULL);
	if (hMapping != NULL) {
		fileMappings[nFileMappings] = hMapping;
		mapid = nFileMappings;
		nFileMappings++;
	} else {
		errno = ENOSYS;
	}

	return mapid;
}

void *shmat(int shmid, const void *shmaddr, int shmflg)
{
	void* mapAddr;
	MEMORY_BASIC_INFORMATION memInfo;
	mapAddr = MapViewOfFile(fileMappings[shmid], FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (mapAddr == NULL) {
		errno = win_to_posix_error(GetLastError());
		return (void*)-1;
	}

	if (VirtualQuery(mapAddr, &memInfo, sizeof(memInfo)) == 0) {
		errno = win_to_posix_error(GetLastError());
		return (void*)-1;
	}

	mapAddr = VirtualAlloc(mapAddr, memInfo.RegionSize, MEM_COMMIT, PAGE_READWRITE);
	if (mapAddr == NULL) {
		errno = win_to_posix_error(GetLastError());
		return (void*)-1;
	}

	return mapAddr;
}

int shmdt(const void *shmaddr)
{
	if (!UnmapViewOfFile(shmaddr)) {
		errno = win_to_posix_error(GetLastError());
		return -1;
	}

	return 0;
}

int shmctl(int shmid, int cmd, struct shmid_ds *buf)
{
	if (cmd == IPC_RMID) {
		fileMappings[shmid] = INVALID_HANDLE_VALUE;
		return 0;
	} else {
		log_err("%s is not implemented\n", __func__);
	}
	errno = ENOSYS;
	return -1;
}

int setuid(uid_t uid)
{
	log_err("%s is not implemented\n", __func__);
	errno = ENOSYS;
	return -1;
}

int setgid(gid_t gid)
{
	log_err("%s is not implemented\n", __func__);
	errno = ENOSYS;
	return -1;
}

int nice(int incr)
{
	DWORD prioclass = NORMAL_PRIORITY_CLASS;
	
	if (incr < -15)
		prioclass = HIGH_PRIORITY_CLASS;
	else if (incr < 0)
		prioclass = ABOVE_NORMAL_PRIORITY_CLASS;
	else if (incr > 15)
		prioclass = IDLE_PRIORITY_CLASS;
	else if (incr > 0)
		prioclass = BELOW_NORMAL_PRIORITY_CLASS;
	
	if (!SetPriorityClass(GetCurrentProcess(), prioclass))
		log_err("fio: SetPriorityClass failed\n");

	return 0;
}

int getrusage(int who, struct rusage *r_usage)
{
	const uint64_t SECONDS_BETWEEN_1601_AND_1970 = 11644473600;
	FILETIME cTime, eTime, kTime, uTime;
	time_t time;
	HANDLE h;

	memset(r_usage, 0, sizeof(*r_usage));

	if (who == RUSAGE_SELF) {
		h = GetCurrentProcess();
		GetProcessTimes(h, &cTime, &eTime, &kTime, &uTime);
	} else if (who == RUSAGE_THREAD) {
		h = GetCurrentThread();
		GetThreadTimes(h, &cTime, &eTime, &kTime, &uTime);
	} else {
		log_err("fio: getrusage %d is not implemented\n", who);
		return -1;
	}

	time = ((uint64_t)uTime.dwHighDateTime << 32) + uTime.dwLowDateTime;
	/* Divide by 10,000,000 to get the number of seconds and move the epoch from
	 * 1601 to 1970 */
	time = (time_t)(((time)/10000000) - SECONDS_BETWEEN_1601_AND_1970);
	r_usage->ru_utime.tv_sec = time;
	/* getrusage() doesn't care about anything other than seconds, so set tv_usec to 0 */
	r_usage->ru_utime.tv_usec = 0;
	time = ((uint64_t)kTime.dwHighDateTime << 32) + kTime.dwLowDateTime;
	/* Divide by 10,000,000 to get the number of seconds and move the epoch from
	 * 1601 to 1970 */
	time = (time_t)(((time)/10000000) - SECONDS_BETWEEN_1601_AND_1970);
	r_usage->ru_stime.tv_sec = time;
	r_usage->ru_stime.tv_usec = 0;
	return 0;
}

int posix_madvise(void *addr, size_t len, int advice)
{
	return ENOSYS;
}

int fdatasync(int fildes)
{
	return fsync(fildes);
}

ssize_t pwrite(int fildes, const void *buf, size_t nbyte,
		off_t offset)
{
	int64_t pos = _telli64(fildes);
	ssize_t len = _write(fildes, buf, nbyte);
	_lseeki64(fildes, pos, SEEK_SET);
	return len;
}

ssize_t pread(int fildes, void *buf, size_t nbyte, off_t offset)
{
	int64_t pos = _telli64(fildes);
	ssize_t len = read(fildes, buf, nbyte);
	_lseeki64(fildes, pos, SEEK_SET);
	return len;
}

ssize_t readv(int fildes, const struct iovec *iov, int iovcnt)
{
	log_err("%s is not implemented\n", __func__);
	errno = ENOSYS;
	return -1;
}

ssize_t writev(int fildes, const struct iovec *iov, int iovcnt)
{
	int i;
	DWORD bytes_written = 0;
	for (i = 0; i < iovcnt; i++)
	{
		int len = send((SOCKET)fildes, iov[i].iov_base, iov[i].iov_len, 0);
		if (len == SOCKET_ERROR)
		{
			DWORD err = GetLastError();
			errno = win_to_posix_error(err);
			bytes_written = -1;
			break;
		}
		bytes_written += len;
	}

	return bytes_written;
}

long long strtoll(const char *restrict str, char **restrict endptr,
		int base)
{
	return _strtoi64(str, endptr, base);
}

int poll(struct pollfd fds[], nfds_t nfds, int timeout)
{
	struct timeval tv;
	struct timeval *to = NULL;
	fd_set readfds, writefds, exceptfds;
	int i;
	int rc;

	if (timeout != -1) {
		to = &tv;
		to->tv_sec = timeout / 1000;
		to->tv_usec = (timeout % 1000) * 1000;
	}

	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	FD_ZERO(&exceptfds);

	for (i = 0; i < nfds; i++)
	{
		if (fds[i].fd < 0) {
			fds[i].revents = 0;
			continue;
		}

		if (fds[i].events & POLLIN)
			FD_SET(fds[i].fd, &readfds);

		if (fds[i].events & POLLOUT)
			FD_SET(fds[i].fd, &writefds);

		FD_SET(fds[i].fd, &exceptfds);
	}
	rc = select(nfds, &readfds, &writefds, &exceptfds, to);

	if (rc != SOCKET_ERROR) {
		for (i = 0; i < nfds; i++)
		{
			if (fds[i].fd < 0) {
				continue;
			}

			if ((fds[i].events & POLLIN) && FD_ISSET(fds[i].fd, &readfds))
				fds[i].revents |= POLLIN;

			if ((fds[i].events & POLLOUT) && FD_ISSET(fds[i].fd, &writefds))
				fds[i].revents |= POLLOUT;

			if (FD_ISSET(fds[i].fd, &exceptfds))
				fds[i].revents |= POLLHUP;
		}
	}
	return rc;
}

int nanosleep(const struct timespec *rqtp, struct timespec *rmtp)
{
	struct timeval tv;
	DWORD ms_remaining;
	DWORD ms_total = (rqtp->tv_sec * 1000) + (rqtp->tv_nsec / 1000000.0);

	if (ms_total == 0)
		ms_total = 1;

	ms_remaining = ms_total;

	/* Since Sleep() can sleep for less than the requested time, add a loop to
	   ensure we only return after the requested length of time has elapsed */
	do {
		fio_gettime(&tv, NULL);
		Sleep(ms_remaining);
		ms_remaining = ms_total - mtime_since_now(&tv);
	} while (ms_remaining > 0 && ms_remaining < ms_total);

	/* this implementation will never sleep for less than the requested time */
	if (rmtp != NULL) {
		rmtp->tv_sec = 0;
		rmtp->tv_nsec = 0;
	}

	return 0;
}

DIR *opendir(const char *dirname)
{
	struct dirent_ctx *dc = NULL;

	/* See if we can open it. If not, we'll return an error here */
	HANDLE file = CreateFileA(dirname, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (file != INVALID_HANDLE_VALUE) {
		CloseHandle(file);
		dc = (struct dirent_ctx*)malloc(sizeof(struct dirent_ctx));
		StringCchCopyA(dc->dirname, MAX_PATH, dirname);
		dc->find_handle = INVALID_HANDLE_VALUE;
	} else {
		DWORD error = GetLastError();
		if (error == ERROR_FILE_NOT_FOUND)
			errno = ENOENT;

		else if (error == ERROR_PATH_NOT_FOUND)
			errno = ENOTDIR;
		else if (error == ERROR_TOO_MANY_OPEN_FILES)
			errno = ENFILE;
		else if (error == ERROR_ACCESS_DENIED)
			errno = EACCES;
		else
			errno = error;
	}

	return dc;
}

int closedir(DIR *dirp)
{
	if (dirp != NULL && dirp->find_handle != INVALID_HANDLE_VALUE)
		FindClose(dirp->find_handle);

	free(dirp);
	return 0;
}

struct dirent *readdir(DIR *dirp)
{
	static struct dirent de;
	WIN32_FIND_DATA find_data;

	if (dirp == NULL)
		return NULL;

	if (dirp->find_handle == INVALID_HANDLE_VALUE) {
		char search_pattern[MAX_PATH];
		StringCchPrintfA(search_pattern, MAX_PATH-1, "%s\\*", dirp->dirname);
		dirp->find_handle = FindFirstFileA(search_pattern, &find_data);
		if (dirp->find_handle == INVALID_HANDLE_VALUE)
			return NULL;
	} else {
		if (!FindNextFile(dirp->find_handle, &find_data))
			return NULL;
	}

	StringCchCopyA(de.d_name, MAX_PATH, find_data.cFileName);
	de.d_ino = 0;

	return &de;
}

uid_t geteuid(void)
{
	log_err("%s is not implemented\n", __func__);
	errno = ENOSYS;
	return -1;
}

in_addr_t inet_network(const char *cp)
{
	in_addr_t hbo;
	in_addr_t nbo = inet_addr(cp);
	hbo = ((nbo & 0xFF) << 24) + ((nbo & 0xFF00) << 8) + ((nbo & 0xFF0000) >> 8) + ((nbo & 0xFF000000) >> 24);
	return hbo;
}

const char* inet_ntop(int af, const void *restrict src,
		char *restrict dst, socklen_t size)
{
	INT status = SOCKET_ERROR;
	WSADATA wsd;
	char *ret = NULL;

	if (af != AF_INET && af != AF_INET6) {
		errno = EAFNOSUPPORT;
		return NULL;
	}

	WSAStartup(MAKEWORD(2,2), &wsd);

	if (af == AF_INET) {
		struct sockaddr_in si;
		DWORD len = size;
		memset(&si, 0, sizeof(si));
		si.sin_family = af;
		memcpy(&si.sin_addr, src, sizeof(si.sin_addr));
		status = WSAAddressToString((struct sockaddr*)&si, sizeof(si), NULL, dst, &len);
	} else if (af == AF_INET6) {
		struct sockaddr_in6 si6;
		DWORD len = size;
		memset(&si6, 0, sizeof(si6));
		si6.sin6_family = af;
		memcpy(&si6.sin6_addr, src, sizeof(si6.sin6_addr));
		status = WSAAddressToString((struct sockaddr*)&si6, sizeof(si6), NULL, dst, &len);
	}

	if (status != SOCKET_ERROR)
		ret = dst;
	else
		errno = ENOSPC;

	WSACleanup();

	return ret;
}

int inet_pton(int af, const char *restrict src, void *restrict dst)
{
	INT status = SOCKET_ERROR;
	WSADATA wsd;
	int ret = 1;

	if (af != AF_INET && af != AF_INET6) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	WSAStartup(MAKEWORD(2,2), &wsd);

	if (af == AF_INET) {
		struct sockaddr_in si;
		INT len = sizeof(si);
		memset(&si, 0, sizeof(si));
		si.sin_family = af;
		status = WSAStringToAddressA((char*)src, af, NULL, (struct sockaddr*)&si, &len);
		if (status != SOCKET_ERROR)
			memcpy(dst, &si.sin_addr, sizeof(si.sin_addr));
	} else if (af == AF_INET6) {
		struct sockaddr_in6 si6;
		INT len = sizeof(si6);
		memset(&si6, 0, sizeof(si6));
		si6.sin6_family = af;
		status = WSAStringToAddressA((char*)src, af, NULL, (struct sockaddr*)&si6, &len);
		if (status != SOCKET_ERROR)
			memcpy(dst, &si6.sin6_addr, sizeof(si6.sin6_addr));
	}

	if (status == SOCKET_ERROR) {
		errno = ENOSPC;
		ret = 0;
	}

	WSACleanup();

	return ret;
}
