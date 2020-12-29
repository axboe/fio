#include <dlfcn.h>
#include <inttypes.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#if defined(__MACH__)
#include <mach/mach_time.h>
#else
/* For compile testing on Linux */
typedef struct mach_timebase_info {
	uint32_t	numer;
	uint32_t	denom;
} mach_timebase_info_data_t;
typedef struct mach_timebase_info *mach_timebase_info_t;
uint64_t mach_absolute_time(void);
int mach_timebase_info(mach_timebase_info_t info);
#endif

static typeof(clock_gettime) *clock_gettime_fn;
static struct mach_timebase_info mach_timebase;
static uint64_t mach_timestart;

static void init_clock_gettime(void)
{
	void *libc = dlopen("/usr/lib/libc.dylib", RTLD_LAZY);
	if (libc) {
		clock_gettime_fn = dlsym(libc, "clock_gettime");
		if (clock_gettime_fn)
			return;
	}
	mach_timebase_info(&mach_timebase);
	mach_timestart = mach_absolute_time();
}

int clock_gettime(clockid_t clk_id, struct timespec *tp)
{
	static pthread_once_t init = PTHREAD_ONCE_INIT;

	pthread_once(&init, init_clock_gettime);
	if (clock_gettime_fn)
		return clock_gettime_fn(clk_id, tp);
	if (clk_id == CLOCK_REALTIME) {
		struct timeval tv;

		if (gettimeofday(&tv, NULL) < 0)
			return -1;
		tp->tv_sec = tv.tv_sec;
		tp->tv_nsec = tv.tv_usec * 1000;
		return 0;
	}
	uint64_t delta_ns = (mach_absolute_time() - mach_timestart) *
		(__uint128_t)mach_timebase.numer / mach_timebase.denom;
	tp->tv_sec = delta_ns / (uint64_t)1e9;
	tp->tv_nsec = delta_ns - tp->tv_sec * (uint64_t)1e9;
	return 0;
}
