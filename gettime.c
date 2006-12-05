/*
 * Clock functions
 */

#include <unistd.h>
#include <sys/time.h>

#include "fio.h"
#include "os.h"

#include "hash.h"

static int clock_gettime_works = 1;

#ifdef FIO_DEBUG_TIME

#define HASH_BITS	8
#define HASH_SIZE	(1 << HASH_BITS)

static struct list_head hash[HASH_SIZE];
static int gtod_inited;

struct gtod_log {
	struct list_head list;
	void *caller;
	unsigned long calls;
};

static struct gtod_log *find_hash(void *caller)
{
	unsigned long h = hash_ptr(caller, HASH_BITS);
	struct list_head *entry;

	list_for_each(entry, &hash[h]) {
		struct gtod_log *log = list_entry(entry, struct gtod_log, list);

		if (log->caller == caller)
			return log;
	}

	return NULL;
}

static struct gtod_log *find_log(void *caller)
{
	struct gtod_log *log = find_hash(caller);

	if (!log) {
		unsigned long h;

		log = malloc(sizeof(*log));
		INIT_LIST_HEAD(&log->list);
		log->caller = caller;
		log->calls = 0;

		h = hash_ptr(caller, HASH_BITS);
		list_add_tail(&log->list, &hash[h]);
	}

	return log;
}

static void gtod_log_caller(void *caller)
{
	if (gtod_inited) {
		struct gtod_log *log = find_log(caller);

		log->calls++;
	}
}

static void fio_exit fio_dump_gtod(void)
{
	unsigned long total_calls = 0;
	int i;

	for (i = 0; i < HASH_SIZE; i++) {
		struct list_head *entry;
		struct gtod_log *log;

		list_for_each(entry, &hash[i]) {
			log = list_entry(entry, struct gtod_log, list);

			printf("function %p, calls %lu\n", log->caller, log->calls);
			total_calls += log->calls;
		}
	}

	printf("Total %lu gettimeofday\n", total_calls);
}

static void fio_init gtod_init(void)
{
	int i;

	for (i = 0; i < HASH_SIZE; i++)
		INIT_LIST_HEAD(&hash[i]);

	gtod_inited = 1;
}

#endif /* FIO_DEBUG_TIME */

#ifdef FIO_DEBUG_TIME
void fio_gettime(struct timeval *tp, void *caller)
#else
void fio_gettime(struct timeval *tp, void fio_unused *caller)
#endif
{
#ifdef FIO_DEBUG_TIME
	if (!caller)
		caller = __builtin_return_address(0);

	gtod_log_caller(caller);
#endif
repeat:
	if (!clock_gettime_works)
		gettimeofday(tp, NULL);
	else {
		struct timespec ts;

		if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
			clock_gettime_works = 0;
			goto repeat;
		}

		tp->tv_sec = ts.tv_sec;
		tp->tv_usec = ts.tv_nsec / 1000;
	}
}

static void fio_init check_clock(void)
{
	struct timespec ts;

	if (clock_getres(CLOCK_MONOTONIC, &ts) < 0)
		clock_gettime_works = 0;
}
