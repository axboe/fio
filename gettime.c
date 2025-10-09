/*
 * Clock functions
 */

#include <math.h>

#include "fio.h"
#include "os/os.h"

#if defined(ARCH_HAVE_CPU_CLOCK)
#ifndef ARCH_CPU_CLOCK_CYCLES_PER_USEC
static unsigned long long cycles_per_msec;
static unsigned long long cycles_start;
static unsigned long long clock_mult;
static unsigned long long max_cycles_mask;
static unsigned long long nsecs_for_max_cycles;
static unsigned int clock_shift;
static unsigned int max_cycles_shift;
#define MAX_CLOCK_SEC 60*60
#endif
#ifdef ARCH_CPU_CLOCK_WRAPS
static unsigned int cycles_wrap;
#endif
#endif
bool tsc_reliable = false;

struct tv_valid {
	int warned;
};
#ifdef ARCH_HAVE_CPU_CLOCK
#ifdef CONFIG_TLS_THREAD
static __thread struct tv_valid static_tv_valid;
#else
static pthread_key_t tv_tls_key;
#endif
#endif

enum fio_cs fio_clock_source = FIO_PREFERRED_CLOCK_SOURCE;
int fio_clock_source_set = 0;
static enum fio_cs fio_clock_source_inited = CS_INVAL;

#ifdef FIO_DEBUG_TIME

#define HASH_BITS	8
#define HASH_SIZE	(1 << HASH_BITS)

static struct flist_head hash[HASH_SIZE];
static int gtod_inited;

struct gtod_log {
	struct flist_head list;
	void *caller;
	unsigned long calls;
};

static struct gtod_log *find_hash(void *caller)
{
	unsigned long h = hash_ptr(caller, HASH_BITS);
	struct flist_head *entry;

	flist_for_each(entry, &hash[h]) {
		struct gtod_log *log = flist_entry(entry, struct gtod_log,
									list);

		if (log->caller == caller)
			return log;
	}

	return NULL;
}

static void inc_caller(void *caller)
{
	struct gtod_log *log = find_hash(caller);

	if (!log) {
		unsigned long h;

		log = malloc(sizeof(*log));
		INIT_FLIST_HEAD(&log->list);
		log->caller = caller;
		log->calls = 0;

		h = hash_ptr(caller, HASH_BITS);
		flist_add_tail(&log->list, &hash[h]);
	}

	log->calls++;
}

static void gtod_log_caller(void *caller)
{
	if (gtod_inited)
		inc_caller(caller);
}

static void fio_exit fio_dump_gtod(void)
{
	unsigned long total_calls = 0;
	int i;

	for (i = 0; i < HASH_SIZE; i++) {
		struct flist_head *entry;
		struct gtod_log *log;

		flist_for_each(entry, &hash[i]) {
			log = flist_entry(entry, struct gtod_log, list);

			printf("function %p, calls %lu\n", log->caller,
								log->calls);
			total_calls += log->calls;
		}
	}

	printf("Total %lu gettimeofday\n", total_calls);
}

static void fio_init gtod_init(void)
{
	int i;

	for (i = 0; i < HASH_SIZE; i++)
		INIT_FLIST_HEAD(&hash[i]);

	gtod_inited = 1;
}

#endif /* FIO_DEBUG_TIME */

/*
 * Queries the value of the monotonic clock if a monotonic clock is available
 * or the wall clock time if no monotonic clock is available. Returns 0 if
 * querying the clock succeeded or -1 if querying the clock failed.
 */
int fio_get_mono_time(struct timespec *ts)
{
	int ret;

#if defined(CONFIG_CLOCK_MONOTONIC)
	ret = clock_gettime(CLOCK_MONOTONIC, ts);
#else
	ret = clock_gettime(CLOCK_REALTIME, ts);
#endif
	assert(ret <= 0);
	return ret;
}

static void __fio_gettime(struct timespec *tp)
{
	switch (fio_clock_source) {
#ifdef CONFIG_GETTIMEOFDAY
	case CS_GTOD: {
		struct timeval tv;
		gettimeofday(&tv, NULL);

		tp->tv_sec = tv.tv_sec;
		tp->tv_nsec = tv.tv_usec * 1000;
		break;
		}
#endif
	case CS_CGETTIME: {
		if (fio_get_mono_time(tp) < 0) {
			log_err("fio: fio_get_mono_time() fails\n");
			assert(0);
		}
		break;
		}
#ifdef ARCH_HAVE_CPU_CLOCK
	case CS_CPUCLOCK: {
		uint64_t nsecs, t, multiples;
		struct tv_valid *tv;

#ifdef CONFIG_TLS_THREAD
		tv = &static_tv_valid;
#else
		tv = pthread_getspecific(tv_tls_key);
#endif

		t = get_cpu_clock();
#ifdef ARCH_CPU_CLOCK_WRAPS
		if (t < cycles_start && !cycles_wrap)
			cycles_wrap = 1;
		else if (cycles_wrap && t >= cycles_start && !tv->warned) {
			log_err("fio: double CPU clock wrap\n");
			tv->warned = 1;
		}
#endif
#ifdef ARCH_CPU_CLOCK_CYCLES_PER_USEC
		nsecs = t / ARCH_CPU_CLOCK_CYCLES_PER_USEC * 1000;
#else
		t -= cycles_start;
		multiples = t >> max_cycles_shift;
		nsecs = multiples * nsecs_for_max_cycles;
		nsecs += ((t & max_cycles_mask) * clock_mult) >> clock_shift;
#endif
		tp->tv_sec = nsecs / 1000000000ULL;
		tp->tv_nsec = nsecs % 1000000000ULL;
		break;
		}
#endif
	default:
		log_err("fio: invalid clock source %d\n", fio_clock_source);
		break;
	}
}

#ifdef FIO_DEBUG_TIME
void fio_gettime(struct timespec *tp, void *caller)
#else
void fio_gettime(struct timespec *tp, void fio_unused *caller)
#endif
{
#ifdef FIO_DEBUG_TIME
	if (!caller)
		caller = __builtin_return_address(0);

	gtod_log_caller(caller);
#endif
	if (fio_unlikely(fio_gettime_offload(tp)))
		return;

	__fio_gettime(tp);
}

#if defined(ARCH_HAVE_CPU_CLOCK) && !defined(ARCH_CPU_CLOCK_CYCLES_PER_USEC)
static unsigned long get_cycles_per_msec(void)
{
	struct timespec s, e;
	uint64_t c_s, c_e;
	uint64_t elapsed;

	fio_get_mono_time(&s);

	c_s = get_cpu_clock();
	do {
		fio_get_mono_time(&e);
		c_e = get_cpu_clock();

		elapsed = ntime_since(&s, &e);
		if (elapsed >= 1280000)
			break;
	} while (1);

	return (c_e - c_s) * 1000000 / elapsed;
}

#define NR_TIME_ITERS	50

static int calibrate_cpu_clock(void)
{
	double delta, mean, S;
	uint64_t minc, maxc, avg, cycles[NR_TIME_ITERS];
	int i, samples, sft = 0;
	unsigned long long tmp, max_ticks, max_mult;

	cycles[0] = get_cycles_per_msec();
	S = delta = mean = 0.0;
	for (i = 0; i < NR_TIME_ITERS; i++) {
		cycles[i] = get_cycles_per_msec();
		delta = cycles[i] - mean;
		if (delta) {
			mean += delta / (i + 1.0);
			S += delta * (cycles[i] - mean);
		}
	}

	/*
	 * The most common platform clock breakage is returning zero
	 * indefinitely. Check for that and return failure.
	 */
	if (!cycles[0] && !cycles[NR_TIME_ITERS - 1])
		return 1;

	S = sqrt(S / (NR_TIME_ITERS - 1.0));

	minc = -1ULL;
	maxc = samples = avg = 0;
	for (i = 0; i < NR_TIME_ITERS; i++) {
		double this = cycles[i];

		minc = min(cycles[i], minc);
		maxc = max(cycles[i], maxc);

		if ((fmax(this, mean) - fmin(this, mean)) > S)
			continue;
		samples++;
		avg += this;
	}

	S /= (double) NR_TIME_ITERS;

	for (i = 0; i < NR_TIME_ITERS; i++)
		dprint(FD_TIME, "cycles[%d]=%llu\n", i, (unsigned long long) cycles[i]);

	avg /= samples;
	cycles_per_msec = avg;
	dprint(FD_TIME, "min=%llu, max=%llu, mean=%f, S=%f, N=%d\n",
			(unsigned long long) minc,
			(unsigned long long) maxc, mean, S, NR_TIME_ITERS);
	dprint(FD_TIME, "trimmed mean=%llu, N=%d\n", (unsigned long long) avg, samples);

	max_ticks = MAX_CLOCK_SEC * cycles_per_msec * 1000ULL;
	max_mult = ULLONG_MAX / max_ticks;
	dprint(FD_TIME, "max_ticks=%llu, __builtin_clzll=%d, "
			"max_mult=%llu\n", max_ticks,
			__builtin_clzll(max_ticks), max_mult);

        /*
         * Find the largest shift count that will produce
         * a multiplier that does not exceed max_mult
         */
        tmp = max_mult * cycles_per_msec / 1000000;
        while (tmp > 1) {
                tmp >>= 1;
                sft++;
                dprint(FD_TIME, "tmp=%llu, sft=%u\n", tmp, sft);
        }

	clock_shift = sft;
	clock_mult = (1ULL << sft) * 1000000 / cycles_per_msec;
	dprint(FD_TIME, "clock_shift=%u, clock_mult=%llu\n", clock_shift,
							clock_mult);

	/*
	 * Find the greatest power of 2 clock ticks that is less than the
	 * ticks in MAX_CLOCK_SEC
	 */
	max_cycles_shift = max_cycles_mask = 0;
	tmp = MAX_CLOCK_SEC * 1000ULL * cycles_per_msec;
	dprint(FD_TIME, "tmp=%llu, max_cycles_shift=%u\n", tmp,
							max_cycles_shift);
	while (tmp > 1) {
		tmp >>= 1;
		max_cycles_shift++;
		dprint(FD_TIME, "tmp=%llu, max_cycles_shift=%u\n", tmp, max_cycles_shift);
	}
	/*
	 * if use use (1ULL << max_cycles_shift) * 1000 / cycles_per_msec
	 * here we will have a discontinuity every
	 * (1ULL << max_cycles_shift) cycles
	 */
	nsecs_for_max_cycles = ((1ULL << max_cycles_shift) * clock_mult)
					>> clock_shift;

	/* Use a bitmask to calculate ticks % (1ULL << max_cycles_shift) */
	for (tmp = 0; tmp < max_cycles_shift; tmp++)
		max_cycles_mask |= 1ULL << tmp;

	dprint(FD_TIME, "max_cycles_shift=%u, 2^max_cycles_shift=%llu, "
			"nsecs_for_max_cycles=%llu, "
			"max_cycles_mask=%016llx\n",
			max_cycles_shift, (1ULL << max_cycles_shift),
			nsecs_for_max_cycles, max_cycles_mask);

	cycles_start = get_cpu_clock();
	dprint(FD_TIME, "cycles_start=%llu\n", cycles_start);
	return 0;
}
#else
static int calibrate_cpu_clock(void)
{
#ifdef ARCH_CPU_CLOCK_CYCLES_PER_USEC
	return 0;
#else
	return 1;
#endif
}
#endif // ARCH_HAVE_CPU_CLOCK

#if defined(ARCH_HAVE_CPU_CLOCK) && !defined(CONFIG_TLS_THREAD)
void fio_local_clock_init(void)
{
	struct tv_valid *t;

	t = calloc(1, sizeof(*t));
	if (pthread_setspecific(tv_tls_key, t)) {
		log_err("fio: can't set TLS key\n");
		assert(0);
	}
}

static void kill_tv_tls_key(void *data)
{
	free(data);
}
#else
void fio_local_clock_init(void)
{
}
#endif

void fio_clock_init(void)
{
	if (fio_clock_source == fio_clock_source_inited)
		return;

#if defined(ARCH_HAVE_CPU_CLOCK) && !defined(CONFIG_TLS_THREAD)
	if (pthread_key_create(&tv_tls_key, kill_tv_tls_key))
		log_err("fio: can't create TLS key\n");
#endif

	fio_clock_source_inited = fio_clock_source;

	if (calibrate_cpu_clock())
		tsc_reliable = false;

	/*
	 * If the arch sets tsc_reliable != 0, then it must be good enough
	 * to use as THE clock source. For x86 CPUs, this means the TSC
	 * runs at a constant rate and is synced across CPU cores.
	 */
	if (tsc_reliable) {
		if (!fio_clock_source_set && !fio_monotonic_clocktest(0))
			fio_clock_source = CS_CPUCLOCK;
	} else if (fio_clock_source == CS_CPUCLOCK)
		log_info("fio: clocksource=cpu may not be reliable\n");
	dprint(FD_TIME, "gettime: clocksource=%d\n", (int) fio_clock_source);
}

uint64_t ntime_since(const struct timespec *s, const struct timespec *e)
{
	int64_t sec, nsec;

	sec = e->tv_sec - s->tv_sec;
	nsec = e->tv_nsec - s->tv_nsec;
	if (sec > 0 && nsec < 0) {
		sec--;
		nsec += 1000000000LL;
	}

       /*
	* time warp bug on some kernels?
	*/
	if (sec < 0 || (sec == 0 && nsec < 0))
		return 0;

	return nsec + (sec * 1000000000LL);
}

uint64_t ntime_since_now(const struct timespec *s)
{
	struct timespec now;

	fio_gettime(&now, NULL);
	return ntime_since(s, &now);
}

uint64_t utime_since(const struct timespec *s, const struct timespec *e)
{
	int64_t sec, usec;

	sec = e->tv_sec - s->tv_sec;
	usec = (e->tv_nsec - s->tv_nsec) / 1000;
	if (sec > 0 && usec < 0) {
		sec--;
		usec += 1000000;
	}

	/*
	 * time warp bug on some kernels?
	 */
	if (sec < 0 || (sec == 0 && usec < 0))
		return 0;

	return usec + (sec * 1000000);
}

uint64_t utime_since_now(const struct timespec *s)
{
	struct timespec t;
#ifdef FIO_DEBUG_TIME
	void *p = __builtin_return_address(0);

	fio_gettime(&t, p);
#else
	fio_gettime(&t, NULL);
#endif

	return utime_since(s, &t);
}

uint64_t mtime_since_tv(const struct timeval *s, const struct timeval *e)
{
	int64_t sec, usec;

	sec = e->tv_sec - s->tv_sec;
	usec = (e->tv_usec - s->tv_usec);
	if (sec > 0 && usec < 0) {
		sec--;
		usec += 1000000;
	}

	if (sec < 0 || (sec == 0 && usec < 0))
		return 0;

	sec *= 1000;
	usec /= 1000;
	return sec + usec;
}

uint64_t mtime_since_now(const struct timespec *s)
{
	struct timespec t;
#ifdef FIO_DEBUG_TIME
	void *p = __builtin_return_address(0);

	fio_gettime(&t, p);
#else
	fio_gettime(&t, NULL);
#endif

	return mtime_since(s, &t);
}

/*
 * Returns *e - *s in milliseconds as a signed integer. Note: rounding is
 * asymmetric. If the difference yields +1 ns then 0 is returned. If the
 * difference yields -1 ns then -1 is returned.
 */
int64_t rel_time_since(const struct timespec *s, const struct timespec *e)
{
	int64_t sec, nsec;

	sec = e->tv_sec - s->tv_sec;
	nsec = e->tv_nsec - s->tv_nsec;
	if (nsec < 0) {
		sec--;
		nsec += 1000ULL * 1000 * 1000;
	}
	assert(0 <= nsec && nsec < 1000ULL * 1000 * 1000);

	return sec * 1000 + nsec / (1000 * 1000);
}

/*
 * Returns *e - *s in milliseconds as an unsigned integer. Returns 0 if
 * *e < *s.
 */
uint64_t mtime_since(const struct timespec *s, const struct timespec *e)
{
	return max(rel_time_since(s, e), (int64_t)0);
}

uint64_t time_since_now(const struct timespec *s)
{
	return mtime_since_now(s) / 1000;
}

#if defined(FIO_HAVE_CPU_AFFINITY) && defined(ARCH_HAVE_CPU_CLOCK)  && \
    defined(CONFIG_SYNC_SYNC) && defined(CONFIG_CMP_SWAP)

#define CLOCK_ENTRIES_DEBUG	100000
#define CLOCK_ENTRIES_TEST	1000

struct clock_entry {
	uint32_t seq;
	uint32_t cpu;
	uint64_t tsc;
};

struct clock_thread {
	pthread_t thread;
	int cpu;
	int debug;
	struct fio_sem lock;
	unsigned long nr_entries;
	uint32_t *seq;
	struct clock_entry *entries;
};

static inline uint32_t atomic32_compare_and_swap(uint32_t *ptr, uint32_t old,
						 uint32_t new)
{
	return __sync_val_compare_and_swap(ptr, old, new);
}

static void *clock_thread_fn(void *data)
{
	struct clock_thread *t = data;
	struct clock_entry *c;
	os_cpu_mask_t cpu_mask;
	unsigned long long first;
	int i;

	if (fio_cpuset_init(&cpu_mask)) {
		int __err = errno;

		log_err("clock cpuset init failed: %s\n", strerror(__err));
		goto err_out;
	}

	fio_cpu_set(&cpu_mask, t->cpu);

	if (fio_setaffinity(gettid(), cpu_mask) == -1) {
		int __err = errno;

		log_err("clock setaffinity failed: %s\n", strerror(__err));
		goto err;
	}

	fio_sem_down(&t->lock);

	first = get_cpu_clock();
	c = &t->entries[0];
	for (i = 0; i < t->nr_entries; i++, c++) {
		uint32_t seq;
		uint64_t tsc;

		c->cpu = t->cpu;
		do {
			seq = *t->seq;
			if (seq == UINT_MAX)
				break;
			tsc_barrier();
			tsc = get_cpu_clock();
		} while (seq != atomic32_compare_and_swap(t->seq, seq, seq + 1));

		if (seq == UINT_MAX)
			break;

		c->seq = seq;
		c->tsc = tsc;
	}

	if (t->debug) {
		unsigned long long clocks;

		clocks = t->entries[i - 1].tsc - t->entries[0].tsc;
		log_info("cs: cpu%3d: %llu clocks seen, first %llu\n", t->cpu,
							clocks, first);
	}

	/*
	 * The most common platform clock breakage is returning zero
	 * indefinitely. Check for that and return failure.
	 */
	if (i > 1 && !t->entries[i - 1].tsc && !t->entries[0].tsc)
		goto err;

	fio_cpuset_exit(&cpu_mask);
	return NULL;
err:
	fio_cpuset_exit(&cpu_mask);
err_out:
	return (void *) 1;
}

static int clock_cmp(const void *p1, const void *p2)
{
	const struct clock_entry *c1 = p1;
	const struct clock_entry *c2 = p2;

	if (c1->seq == c2->seq)
		log_err("cs: bug in atomic sequence!\n");

	return c1->seq - c2->seq;
}

int fio_monotonic_clocktest(int debug)
{
	struct clock_thread *cthreads;
	unsigned int seen_cpus, nr_cpus = cpus_configured();
	struct clock_entry *entries;
	unsigned long nr_entries, tentries, failed = 0;
	struct clock_entry *prev, *this;
	uint32_t seq = 0;
	unsigned int i;
	os_cpu_mask_t mask;

#ifdef FIO_HAVE_GET_THREAD_AFFINITY
	fio_get_thread_affinity(mask);
#else
	memset(&mask, 0, sizeof(mask));
	for (i = 0; i < nr_cpus; i++)
		fio_cpu_set(&mask, i);
#endif

	if (debug) {
		log_info("cs: reliable_tsc: %s\n", tsc_reliable ? "yes" : "no");

#ifdef FIO_INC_DEBUG
		fio_debug |= 1U << FD_TIME;
#endif
		nr_entries = CLOCK_ENTRIES_DEBUG;
	} else
		nr_entries = CLOCK_ENTRIES_TEST;

	calibrate_cpu_clock();

	if (debug) {
#ifdef FIO_INC_DEBUG
		fio_debug &= ~(1U << FD_TIME);
#endif
	}

	cthreads = malloc(nr_cpus * sizeof(struct clock_thread));
	tentries = nr_entries * nr_cpus;
	entries = malloc(tentries * sizeof(struct clock_entry));

	if (debug)
		log_info("cs: Testing %u CPUs\n", nr_cpus);

	seen_cpus = 0;
	for (i = 0; i < nr_cpus; i++) {
		struct clock_thread *t = &cthreads[i];

		if (!fio_cpu_isset(&mask, i))
			continue;
		t->cpu = i;
		t->debug = debug;
		t->seq = &seq;
		t->nr_entries = nr_entries;
		t->entries = &entries[seen_cpus * nr_entries];
		__fio_sem_init(&t->lock, FIO_SEM_LOCKED);
		if (pthread_create(&t->thread, NULL, clock_thread_fn, t)) {
			failed++;
			nr_cpus = i;
			break;
		}
		seen_cpus++;
	}

	for (i = 0; i < nr_cpus; i++) {
		struct clock_thread *t = &cthreads[i];

		if (!fio_cpu_isset(&mask, i))
			continue;
		fio_sem_up(&t->lock);
	}

	for (i = 0; i < nr_cpus; i++) {
		struct clock_thread *t = &cthreads[i];
		void *ret;

		if (!fio_cpu_isset(&mask, i))
			continue;
		pthread_join(t->thread, &ret);
		if (ret)
			failed++;
		__fio_sem_remove(&t->lock);
	}
	free(cthreads);

	if (failed) {
		if (debug)
			log_err("Clocksource test: %lu threads failed\n", failed);
		goto err;
	}

	tentries = nr_entries * seen_cpus;
	qsort(entries, tentries, sizeof(struct clock_entry), clock_cmp);

	/* silence silly gcc */
	prev = NULL;
	for (failed = i = 0; i < tentries; i++) {
		this = &entries[i];

		if (!i) {
			prev = this;
			continue;
		}

		if (prev->tsc > this->tsc) {
			uint64_t diff = prev->tsc - this->tsc;

			if (!debug) {
				failed++;
				break;
			}

			log_info("cs: CPU clock mismatch (diff=%llu):\n",
						(unsigned long long) diff);
			log_info("\t CPU%3u: TSC=%llu, SEQ=%u\n", prev->cpu, (unsigned long long) prev->tsc, prev->seq);
			log_info("\t CPU%3u: TSC=%llu, SEQ=%u\n", this->cpu, (unsigned long long) this->tsc, this->seq);
			failed++;
		}

		prev = this;
	}

	if (debug) {
		if (failed)
			log_info("cs: Failed: %lu\n", failed);
		else
			log_info("cs: Pass!\n");
	}
err:
	free(entries);
	return !!failed;
}

#else /* defined(FIO_HAVE_CPU_AFFINITY) && defined(ARCH_HAVE_CPU_CLOCK) */

int fio_monotonic_clocktest(int debug)
{
	if (debug)
		log_info("cs: current platform does not support CPU clocks\n");
	return 1;
}

#endif
