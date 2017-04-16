/*
 * Clock functions
 */

#include <unistd.h>
#include <math.h>
#include <sys/time.h>
#include <time.h>

#include "fio.h"
#include "smalloc.h"

#include "hash.h"
#include "os/os.h"

#if defined(ARCH_HAVE_CPU_CLOCK)
#ifndef ARCH_CPU_CLOCK_CYCLES_PER_USEC
static unsigned long cycles_per_usec;
static unsigned long inv_cycles_per_usec;
static uint64_t max_cycles_for_mult;
#endif
#ifdef ARCH_CPU_CLOCK_WRAPS
static unsigned long long cycles_start, cycles_wrap;
#endif
#endif
int tsc_reliable = 0;

struct tv_valid {
	uint64_t last_cycles;
	int last_tv_valid;
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

#ifdef CONFIG_CLOCK_GETTIME
static int fill_clock_gettime(struct timespec *ts)
{
#if defined(CONFIG_CLOCK_MONOTONIC_RAW)
	return clock_gettime(CLOCK_MONOTONIC_RAW, ts);
#elif defined(CONFIG_CLOCK_MONOTONIC)
	return clock_gettime(CLOCK_MONOTONIC, ts);
#else
	return clock_gettime(CLOCK_REALTIME, ts);
#endif
}
#endif

static void __fio_gettime(struct timeval *tp)
{
	switch (fio_clock_source) {
#ifdef CONFIG_GETTIMEOFDAY
	case CS_GTOD:
		gettimeofday(tp, NULL);
		break;
#endif
#ifdef CONFIG_CLOCK_GETTIME
	case CS_CGETTIME: {
		struct timespec ts;

		if (fill_clock_gettime(&ts) < 0) {
			log_err("fio: clock_gettime fails\n");
			assert(0);
		}

		tp->tv_sec = ts.tv_sec;
		tp->tv_usec = ts.tv_nsec / 1000;
		break;
		}
#endif
#ifdef ARCH_HAVE_CPU_CLOCK
	case CS_CPUCLOCK: {
		uint64_t usecs, t;
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

		t -= cycles_start;
#endif
		tv->last_cycles = t;
		tv->last_tv_valid = 1;
#ifdef ARCH_CPU_CLOCK_CYCLES_PER_USEC
		usecs = t / ARCH_CPU_CLOCK_CYCLES_PER_USEC;
#else
		if (t < max_cycles_for_mult)
			usecs = (t * inv_cycles_per_usec) / 16777216UL;
		else
			usecs = t / cycles_per_usec;
#endif
		tp->tv_sec = usecs / 1000000;
		tp->tv_usec = usecs % 1000000;
		break;
		}
#endif
	default:
		log_err("fio: invalid clock source %d\n", fio_clock_source);
		break;
	}
}

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
	if (fio_unlikely(fio_gettime_offload(tp)))
		return;

	__fio_gettime(tp);
}

#if defined(ARCH_HAVE_CPU_CLOCK) && !defined(ARCH_CPU_CLOCK_CYCLES_PER_USEC)
static unsigned long get_cycles_per_usec(void)
{
	struct timeval s, e;
	uint64_t c_s, c_e;
	enum fio_cs old_cs = fio_clock_source;
	uint64_t elapsed;

#ifdef CONFIG_CLOCK_GETTIME
	fio_clock_source = CS_CGETTIME;
#else
	fio_clock_source = CS_GTOD;
#endif
	__fio_gettime(&s);

	c_s = get_cpu_clock();
	do {
		__fio_gettime(&e);

		elapsed = utime_since(&s, &e);
		if (elapsed >= 1280) {
			c_e = get_cpu_clock();
			break;
		}
	} while (1);

	fio_clock_source = old_cs;
	return (c_e - c_s) / elapsed;
}

#define NR_TIME_ITERS	50

static int calibrate_cpu_clock(void)
{
	double delta, mean, S;
	uint64_t minc, maxc, avg, cycles[NR_TIME_ITERS];
	int i, samples;

	cycles[0] = get_cycles_per_usec();
	S = delta = mean = 0.0;
	for (i = 0; i < NR_TIME_ITERS; i++) {
		cycles[i] = get_cycles_per_usec();
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
	dprint(FD_TIME, "avg: %llu\n", (unsigned long long) avg);
	dprint(FD_TIME, "min=%llu, max=%llu, mean=%f, S=%f\n",
			(unsigned long long) minc,
			(unsigned long long) maxc, mean, S);

	cycles_per_usec = avg;
	inv_cycles_per_usec = 16777216UL / cycles_per_usec;
	max_cycles_for_mult = ~0ULL / inv_cycles_per_usec;
	dprint(FD_TIME, "inv_cycles_per_usec=%lu\n", inv_cycles_per_usec);
#ifdef ARCH_CPU_CLOCK_WRAPS
	cycles_start = get_cpu_clock();
	dprint(FD_TIME, "cycles_start=%llu\n", cycles_start);
#endif
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

#ifndef CONFIG_TLS_THREAD
void fio_local_clock_init(int is_thread)
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
void fio_local_clock_init(int is_thread)
{
}
#endif

void fio_clock_init(void)
{
	if (fio_clock_source == fio_clock_source_inited)
		return;

#ifndef CONFIG_TLS_THREAD
	if (pthread_key_create(&tv_tls_key, kill_tv_tls_key))
		log_err("fio: can't create TLS key\n");
#endif

	fio_clock_source_inited = fio_clock_source;

	if (calibrate_cpu_clock())
		tsc_reliable = 0;

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
}

uint64_t utime_since(const struct timeval *s, const struct timeval *e)
{
	int64_t sec, usec;

	sec = e->tv_sec - s->tv_sec;
	usec = e->tv_usec - s->tv_usec;
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

uint64_t utime_since_now(const struct timeval *s)
{
	struct timeval t;
#ifdef FIO_DEBUG_TIME
	void *p = __builtin_return_address(0);

	fio_gettime(&t, p);
#else
	fio_gettime(&t, NULL);
#endif

	return utime_since(s, &t);
}

uint64_t mtime_since(const struct timeval *s, const struct timeval *e)
{
	long sec, usec;

	sec = e->tv_sec - s->tv_sec;
	usec = e->tv_usec - s->tv_usec;
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

uint64_t mtime_since_now(const struct timeval *s)
{
	struct timeval t;
#ifdef FIO_DEBUG_TIME
	void *p = __builtin_return_address(0);

	fio_gettime(&t, p);
#else
	fio_gettime(&t, NULL);
#endif

	return mtime_since(s, &t);
}

uint64_t time_since_now(const struct timeval *s)
{
	return mtime_since_now(s) / 1000;
}

#if defined(FIO_HAVE_CPU_AFFINITY) && defined(ARCH_HAVE_CPU_CLOCK)  && \
    defined(CONFIG_SFAA)

#define CLOCK_ENTRIES_DEBUG	100000
#define CLOCK_ENTRIES_TEST	10000

struct clock_entry {
	uint32_t seq;
	uint32_t cpu;
	uint64_t tsc;
};

struct clock_thread {
	pthread_t thread;
	int cpu;
	int debug;
	pthread_mutex_t lock;
	pthread_mutex_t started;
	unsigned long nr_entries;
	uint32_t *seq;
	struct clock_entry *entries;
};

static inline uint32_t atomic32_inc_return(uint32_t *seq)
{
	return 1 + __sync_fetch_and_add(seq, 1);
}

static void *clock_thread_fn(void *data)
{
	struct clock_thread *t = data;
	struct clock_entry *c;
	os_cpu_mask_t cpu_mask;
	uint32_t last_seq;
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

	pthread_mutex_lock(&t->lock);
	pthread_mutex_unlock(&t->started);

	first = get_cpu_clock();
	last_seq = 0;
	c = &t->entries[0];
	for (i = 0; i < t->nr_entries; i++, c++) {
		uint32_t seq;
		uint64_t tsc;

		c->cpu = t->cpu;
		do {
			seq = atomic32_inc_return(t->seq);
			if (seq < last_seq)
				break;
			tsc = get_cpu_clock();
		} while (seq != *t->seq);

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
	if (!t->entries[i - 1].tsc && !t->entries[0].tsc)
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
	unsigned int nr_cpus = cpus_online();
	struct clock_entry *entries;
	unsigned long nr_entries, tentries, failed = 0;
	struct clock_entry *prev, *this;
	uint32_t seq = 0;
	unsigned int i;

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

	for (i = 0; i < nr_cpus; i++) {
		struct clock_thread *t = &cthreads[i];

		t->cpu = i;
		t->debug = debug;
		t->seq = &seq;
		t->nr_entries = nr_entries;
		t->entries = &entries[i * nr_entries];
		pthread_mutex_init(&t->lock, NULL);
		pthread_mutex_init(&t->started, NULL);
		pthread_mutex_lock(&t->lock);
		if (pthread_create(&t->thread, NULL, clock_thread_fn, t)) {
			failed++;
			nr_cpus = i;
			break;
		}
	}

	for (i = 0; i < nr_cpus; i++) {
		struct clock_thread *t = &cthreads[i];

		pthread_mutex_lock(&t->started);
	}

	for (i = 0; i < nr_cpus; i++) {
		struct clock_thread *t = &cthreads[i];

		pthread_mutex_unlock(&t->lock);
	}

	for (i = 0; i < nr_cpus; i++) {
		struct clock_thread *t = &cthreads[i];
		void *ret;

		pthread_join(t->thread, &ret);
		if (ret)
			failed++;
	}
	free(cthreads);

	if (failed) {
		if (debug)
			log_err("Clocksource test: %lu threads failed\n", failed);
		goto err;
	}

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
