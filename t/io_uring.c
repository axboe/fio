#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <stddef.h>
#include <signal.h>
#include <inttypes.h>
#include <math.h>

#ifdef CONFIG_LIBAIO
#include <libaio.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>

#include "../arch/arch.h"
#include "../lib/types.h"
#include "../lib/roundup.h"
#include "../lib/rand.h"
#include "../minmax.h"
#include "../os/linux/io_uring.h"

struct io_sq_ring {
	unsigned *head;
	unsigned *tail;
	unsigned *ring_mask;
	unsigned *ring_entries;
	unsigned *flags;
	unsigned *array;
};

struct io_cq_ring {
	unsigned *head;
	unsigned *tail;
	unsigned *ring_mask;
	unsigned *ring_entries;
	struct io_uring_cqe *cqes;
};

#define DEPTH			128
#define BATCH_SUBMIT		32
#define BATCH_COMPLETE		32
#define BS			4096

#define MAX_FDS			16

static unsigned sq_ring_mask, cq_ring_mask;

struct file {
	unsigned long max_blocks;
	unsigned long max_size;
	unsigned long cur_off;
	unsigned pending_ios;
	int real_fd;
	int fixed_fd;
	int fileno;
};

#define PLAT_BITS		6
#define PLAT_VAL		(1 << PLAT_BITS)
#define PLAT_GROUP_NR		29
#define PLAT_NR			(PLAT_GROUP_NR * PLAT_VAL)

struct submitter {
	pthread_t thread;
	int ring_fd;
	int index;
	struct io_sq_ring sq_ring;
	struct io_uring_sqe *sqes;
	struct io_cq_ring cq_ring;
	int inflight;
	int tid;
	unsigned long reaps;
	unsigned long done;
	unsigned long calls;
	volatile int finish;

	__s32 *fds;

	struct taus258_state rand_state;

	unsigned long *clock_batch;
	int clock_index;
	unsigned long *plat;

#ifdef CONFIG_LIBAIO
	io_context_t aio_ctx;
#endif

	struct file files[MAX_FDS];
	unsigned nr_files;
	unsigned cur_file;
	struct iovec iovecs[];
};

static struct submitter *submitter;
static volatile int finish;
static int stats_running;
static unsigned long max_iops;

static int depth = DEPTH;
static int batch_submit = BATCH_SUBMIT;
static int batch_complete = BATCH_COMPLETE;
static int bs = BS;
static int polled = 1;		/* use IO polling */
static int fixedbufs = 1;	/* use fixed user buffers */
static int dma_map;		/* pre-map DMA buffers */
static int register_files = 1;	/* use fixed files */
static int buffered = 0;	/* use buffered IO, not O_DIRECT */
static int sq_thread_poll = 0;	/* use kernel submission/poller thread */
static int sq_thread_cpu = -1;	/* pin above thread to this CPU */
static int do_nop = 0;		/* no-op SQ ring commands */
static int nthreads = 1;
static int stats = 0;		/* generate IO stats */
static int aio = 0;		/* use libaio */
static int runtime = 0;		/* runtime */
static int random_io = 1;	/* random or sequential IO */

static unsigned long tsc_rate;

#define TSC_RATE_FILE	"tsc-rate"

static int vectored = 1;

static float plist[] = { 1.0, 5.0, 10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0,
			80.0, 90.0, 95.0, 99.0, 99.5, 99.9, 99.95, 99.99 };
static int plist_len = 17;

#ifndef IORING_REGISTER_MAP_BUFFERS
#define IORING_REGISTER_MAP_BUFFERS	20
struct io_uring_map_buffers {
	__s32	fd;
	__u32	buf_start;
	__u32	buf_end;
	__u32	flags;
	__u64	rsvd[2];
};
#endif

static unsigned long cycles_to_nsec(unsigned long cycles)
{
	uint64_t val;

	if (!tsc_rate)
		return cycles;

	val = cycles * 1000000000ULL;
	return val / tsc_rate;
}

static unsigned long plat_idx_to_val(unsigned int idx)
{
	unsigned int error_bits;
	unsigned long k, base;

	assert(idx < PLAT_NR);

	/* MSB <= (PLAT_BITS-1), cannot be rounded off. Use
	 * all bits of the sample as index */
	if (idx < (PLAT_VAL << 1))
		return cycles_to_nsec(idx);

	/* Find the group and compute the minimum value of that group */
	error_bits = (idx >> PLAT_BITS) - 1;
	base = ((unsigned long) 1) << (error_bits + PLAT_BITS);

	/* Find its bucket number of the group */
	k = idx % PLAT_VAL;

	/* Return the mean of the range of the bucket */
	return cycles_to_nsec(base + ((k + 0.5) * (1 << error_bits)));
}

unsigned int calc_clat_percentiles(unsigned long *io_u_plat, unsigned long nr,
				   unsigned long **output,
				   unsigned long *maxv, unsigned long *minv)
{
	unsigned long sum = 0;
	unsigned int len = plist_len, i, j = 0;
	unsigned long *ovals = NULL;
	bool is_last;

	*minv = -1UL;
	*maxv = 0;

	ovals = malloc(len * sizeof(*ovals));
	if (!ovals)
		return 0;

	/*
	 * Calculate bucket values, note down max and min values
	 */
	is_last = false;
	for (i = 0; i < PLAT_NR && !is_last; i++) {
		sum += io_u_plat[i];
		while (sum >= ((long double) plist[j] / 100.0 * nr)) {
			assert(plist[j] <= 100.0);

			ovals[j] = plat_idx_to_val(i);
			if (ovals[j] < *minv)
				*minv = ovals[j];
			if (ovals[j] > *maxv)
				*maxv = ovals[j];

			is_last = (j == len - 1) != 0;
			if (is_last)
				break;

			j++;
		}
	}

	if (!is_last)
		fprintf(stderr, "error calculating latency percentiles\n");

	*output = ovals;
	return len;
}

static void show_clat_percentiles(unsigned long *io_u_plat, unsigned long nr,
				  unsigned int precision)
{
	unsigned int divisor, len, i, j = 0;
	unsigned long minv, maxv;
	unsigned long *ovals;
	int per_line, scale_down, time_width;
	bool is_last;
	char fmt[32];

	len = calc_clat_percentiles(io_u_plat, nr, &ovals, &maxv, &minv);
	if (!len || !ovals)
		goto out;

	if (!tsc_rate) {
		scale_down = 0;
		divisor = 1;
		printf("    percentiles (tsc ticks):\n     |");
	} else if (minv > 2000 && maxv > 99999) {
		scale_down = 1;
		divisor = 1000;
		printf("    percentiles (usec):\n     |");
	} else {
		scale_down = 0;
		divisor = 1;
		printf("    percentiles (nsec):\n     |");
	}

	time_width = max(5, (int) (log10(maxv / divisor) + 1));
	snprintf(fmt, sizeof(fmt), " %%%u.%ufth=[%%%dllu]%%c", precision + 3,
			precision, time_width);
	/* fmt will be something like " %5.2fth=[%4llu]%c" */
	per_line = (80 - 7) / (precision + 10 + time_width);

	for (j = 0; j < len; j++) {
		/* for formatting */
		if (j != 0 && (j % per_line) == 0)
			printf("     |");

		/* end of the list */
		is_last = (j == len - 1) != 0;

		for (i = 0; i < scale_down; i++)
			ovals[j] = (ovals[j] + 999) / 1000;

		printf(fmt, plist[j], ovals[j], is_last ? '\n' : ',');

		if (is_last)
			break;

		if ((j % per_line) == per_line - 1)	/* for formatting */
			printf("\n");
	}

out:
	free(ovals);
}

#ifdef ARCH_HAVE_CPU_CLOCK
static unsigned int plat_val_to_idx(unsigned long val)
{
	unsigned int msb, error_bits, base, offset, idx;

	/* Find MSB starting from bit 0 */
	if (val == 0)
		msb = 0;
	else
		msb = (sizeof(val)*8) - __builtin_clzll(val) - 1;

	/*
	 * MSB <= (PLAT_BITS-1), cannot be rounded off. Use
	 * all bits of the sample as index
	 */
	if (msb <= PLAT_BITS)
		return val;

	/* Compute the number of error bits to discard*/
	error_bits = msb - PLAT_BITS;

	/* Compute the number of buckets before the group */
	base = (error_bits + 1) << PLAT_BITS;

	/*
	 * Discard the error bits and apply the mask to find the
	 * index for the buckets in the group
	 */
	offset = (PLAT_VAL - 1) & (val >> error_bits);

	/* Make sure the index does not exceed (array size - 1) */
	idx = (base + offset) < (PLAT_NR - 1) ?
		(base + offset) : (PLAT_NR - 1);

	return idx;
}
#endif

static void add_stat(struct submitter *s, int clock_index, int nr)
{
#ifdef ARCH_HAVE_CPU_CLOCK
	unsigned long cycles;
	unsigned int pidx;

	if (!s->finish && clock_index) {
		cycles = get_cpu_clock();
		cycles -= s->clock_batch[clock_index];
		pidx = plat_val_to_idx(cycles);
		s->plat[pidx] += nr;
	}
#endif
}

static int io_uring_map_buffers(struct submitter *s)
{
	struct io_uring_map_buffers map = {
		.fd		= s->files[0].real_fd,
		.buf_end	= depth,
	};

	if (do_nop)
		return 0;
	if (s->nr_files > 1) {
		fprintf(stderr, "Can't map buffers with multiple files\n");
		return -1;
	}

	return syscall(__NR_io_uring_register, s->ring_fd,
			IORING_REGISTER_MAP_BUFFERS, &map, 1);
}

static int io_uring_register_buffers(struct submitter *s)
{
	if (do_nop)
		return 0;

	return syscall(__NR_io_uring_register, s->ring_fd,
			IORING_REGISTER_BUFFERS, s->iovecs, roundup_pow2(depth));
}

static int io_uring_register_files(struct submitter *s)
{
	int i;

	if (do_nop)
		return 0;

	s->fds = calloc(s->nr_files, sizeof(__s32));
	for (i = 0; i < s->nr_files; i++) {
		s->fds[i] = s->files[i].real_fd;
		s->files[i].fixed_fd = i;
	}

	return syscall(__NR_io_uring_register, s->ring_fd,
			IORING_REGISTER_FILES, s->fds, s->nr_files);
}

static int io_uring_setup(unsigned entries, struct io_uring_params *p)
{
	/*
	 * Clamp CQ ring size at our SQ ring size, we don't need more entries
	 * than that.
	 */
	p->flags |= IORING_SETUP_CQSIZE;
	p->cq_entries = entries;

	return syscall(__NR_io_uring_setup, entries, p);
}

static void io_uring_probe(int fd)
{
	struct io_uring_probe *p;
	int ret;

	p = malloc(sizeof(*p) + 256 * sizeof(struct io_uring_probe_op));
	if (!p)
		return;

	memset(p, 0, sizeof(*p) + 256 * sizeof(struct io_uring_probe_op));
	ret = syscall(__NR_io_uring_register, fd, IORING_REGISTER_PROBE, p, 256);
	if (ret < 0)
		goto out;

	if (IORING_OP_READ > p->ops_len)
		goto out;

	if ((p->ops[IORING_OP_READ].flags & IO_URING_OP_SUPPORTED))
		vectored = 0;
out:
	free(p);
}

static int io_uring_enter(struct submitter *s, unsigned int to_submit,
			  unsigned int min_complete, unsigned int flags)
{
#ifdef FIO_ARCH_HAS_SYSCALL
	return __do_syscall6(__NR_io_uring_enter, s->ring_fd, to_submit,
				min_complete, flags, NULL, 0);
#else
	return syscall(__NR_io_uring_enter, s->ring_fd, to_submit, min_complete,
			flags, NULL, 0);
#endif
}

#ifndef CONFIG_HAVE_GETTID
static int gettid(void)
{
	return syscall(__NR_gettid);
}
#endif

static unsigned file_depth(struct submitter *s)
{
	return (depth + s->nr_files - 1) / s->nr_files;
}

static void init_io(struct submitter *s, unsigned index)
{
	struct io_uring_sqe *sqe = &s->sqes[index];
	unsigned long offset;
	struct file *f;
	long r;

	if (do_nop) {
		sqe->opcode = IORING_OP_NOP;
		return;
	}

	if (s->nr_files == 1) {
		f = &s->files[0];
	} else {
		f = &s->files[s->cur_file];
		if (f->pending_ios >= file_depth(s)) {
			s->cur_file++;
			if (s->cur_file == s->nr_files)
				s->cur_file = 0;
			f = &s->files[s->cur_file];
		}
	}
	f->pending_ios++;

	if (random_io) {
		r = __rand64(&s->rand_state);
		offset = (r % (f->max_blocks - 1)) * bs;
	} else {
		offset = f->cur_off;
		f->cur_off += bs;
		if (f->cur_off + bs > f->max_size)
			f->cur_off = 0;
	}

	if (register_files) {
		sqe->flags = IOSQE_FIXED_FILE;
		sqe->fd = f->fixed_fd;
	} else {
		sqe->flags = 0;
		sqe->fd = f->real_fd;
	}
	if (fixedbufs) {
		sqe->opcode = IORING_OP_READ_FIXED;
		sqe->addr = (unsigned long) s->iovecs[index].iov_base;
		sqe->len = bs;
		sqe->buf_index = index;
	} else if (!vectored) {
		sqe->opcode = IORING_OP_READ;
		sqe->addr = (unsigned long) s->iovecs[index].iov_base;
		sqe->len = bs;
		sqe->buf_index = 0;
	} else {
		sqe->opcode = IORING_OP_READV;
		sqe->addr = (unsigned long) &s->iovecs[index];
		sqe->len = 1;
		sqe->buf_index = 0;
	}
	sqe->ioprio = 0;
	sqe->off = offset;
	sqe->user_data = (unsigned long) f->fileno;
	if (stats && stats_running)
		sqe->user_data |= ((uint64_t)s->clock_index << 32);
}

static int prep_more_ios_uring(struct submitter *s, int max_ios)
{
	struct io_sq_ring *ring = &s->sq_ring;
	unsigned index, tail, next_tail, prepped = 0;

	next_tail = tail = *ring->tail;
	do {
		next_tail++;
		if (next_tail == atomic_load_acquire(ring->head))
			break;

		index = tail & sq_ring_mask;
		init_io(s, index);
		ring->array[index] = index;
		prepped++;
		tail = next_tail;
	} while (prepped < max_ios);

	if (prepped)
		atomic_store_release(ring->tail, tail);
	return prepped;
}

static int get_file_size(struct file *f)
{
	struct stat st;

	if (fstat(f->real_fd, &st) < 0)
		return -1;
	if (S_ISBLK(st.st_mode)) {
		unsigned long long bytes;

		if (ioctl(f->real_fd, BLKGETSIZE64, &bytes) != 0)
			return -1;

		f->max_blocks = bytes / bs;
		f->max_size = bytes;
		return 0;
	} else if (S_ISREG(st.st_mode)) {
		f->max_blocks = st.st_size / bs;
		f->max_size = st.st_size;
		return 0;
	}

	return -1;
}

static int reap_events_uring(struct submitter *s)
{
	struct io_cq_ring *ring = &s->cq_ring;
	struct io_uring_cqe *cqe;
	unsigned head, reaped = 0;
	int last_idx = -1, stat_nr = 0;

	head = *ring->head;
	do {
		struct file *f;

		read_barrier();
		if (head == atomic_load_acquire(ring->tail))
			break;
		cqe = &ring->cqes[head & cq_ring_mask];
		if (!do_nop) {
			int fileno = cqe->user_data & 0xffffffff;

			f = &s->files[fileno];
			f->pending_ios--;
			if (cqe->res != bs) {
				printf("io: unexpected ret=%d\n", cqe->res);
				if (polled && cqe->res == -EOPNOTSUPP)
					printf("Your filesystem/driver/kernel doesn't support polled IO\n");
				return -1;
			}
		}
		if (stats) {
			int clock_index = cqe->user_data >> 32;

			if (last_idx != clock_index) {
				if (last_idx != -1) {
					add_stat(s, last_idx, stat_nr);
					stat_nr = 0;
				}
				last_idx = clock_index;
			}
			stat_nr++;
		}
		reaped++;
		head++;
	} while (1);

	if (stat_nr)
		add_stat(s, last_idx, stat_nr);

	if (reaped) {
		s->inflight -= reaped;
		atomic_store_release(ring->head, head);
	}
	return reaped;
}

static int submitter_init(struct submitter *s)
{
	int i, nr_batch;

	s->tid = gettid();
	printf("submitter=%d, tid=%d\n", s->index, s->tid);

	__init_rand64(&s->rand_state, pthread_self());
	srand48(pthread_self());

	for (i = 0; i < MAX_FDS; i++)
		s->files[i].fileno = i;

	if (stats) {
		nr_batch = roundup_pow2(depth / batch_submit);
		if (nr_batch < 2)
			nr_batch = 2;
		s->clock_batch = calloc(nr_batch, sizeof(unsigned long));
		s->clock_index = 1;

		s->plat = calloc(PLAT_NR, sizeof(unsigned long));
	} else {
		s->clock_batch = NULL;
		s->plat = NULL;
		nr_batch = 0;
	}

	return nr_batch;
}

#ifdef CONFIG_LIBAIO
static int prep_more_ios_aio(struct submitter *s, int max_ios, struct iocb *iocbs)
{
	uint64_t data;
	long long offset;
	struct file *f;
	unsigned index;
	long r;

	index = 0;
	while (index < max_ios) {
		struct iocb *iocb = &iocbs[index];

		if (s->nr_files == 1) {
			f = &s->files[0];
		} else {
			f = &s->files[s->cur_file];
			if (f->pending_ios >= file_depth(s)) {
				s->cur_file++;
				if (s->cur_file == s->nr_files)
					s->cur_file = 0;
				f = &s->files[s->cur_file];
			}
		}
		f->pending_ios++;

		r = lrand48();
		offset = (r % (f->max_blocks - 1)) * bs;
		io_prep_pread(iocb, f->real_fd, s->iovecs[index].iov_base,
				s->iovecs[index].iov_len, offset);

		data = f->fileno;
		if (stats && stats_running)
			data |= (((uint64_t) s->clock_index) << 32);
		iocb->data = (void *) (uintptr_t) data;
		index++;
	}
	return index;
}

static int reap_events_aio(struct submitter *s, struct io_event *events, int evs)
{
	int last_idx = -1, stat_nr = 0;
	int reaped = 0;

	while (evs) {
		uint64_t data = (uintptr_t) events[reaped].data;
		struct file *f = &s->files[data & 0xffffffff];

		f->pending_ios--;
		if (events[reaped].res != bs) {
			printf("io: unexpected ret=%ld\n", events[reaped].res);
			return -1;
		}
		if (stats) {
			int clock_index = data >> 32;

			if (last_idx != clock_index) {
				if (last_idx != -1) {
					add_stat(s, last_idx, stat_nr);
					stat_nr = 0;
				}
				last_idx = clock_index;
			}
			stat_nr++;
		}
		reaped++;
		evs--;
	}

	if (stat_nr)
		add_stat(s, last_idx, stat_nr);

	s->inflight -= reaped;
	s->done += reaped;
	return reaped;
}

static void *submitter_aio_fn(void *data)
{
	struct submitter *s = data;
	int i, ret, prepped;
	struct iocb **iocbsptr;
	struct iocb *iocbs;
	struct io_event *events;
#ifdef ARCH_HAVE_CPU_CLOCK
	int nr_batch = submitter_init(s);
#else
	submitter_init(s);
#endif

	iocbsptr = calloc(depth, sizeof(struct iocb *));
	iocbs = calloc(depth, sizeof(struct iocb));
	events = calloc(depth, sizeof(struct io_event));

	for (i = 0; i < depth; i++)
		iocbsptr[i] = &iocbs[i];

	prepped = 0;
	do {
		int to_wait, to_submit, to_prep;

		if (!prepped && s->inflight < depth) {
			to_prep = min(depth - s->inflight, batch_submit);
			prepped = prep_more_ios_aio(s, to_prep, iocbs);
#ifdef ARCH_HAVE_CPU_CLOCK
			if (prepped && stats) {
				s->clock_batch[s->clock_index] = get_cpu_clock();
				s->clock_index = (s->clock_index + 1) & (nr_batch - 1);
			}
#endif
		}
		s->inflight += prepped;
		to_submit = prepped;

		if (to_submit && (s->inflight + to_submit <= depth))
			to_wait = 0;
		else
			to_wait = min(s->inflight + to_submit, batch_complete);

		ret = io_submit(s->aio_ctx, to_submit, iocbsptr);
		s->calls++;
		if (ret < 0) {
			perror("io_submit");
			break;
		} else if (ret != to_submit) {
			printf("submitted %d, wanted %d\n", ret, to_submit);
			break;
		}
		prepped = 0;

		while (to_wait) {
			int r;

			s->calls++;
			r = io_getevents(s->aio_ctx, to_wait, to_wait, events, NULL);
			if (r < 0) {
				perror("io_getevents");
				break;
			} else if (r != to_wait) {
				printf("r=%d, wait=%d\n", r, to_wait);
				break;
			}
			r = reap_events_aio(s, events, r);
			s->reaps += r;
			to_wait -= r;
		}
	} while (!s->finish);

	free(iocbsptr);
	free(iocbs);
	free(events);
	finish = 1;
	return NULL;
}
#endif

static void *submitter_uring_fn(void *data)
{
	struct submitter *s = data;
	struct io_sq_ring *ring = &s->sq_ring;
	int ret, prepped;
#ifdef ARCH_HAVE_CPU_CLOCK
	int nr_batch = submitter_init(s);
#else
	submitter_init(s);
#endif

	prepped = 0;
	do {
		int to_wait, to_submit, this_reap, to_prep;
		unsigned ring_flags = 0;

		if (!prepped && s->inflight < depth) {
			to_prep = min(depth - s->inflight, batch_submit);
			prepped = prep_more_ios_uring(s, to_prep);
#ifdef ARCH_HAVE_CPU_CLOCK
			if (prepped && stats) {
				s->clock_batch[s->clock_index] = get_cpu_clock();
				s->clock_index = (s->clock_index + 1) & (nr_batch - 1);
			}
#endif
		}
		s->inflight += prepped;
submit_more:
		to_submit = prepped;
submit:
		if (to_submit && (s->inflight + to_submit <= depth))
			to_wait = 0;
		else
			to_wait = min(s->inflight + to_submit, batch_complete);

		/*
		 * Only need to call io_uring_enter if we're not using SQ thread
		 * poll, or if IORING_SQ_NEED_WAKEUP is set.
		 */
		if (sq_thread_poll)
			ring_flags = atomic_load_acquire(ring->flags);
		if (!sq_thread_poll || ring_flags & IORING_SQ_NEED_WAKEUP) {
			unsigned flags = 0;

			if (to_wait)
				flags = IORING_ENTER_GETEVENTS;
			if (ring_flags & IORING_SQ_NEED_WAKEUP)
				flags |= IORING_ENTER_SQ_WAKEUP;
			ret = io_uring_enter(s, to_submit, to_wait, flags);
			s->calls++;
		} else {
			/* for SQPOLL, we submitted it all effectively */
			ret = to_submit;
		}

		/*
		 * For non SQ thread poll, we already got the events we needed
		 * through the io_uring_enter() above. For SQ thread poll, we
		 * need to loop here until we find enough events.
		 */
		this_reap = 0;
		do {
			int r;

			r = reap_events_uring(s);
			if (r == -1) {
				s->finish = 1;
				break;
			} else if (r > 0)
				this_reap += r;
		} while (sq_thread_poll && this_reap < to_wait);
		s->reaps += this_reap;

		if (ret >= 0) {
			if (!ret) {
				to_submit = 0;
				if (s->inflight)
					goto submit;
				continue;
			} else if (ret < to_submit) {
				int diff = to_submit - ret;

				s->done += ret;
				prepped -= diff;
				goto submit_more;
			}
			s->done += ret;
			prepped = 0;
			continue;
		} else if (ret < 0) {
			if (errno == EAGAIN) {
				if (s->finish)
					break;
				if (this_reap)
					goto submit;
				to_submit = 0;
				goto submit;
			}
			printf("io_submit: %s\n", strerror(errno));
			break;
		}
	} while (!s->finish);

	finish = 1;
	return NULL;
}

static struct submitter *get_submitter(int offset)
{
	void *ret;

	ret = submitter;
	if (offset)
		ret += offset * (sizeof(*submitter) + depth * sizeof(struct iovec));
	return ret;
}

static void do_finish(const char *reason)
{
	int j;
	printf("Exiting on %s\n", reason);
	for (j = 0; j < nthreads; j++) {
		struct submitter *s = get_submitter(j);
		s->finish = 1;
	}
	if (max_iops > 100000)
		printf("Maximum IOPS=%luK\n", max_iops / 1000);
	else if (max_iops)
		printf("Maximum IOPS=%lu\n", max_iops);
	finish = 1;
}

static void sig_int(int sig)
{
	do_finish("signal");
}

static void arm_sig_int(void)
{
	struct sigaction act;

	memset(&act, 0, sizeof(act));
	act.sa_handler = sig_int;
	act.sa_flags = SA_RESTART;
	sigaction(SIGINT, &act, NULL);

	/* Windows uses SIGBREAK as a quit signal from other applications */
#ifdef WIN32
	sigaction(SIGBREAK, &act, NULL);
#endif
}

static int setup_aio(struct submitter *s)
{
#ifdef CONFIG_LIBAIO
	if (polled) {
		fprintf(stderr, "aio does not support polled IO\n");
		polled = 0;
	}
	if (sq_thread_poll) {
		fprintf(stderr, "aio does not support SQPOLL IO\n");
		sq_thread_poll = 0;
	}
	if (do_nop) {
		fprintf(stderr, "aio does not support polled IO\n");
		do_nop = 0;
	}
	if (fixedbufs || register_files) {
		fprintf(stderr, "aio does not support registered files or buffers\n");
		fixedbufs = register_files = 0;
	}

	return io_queue_init(roundup_pow2(depth), &s->aio_ctx);
#else
	fprintf(stderr, "Legacy AIO not available on this system/build\n");
	errno = EINVAL;
	return -1;
#endif
}

static int setup_ring(struct submitter *s)
{
	struct io_sq_ring *sring = &s->sq_ring;
	struct io_cq_ring *cring = &s->cq_ring;
	struct io_uring_params p;
	int ret, fd;
	void *ptr;

	memset(&p, 0, sizeof(p));

	if (polled && !do_nop)
		p.flags |= IORING_SETUP_IOPOLL;
	if (sq_thread_poll) {
		p.flags |= IORING_SETUP_SQPOLL;
		if (sq_thread_cpu != -1) {
			p.flags |= IORING_SETUP_SQ_AFF;
			p.sq_thread_cpu = sq_thread_cpu;
		}
	}

	fd = io_uring_setup(depth, &p);
	if (fd < 0) {
		perror("io_uring_setup");
		return 1;
	}
	s->ring_fd = fd;

	io_uring_probe(fd);

	if (fixedbufs) {
		struct rlimit rlim;

		rlim.rlim_cur = RLIM_INFINITY;
		rlim.rlim_max = RLIM_INFINITY;
		/* ignore potential error, not needed on newer kernels */
		setrlimit(RLIMIT_MEMLOCK, &rlim);

		ret = io_uring_register_buffers(s);
		if (ret < 0) {
			perror("io_uring_register_buffers");
			return 1;
		}

		if (dma_map) {
			ret = io_uring_map_buffers(s);
			if (ret < 0) {
				perror("io_uring_map_buffers");
				return 1;
			}
		}
	}

	if (register_files) {
		ret = io_uring_register_files(s);
		if (ret < 0) {
			perror("io_uring_register_files");
			return 1;
		}
	}

	ptr = mmap(0, p.sq_off.array + p.sq_entries * sizeof(__u32),
			PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
			IORING_OFF_SQ_RING);
	sring->head = ptr + p.sq_off.head;
	sring->tail = ptr + p.sq_off.tail;
	sring->ring_mask = ptr + p.sq_off.ring_mask;
	sring->ring_entries = ptr + p.sq_off.ring_entries;
	sring->flags = ptr + p.sq_off.flags;
	sring->array = ptr + p.sq_off.array;
	sq_ring_mask = *sring->ring_mask;

	s->sqes = mmap(0, p.sq_entries * sizeof(struct io_uring_sqe),
			PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
			IORING_OFF_SQES);

	ptr = mmap(0, p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe),
			PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
			IORING_OFF_CQ_RING);
	cring->head = ptr + p.cq_off.head;
	cring->tail = ptr + p.cq_off.tail;
	cring->ring_mask = ptr + p.cq_off.ring_mask;
	cring->ring_entries = ptr + p.cq_off.ring_entries;
	cring->cqes = ptr + p.cq_off.cqes;
	cq_ring_mask = *cring->ring_mask;
	return 0;
}

static void file_depths(char *buf)
{
	bool prev = false;
	char *p;
	int i, j;

	buf[0] = '\0';
	p = buf;
	for (j = 0; j < nthreads; j++) {
		struct submitter *s = get_submitter(j);

		for (i = 0; i < s->nr_files; i++) {
			struct file *f = &s->files[i];

			if (prev)
				p += sprintf(p, " %d", f->pending_ios);
			else
				p += sprintf(p, "%d", f->pending_ios);
			prev = true;
		}
	}
}

static void usage(char *argv, int status)
{
	char runtime_str[16];
	snprintf(runtime_str, sizeof(runtime_str), "%d", runtime);
	printf("%s [options] -- [filenames]\n"
		" -d <int>  : IO Depth, default %d\n"
		" -s <int>  : Batch submit, default %d\n"
		" -c <int>  : Batch complete, default %d\n"
		" -b <int>  : Block size, default %d\n"
		" -p <bool> : Polled IO, default %d\n"
		" -B <bool> : Fixed buffers, default %d\n"
		" -D <bool> : DMA map fixed buffers, default %d\n"
		" -F <bool> : Register files, default %d\n"
		" -n <int>  : Number of threads, default %d\n"
		" -O <bool> : Use O_DIRECT, default %d\n"
		" -N <bool> : Perform just no-op requests, default %d\n"
		" -t <bool> : Track IO latencies, default %d\n"
		" -T <int>  : TSC rate in HZ\n"
		" -r <int>  : Runtime in seconds, default %s\n"
		" -R <bool> : Use random IO, default %d\n"
		" -a <bool> : Use legacy aio, default %d\n",
		argv, DEPTH, BATCH_SUBMIT, BATCH_COMPLETE, BS, polled,
		fixedbufs, dma_map, register_files, nthreads, !buffered, do_nop,
		stats, runtime == 0 ? "unlimited" : runtime_str, random_io, aio);
	exit(status);
}

static void read_tsc_rate(void)
{
	char buffer[32];
	int fd, ret;

	if (tsc_rate)
		return;

	fd = open(TSC_RATE_FILE, O_RDONLY);
	if (fd < 0)
		return;

	ret = read(fd, buffer, sizeof(buffer));
	if (ret < 0) {
		close(fd);
		return;
	}

	tsc_rate = strtoul(buffer, NULL, 10);
	printf("Using TSC rate %luHz\n", tsc_rate);
	close(fd);
}

static void write_tsc_rate(void)
{
	char buffer[32];
	struct stat sb;
	int fd, ret;

	if (!stat(TSC_RATE_FILE, &sb))
		return;

	fd = open(TSC_RATE_FILE, O_WRONLY | O_CREAT, 0644);
	if (fd < 0)
		return;

	memset(buffer, 0, sizeof(buffer));
	sprintf(buffer, "%lu", tsc_rate);
	ret = write(fd, buffer, strlen(buffer));
	if (ret < 0)
		perror("write");
	close(fd);
}

int main(int argc, char *argv[])
{
	struct submitter *s;
	unsigned long done, calls, reap;
	int err, i, j, flags, fd, opt, threads_per_f, threads_rem = 0, nfiles;
	long page_size;
	struct file f;
	char *fdepths;
	void *ret;

	if (!do_nop && argc < 2)
		usage(argv[0], 1);

	while ((opt = getopt(argc, argv, "d:s:c:b:p:B:F:n:N:O:t:T:a:r:D:R:h?")) != -1) {
		switch (opt) {
		case 'a':
			aio = !!atoi(optarg);
			break;
		case 'd':
			depth = atoi(optarg);
			break;
		case 's':
			batch_submit = atoi(optarg);
			if (!batch_submit)
				batch_submit = 1;
			break;
		case 'c':
			batch_complete = atoi(optarg);
			if (!batch_complete)
				batch_complete = 1;
			break;
		case 'b':
			bs = atoi(optarg);
			break;
		case 'p':
			polled = !!atoi(optarg);
			break;
		case 'B':
			fixedbufs = !!atoi(optarg);
			break;
		case 'F':
			register_files = !!atoi(optarg);
			break;
		case 'n':
			nthreads = atoi(optarg);
			if (!nthreads) {
				printf("Threads must be non-zero\n");
				usage(argv[0], 1);
			}
			break;
		case 'N':
			do_nop = !!atoi(optarg);
			break;
		case 'O':
			buffered = !atoi(optarg);
			break;
		case 't':
#ifndef ARCH_HAVE_CPU_CLOCK
			fprintf(stderr, "Stats not supported on this CPU\n");
			return 1;
#endif
			stats = !!atoi(optarg);
			break;
		case 'T':
#ifndef ARCH_HAVE_CPU_CLOCK
			fprintf(stderr, "Stats not supported on this CPU\n");
			return 1;
#endif
			tsc_rate = strtoul(optarg, NULL, 10);
			write_tsc_rate();
			break;
		case 'r':
			runtime = atoi(optarg);
			break;
		case 'D':
			dma_map = !!atoi(optarg);
			break;
		case 'R':
			random_io = !!atoi(optarg);
			break;
		case 'h':
		case '?':
		default:
			usage(argv[0], 0);
			break;
		}
	}

	if (stats)
		read_tsc_rate();

	if (batch_complete > depth)
		batch_complete = depth;
	if (batch_submit > depth)
		batch_submit = depth;
	if (!fixedbufs && dma_map)
		dma_map = 0;

	submitter = calloc(nthreads, sizeof(*submitter) +
				roundup_pow2(depth) * sizeof(struct iovec));
	for (j = 0; j < nthreads; j++) {
		s = get_submitter(j);
		s->index = j;
		s->done = s->calls = s->reaps = 0;
	}

	flags = O_RDONLY | O_NOATIME;
	if (!buffered)
		flags |= O_DIRECT;

	j = 0;
	i = optind;
	nfiles = argc - i;
	if (!do_nop) {
		if (!nfiles) {
			printf("No files specified\n");
			usage(argv[0], 1);
		}
		threads_per_f = nthreads / nfiles;
		/* make sure each thread gets assigned files */
		if (threads_per_f == 0) {
			threads_per_f = 1;
		} else {
			threads_rem = nthreads - threads_per_f * nfiles;
		}
	}
	while (!do_nop && i < argc) {
		int k, limit;

		memset(&f, 0, sizeof(f));

		fd = open(argv[i], flags);
		if (fd < 0) {
			perror("open");
			return 1;
		}
		f.real_fd = fd;
		if (get_file_size(&f)) {
			printf("failed getting size of device/file\n");
			return 1;
		}
		if (f.max_blocks <= 1) {
			printf("Zero file/device size?\n");
			return 1;
		}
		f.max_blocks--;

		limit = threads_per_f;
		limit += threads_rem > 0 ? 1 : 0;
		for (k = 0; k < limit; k++) {
			s = get_submitter((j + k) % nthreads);

			if (s->nr_files == MAX_FDS) {
				printf("Max number of files (%d) reached\n", MAX_FDS);
				break;
			}

			memcpy(&s->files[s->nr_files], &f, sizeof(f));

			printf("Added file %s (submitter %d)\n", argv[i], s->index);
			s->nr_files++;
		}
		threads_rem--;
		i++;
		j += limit;
	}

	arm_sig_int();

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size < 0)
		page_size = 4096;

	for (j = 0; j < nthreads; j++) {
		s = get_submitter(j);
		for (i = 0; i < roundup_pow2(depth); i++) {
			void *buf;

			if (posix_memalign(&buf, page_size, bs)) {
				printf("failed alloc\n");
				return 1;
			}
			s->iovecs[i].iov_base = buf;
			s->iovecs[i].iov_len = bs;
		}
	}

	for (j = 0; j < nthreads; j++) {
		s = get_submitter(j);

		if (!aio)
			err = setup_ring(s);
		else
			err = setup_aio(s);
		if (err) {
			printf("ring setup failed: %s, %d\n", strerror(errno), err);
			return 1;
		}
	}
	s = get_submitter(0);
	printf("polled=%d, fixedbufs=%d/%d, register_files=%d, buffered=%d, QD=%d\n", polled, fixedbufs, dma_map, register_files, buffered, depth);
	if (!aio)
		printf("Engine=io_uring, sq_ring=%d, cq_ring=%d\n", *s->sq_ring.ring_entries, *s->cq_ring.ring_entries);
	else
		printf("Engine=aio\n");

	for (j = 0; j < nthreads; j++) {
		s = get_submitter(j);
		if (!aio)
			pthread_create(&s->thread, NULL, submitter_uring_fn, s);
#ifdef CONFIG_LIBAIO
		else
			pthread_create(&s->thread, NULL, submitter_aio_fn, s);
#endif
	}

	fdepths = malloc(8 * s->nr_files * nthreads);
	reap = calls = done = 0;
	do {
		unsigned long this_done = 0;
		unsigned long this_reap = 0;
		unsigned long this_call = 0;
		unsigned long rpc = 0, ipc = 0;
		unsigned long iops, bw;

		sleep(1);
		if (runtime && !--runtime)
			do_finish("timeout");

		/* don't print partial run, if interrupted by signal */
		if (finish)
			break;

		/* one second in to the run, enable stats */
		if (stats)
			stats_running = 1;

		for (j = 0; j < nthreads; j++) {
			s = get_submitter(j);
			this_done += s->done;
			this_call += s->calls;
			this_reap += s->reaps;
		}
		if (this_call - calls) {
			rpc = (this_done - done) / (this_call - calls);
			ipc = (this_reap - reap) / (this_call - calls);
		} else
			rpc = ipc = -1;
		file_depths(fdepths);
		iops = this_done - done;
		if (bs > 1048576)
			bw = iops * (bs / 1048576);
		else
			bw = iops / (1048576 / bs);
		if (iops > 100000)
			printf("IOPS=%luK, ", iops / 1000);
		else
			printf("IOPS=%lu, ", iops);
		max_iops = max(max_iops, iops);
		if (!do_nop)
			printf("BW=%luMiB/s, ", bw);
		printf("IOS/call=%ld/%ld, inflight=(%s)\n", rpc, ipc, fdepths);
		done = this_done;
		calls = this_call;
		reap = this_reap;
	} while (!finish);

	for (j = 0; j < nthreads; j++) {
		s = get_submitter(j);
		pthread_join(s->thread, &ret);
		close(s->ring_fd);

		if (stats) {
			unsigned long nr;

			printf("%d: Latency percentiles:\n", s->tid);
			for (i = 0, nr = 0; i < PLAT_NR; i++)
				nr += s->plat[i];
			show_clat_percentiles(s->plat, nr, 4);
			free(s->clock_batch);
			free(s->plat);
		}
	}

	free(fdepths);
	free(submitter);
	return 0;
}
