/*
 * gcc -D_GNU_SOURCE -Wall -O2 -o aio-ring aio-ring.c  -lpthread -laio
 */
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <stddef.h>
#include <signal.h>
#include <inttypes.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <unistd.h>
#include <libaio.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>

#define IOCB_FLAG_HIPRI		(1 << 2)

#define IOCTX_FLAG_IOPOLL	(1 << 0)
#define IOCTX_FLAG_SCQRING	(1 << 1)	/* Use SQ/CQ rings */
#define IOCTX_FLAG_FIXEDBUFS	(1 << 2)
#define IOCTX_FLAG_SQTHREAD	(1 << 3)	/* Use SQ thread */
#define IOCTX_FLAG_SQWQ		(1 << 4)	/* Use SQ wq */

#define IOEV_RES2_CACHEHIT	(1 << 0)

#define barrier()	__asm__ __volatile__("": : :"memory")

#define min(a, b)		((a < b) ? (a) : (b))

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;

struct aio_sq_ring {
	union {
		struct {
			u32 head;
			u32 tail;
			u32 nr_events;
			u16 sq_thread_cpu;
			u64 iocbs;
		};
		u32 pad[16];
	};
	u32 array[0];
};

struct aio_cq_ring {
	union {
		struct {
			u32 head;
			u32 tail;
			u32 nr_events;
		};
		struct io_event pad;
	};
	struct io_event events[0];
};

#define IORING_FLAG_SUBMIT	(1 << 0)
#define IORING_FLAG_GETEVENTS	(1 << 1)

#define DEPTH			32
#define RING_SIZE		(DEPTH + 1)

#define BATCH_SUBMIT		8
#define BATCH_COMPLETE		8

#define BS			4096

struct submitter {
	pthread_t thread;
	unsigned long max_blocks;
	io_context_t ioc;
	struct drand48_data rand;
	struct aio_sq_ring *sq_ring;
	struct iocb *iocbs;
	struct aio_cq_ring *cq_ring;
	int inflight;
	unsigned long reaps;
	unsigned long done;
	unsigned long calls;
	unsigned long cachehit, cachemiss;
	volatile int finish;
	char filename[128];
};

static struct submitter submitters[1];
static volatile int finish;

static int polled = 1;		/* use IO polling */
static int fixedbufs = 1;	/* use fixed user buffers */
static int buffered = 0;	/* use buffered IO, not O_DIRECT */
static int sq_thread = 0;	/* use kernel submission thread */
static int sq_thread_cpu = 0;	/* pin above thread to this CPU */

static int io_setup2(unsigned int nr_events, unsigned int flags,
		     struct aio_sq_ring *sq_ring, struct aio_cq_ring *cq_ring,
		     io_context_t *ctx_idp)
{
	return syscall(335, nr_events, flags, sq_ring, cq_ring, ctx_idp);
}

static int io_ring_enter(io_context_t ctx, unsigned int to_submit,
			 unsigned int min_complete, unsigned int flags)
{
	return syscall(336, ctx, to_submit, min_complete, flags);
}

static int gettid(void)
{
	return syscall(__NR_gettid);
}

static void init_io(struct submitter *s, int fd, struct iocb *iocb)
{
	unsigned long offset;
	long r;

	lrand48_r(&s->rand, &r);
	offset = (r % (s->max_blocks - 1)) * BS;

	iocb->aio_fildes = fd;
	iocb->aio_lio_opcode = IO_CMD_PREAD;
	iocb->u.c.offset = offset;
	if (polled)
		iocb->u.c.flags = IOCB_FLAG_HIPRI;
	if (!fixedbufs)
		iocb->u.c.nbytes = BS;
}

static int prep_more_ios(struct submitter *s, int fd, int max_ios)
{
	struct aio_sq_ring *ring = s->sq_ring;
	u32 tail, next_tail, prepped = 0;

	next_tail = tail = ring->tail;
	do {
		next_tail++;
		if (next_tail == ring->nr_events)
			next_tail = 0;

		barrier();
		if (next_tail == ring->head)
			break;

		init_io(s, fd, &s->iocbs[tail]);
		s->sq_ring->array[tail] = tail;
		prepped++;
		tail = next_tail;
	} while (prepped < max_ios);

	if (ring->tail != tail) {
		/* order tail store with writes to iocbs above */
		barrier();
		ring->tail = tail;
		barrier();
	}
	return prepped;
}

static int get_file_size(int fd, unsigned long *blocks)
{
	struct stat st;

	if (fstat(fd, &st) < 0)
		return -1;
	if (S_ISBLK(st.st_mode)) {
		unsigned long long bytes;

		if (ioctl(fd, BLKGETSIZE64, &bytes) != 0)
			return -1;

		*blocks = bytes / BS;
		return 0;
	} else if (S_ISREG(st.st_mode)) {
		*blocks = st.st_size / BS;
		return 0;
	}

	return -1;
}

static int reap_events(struct submitter *s)
{
	struct aio_cq_ring *ring = s->cq_ring;
	struct io_event *ev;
	u32 head, reaped = 0;

	head = ring->head;
	do {
		barrier();
		if (head == ring->tail)
			break;
		ev = &ring->events[head];
		if (ev->res != BS) {
			struct iocb *iocb = ev->obj;

			printf("io: unexpected ret=%ld\n", ev->res);
			printf("offset=%lu, size=%lu\n", (unsigned long) iocb->u.c.offset, (unsigned long) iocb->u.c.nbytes);
			return -1;
		}
		if (ev->res2 & IOEV_RES2_CACHEHIT)
			s->cachehit++;
		else
			s->cachemiss++;
		reaped++;
		head++;
		if (head == ring->nr_events)
			head = 0;
	} while (1);

	s->inflight -= reaped;
	ring->head = head;
	barrier();
	return reaped;
}

static void *submitter_fn(void *data)
{
	struct submitter *s = data;
	int fd, ret, prepped, flags;

	printf("submitter=%d\n", gettid());

	flags = O_RDONLY;
	if (!buffered)
		flags |= O_DIRECT;
	fd = open(s->filename, flags);
	if (fd < 0) {
		perror("open");
		goto done;
	}

	if (get_file_size(fd, &s->max_blocks)) {
		printf("failed getting size of device/file\n");
		goto err;
	}
	if (!s->max_blocks) {
		printf("Zero file/device size?\n");
		goto err;
	}

	s->max_blocks--;

	srand48_r(pthread_self(), &s->rand);

	prepped = 0;
	do {
		int to_wait, flags, to_submit, this_reap;

		if (!prepped && s->inflight < DEPTH)
			prepped = prep_more_ios(s, fd, min(DEPTH - s->inflight, BATCH_SUBMIT));
		s->inflight += prepped;
submit_more:
		to_submit = prepped;
submit:
		if (s->inflight + BATCH_SUBMIT < DEPTH)
			to_wait = 0;
		else
			to_wait = min(s->inflight + to_submit, BATCH_COMPLETE);

		flags = IORING_FLAG_GETEVENTS;
		if (to_submit)
			flags |= IORING_FLAG_SUBMIT;

		ret = io_ring_enter(s->ioc, to_submit, to_wait, flags);
		s->calls++;

		this_reap = reap_events(s);
		if (this_reap == -1)
			break;
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
			if ((ret == -1 && errno == EAGAIN) || ret == -EAGAIN) {
				if (s->finish)
					break;
				if (this_reap)
					goto submit;
				to_submit = 0;
				goto submit;
			}
			if (ret == -1)
				printf("io_submit: %s\n", strerror(errno));
			else
				printf("io_submit: %s\n", strerror(-ret));
			break;
		}
	} while (!s->finish);
err:
	close(fd);
done:
	finish = 1;
	return NULL;
}

static void sig_int(int sig)
{
	printf("Exiting on signal %d\n", sig);
	submitters[0].finish = 1;
	finish = 1;
}

static void arm_sig_int(void)
{
	struct sigaction act;

	memset(&act, 0, sizeof(act));
	act.sa_handler = sig_int;
	act.sa_flags = SA_RESTART;
	sigaction(SIGINT, &act, NULL);
}

int main(int argc, char *argv[])
{
	struct submitter *s = &submitters[0];
	unsigned long done, calls, reap, cache_hit, cache_miss;
	int flags = 0, err;
	int j;
	size_t size;
	void *p, *ret;
	struct rlimit rlim;

	if (argc < 2) {
		printf("%s: filename\n", argv[0]);
		return 1;
	}

	rlim.rlim_cur = RLIM_INFINITY;
	rlim.rlim_max = RLIM_INFINITY;
	if (setrlimit(RLIMIT_MEMLOCK, &rlim) < 0) {
		perror("setrlimit");
		return 1;
	}

	arm_sig_int();

	size = sizeof(struct iocb) * RING_SIZE;
	if (posix_memalign(&p, 4096, size))
		return 1;
	memset(p, 0, size);
	s->iocbs = p;

	size = sizeof(struct aio_sq_ring) + RING_SIZE * sizeof(u32);
	if (posix_memalign(&p, 4096, size))
		return 1;
	s->sq_ring = p;
	memset(p, 0, size);
	s->sq_ring->nr_events = RING_SIZE;
	s->sq_ring->iocbs = (u64) s->iocbs;

	/* CQ ring must be twice as big */
	size = sizeof(struct aio_cq_ring) +
			2 * RING_SIZE * sizeof(struct io_event);
	if (posix_memalign(&p, 4096, size))
		return 1;
	s->cq_ring = p;
	memset(p, 0, size);
	s->cq_ring->nr_events = 2 * RING_SIZE;

	for (j = 0; j < RING_SIZE; j++) {
		struct iocb *iocb = &s->iocbs[j];

		if (posix_memalign(&iocb->u.c.buf, BS, BS)) {
			printf("failed alloc\n");
			return 1;
		}
		iocb->u.c.nbytes = BS;
	}

	flags = IOCTX_FLAG_SCQRING;
	if (polled)
		flags |= IOCTX_FLAG_IOPOLL;
	if (fixedbufs)
		flags |= IOCTX_FLAG_FIXEDBUFS;
	if (buffered)
		flags |= IOCTX_FLAG_SQWQ;
	else if (sq_thread) {
		flags |= IOCTX_FLAG_SQTHREAD;
		s->sq_ring->sq_thread_cpu = sq_thread_cpu;
	}

	err = io_setup2(RING_SIZE, flags, s->sq_ring, s->cq_ring, &s->ioc);
	if (err) {
		printf("ctx_init failed: %s, %d\n", strerror(errno), err);
		return 1;
	}
	printf("polled=%d, fixedbufs=%d, buffered=%d\n", polled, fixedbufs, buffered);
	printf("  QD=%d, sq_ring=%d, cq_ring=%d\n", DEPTH, s->sq_ring->nr_events, s->cq_ring->nr_events);
	strcpy(s->filename, argv[1]);

	pthread_create(&s->thread, NULL, submitter_fn, s);

	cache_hit = cache_miss = reap = calls = done = 0;
	do {
		unsigned long this_done = 0;
		unsigned long this_reap = 0;
		unsigned long this_call = 0;
		unsigned long this_cache_hit = 0;
		unsigned long this_cache_miss = 0;
		unsigned long rpc = 0, ipc = 0;
		double hit = 0.0;

		sleep(1);
		this_done += s->done;
		this_call += s->calls;
		this_reap += s->reaps;
		this_cache_hit += s->cachehit;
		this_cache_miss += s->cachemiss;
		if (this_cache_hit && this_cache_miss) {
			unsigned long hits, total;

			hits = this_cache_hit - cache_hit;
			total = hits + this_cache_miss - cache_miss;
			hit = (double) hits / (double) total;
			hit *= 100.0;
		}
		if (this_call - calls) {
			rpc = (this_done - done) / (this_call - calls);
			ipc = (this_reap - reap) / (this_call - calls);
		}
		printf("IOPS=%lu, IOS/call=%lu/%lu, inflight=%u (head=%d tail=%d), Cachehit=%0.2f%%\n",
				this_done - done, rpc, ipc, s->inflight,
				s->cq_ring->head, s->cq_ring->tail, hit);
		done = this_done;
		calls = this_call;
		reap = this_reap;
		cache_hit = s->cachehit;
		cache_miss = s->cachemiss;
	} while (!finish);

	pthread_join(s->thread, &ret);
	return 0;
}
