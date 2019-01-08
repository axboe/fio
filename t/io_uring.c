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
#include "../os/io_uring.h"

#define barrier()	__asm__ __volatile__("": : :"memory")

#define min(a, b)		((a < b) ? (a) : (b))

struct io_sq_ring {
	unsigned *head;
	unsigned *tail;
	unsigned *ring_mask;
	unsigned *ring_entries;
	unsigned *array;
};

struct io_cq_ring {
	unsigned *head;
	unsigned *tail;
	unsigned *ring_mask;
	unsigned *ring_entries;
	struct io_uring_event *events;
};

#define DEPTH			32

#define BATCH_SUBMIT		8
#define BATCH_COMPLETE		8

#define BS			4096

static unsigned sq_ring_mask, cq_ring_mask;

struct submitter {
	pthread_t thread;
	unsigned long max_blocks;
	int ring_fd;
	struct drand48_data rand;
	struct io_sq_ring sq_ring;
	struct io_uring_iocb *iocbs;
	struct iovec iovecs[DEPTH];
	struct io_cq_ring cq_ring;
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

static int polled = 0;		/* use IO polling */
static int fixedbufs = 0;	/* use fixed user buffers */
static int buffered = 1;	/* use buffered IO, not O_DIRECT */
static int sq_thread = 0;	/* use kernel submission thread */
static int sq_thread_cpu = 0;	/* pin above thread to this CPU */

static int io_uring_setup(unsigned entries, struct iovec *iovecs,
			  struct io_uring_params *p)
{
	return syscall(__NR_sys_io_uring_setup, entries, iovecs, p);
}

static int io_uring_enter(struct submitter *s, unsigned int to_submit,
			  unsigned int min_complete, unsigned int flags)
{
	return syscall(__NR_sys_io_uring_enter, s->ring_fd, to_submit,
			min_complete, flags);
}

static int gettid(void)
{
	return syscall(__NR_gettid);
}

static void init_io(struct submitter *s, int fd, unsigned index)
{
	struct io_uring_iocb *iocb = &s->iocbs[index];
	unsigned long offset;
	long r;

	lrand48_r(&s->rand, &r);
	offset = (r % (s->max_blocks - 1)) * BS;

	if (fixedbufs)
		iocb->opcode = IORING_OP_READ_FIXED;
	else
		iocb->opcode = IORING_OP_READ;
	iocb->flags = 0;
	iocb->ioprio = 0;
	iocb->fd = fd;
	iocb->off = offset;
	iocb->addr = s->iovecs[index].iov_base;
	iocb->len = BS;
}

static int prep_more_ios(struct submitter *s, int fd, int max_ios)
{
	struct io_sq_ring *ring = &s->sq_ring;
	unsigned index, tail, next_tail, prepped = 0;

	next_tail = tail = *ring->tail;
	do {
		next_tail++;
		barrier();
		if (next_tail == *ring->head)
			break;

		index = tail & sq_ring_mask;
		init_io(s, fd, index);
		ring->array[index] = index;
		prepped++;
		tail = next_tail;
	} while (prepped < max_ios);

	if (*ring->tail != tail) {
		/* order tail store with writes to iocbs above */
		barrier();
		*ring->tail = tail;
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
	struct io_cq_ring *ring = &s->cq_ring;
	struct io_uring_event *ev;
	unsigned head, reaped = 0;

	head = *ring->head;
	do {
		barrier();
		if (head == *ring->tail)
			break;
		ev = &ring->events[head & cq_ring_mask];
		if (ev->res != BS) {
			struct io_uring_iocb *iocb = &s->iocbs[ev->index];

			printf("io: unexpected ret=%d\n", ev->res);
			printf("offset=%lu, size=%lu\n",
					(unsigned long) iocb->off,
					(unsigned long) iocb->len);
			return -1;
		}
		if (ev->flags & IOEV_FLAG_CACHEHIT)
			s->cachehit++;
		else
			s->cachemiss++;
		reaped++;
		head++;
	} while (1);

	s->inflight -= reaped;
	*ring->head = head;
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
	if (s->max_blocks <= 1) {
		printf("Zero file/device size?\n");
		goto err;
	}
	s->max_blocks--;

	srand48_r(pthread_self(), &s->rand);

	prepped = 0;
	do {
		int to_wait, to_submit, this_reap, to_prep;

		if (!prepped && s->inflight < DEPTH) {
			to_prep = min(DEPTH - s->inflight, BATCH_SUBMIT);
			prepped = prep_more_ios(s, fd, to_prep);
		}
		s->inflight += prepped;
submit_more:
		to_submit = prepped;
submit:
		if (s->inflight + BATCH_SUBMIT < DEPTH)
			to_wait = 0;
		else
			to_wait = min(s->inflight + to_submit, BATCH_COMPLETE);

		ret = io_uring_enter(s, to_submit, to_wait,
					IORING_ENTER_GETEVENTS);
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

static int setup_ring(struct submitter *s)
{
	struct io_sq_ring *sring = &s->sq_ring;
	struct io_cq_ring *cring = &s->cq_ring;
	struct io_uring_params p;
	void *ptr;
	int fd;

	memset(&p, 0, sizeof(p));

	if (polled)
		p.flags |= IORING_SETUP_IOPOLL;
	if (fixedbufs)
		p.flags |= IORING_SETUP_FIXEDBUFS;
	if (buffered)
		p.flags |= IORING_SETUP_SQWQ;
	else if (sq_thread) {
		p.flags |= IORING_SETUP_SQTHREAD;
		p.sq_thread_cpu = sq_thread_cpu;
	}

	if (fixedbufs)
		fd = io_uring_setup(DEPTH, s->iovecs, &p);
	else
		fd = io_uring_setup(DEPTH, NULL, &p);
	if (fd < 0) {
		perror("io_uring_setup");
		return 1;
	}

	s->ring_fd = fd;
	ptr = mmap(0, p.sq_off.array + p.sq_entries * sizeof(__u32),
			PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
			IORING_OFF_SQ_RING);
	printf("sq_ring ptr = 0x%p\n", ptr);
	sring->head = ptr + p.sq_off.head;
	sring->tail = ptr + p.sq_off.tail;
	sring->ring_mask = ptr + p.sq_off.ring_mask;
	sring->ring_entries = ptr + p.sq_off.ring_entries;
	sring->array = ptr + p.sq_off.array;
	sq_ring_mask = *sring->ring_mask;

	s->iocbs = mmap(0, p.sq_entries * sizeof(struct io_uring_iocb),
			PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
			IORING_OFF_IOCB);
	printf("iocbs ptr   = 0x%p\n", s->iocbs);

	ptr = mmap(0, p.cq_off.events + p.cq_entries * sizeof(struct io_uring_event),
			PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
			IORING_OFF_CQ_RING);
	printf("cq_ring ptr = 0x%p\n", ptr);
	cring->head = ptr + p.cq_off.head;
	cring->tail = ptr + p.cq_off.tail;
	cring->ring_mask = ptr + p.cq_off.ring_mask;
	cring->ring_entries = ptr + p.cq_off.ring_entries;
	cring->events = ptr + p.cq_off.events;
	cq_ring_mask = *cring->ring_mask;
	return 0;
}

int main(int argc, char *argv[])
{
	struct submitter *s = &submitters[0];
	unsigned long done, calls, reap, cache_hit, cache_miss;
	int err, i;
	struct rlimit rlim;
	void *ret;

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

	for (i = 0; i < DEPTH; i++) {
		void *buf;

		if (posix_memalign(&buf, BS, BS)) {
			printf("failed alloc\n");
			return 1;
		}
		s->iovecs[i].iov_base = buf;
		s->iovecs[i].iov_len = BS;
	}

	err = setup_ring(s);
	if (err) {
		printf("ring setup failed: %s, %d\n", strerror(errno), err);
		return 1;
	}
	printf("polled=%d, fixedbufs=%d, buffered=%d", polled, fixedbufs, buffered);
	printf(" QD=%d, sq_ring=%d, cq_ring=%d\n", DEPTH, *s->sq_ring.ring_entries, *s->cq_ring.ring_entries);
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
		printf("IOPS=%lu, IOS/call=%lu/%lu, inflight=%u (head=%u tail=%u), Cachehit=%0.2f%%\n",
				this_done - done, rpc, ipc, s->inflight,
				*s->cq_ring.head, *s->cq_ring.tail, hit);
		done = this_done;
		calls = this_call;
		reap = this_reap;
		cache_hit = s->cachehit;
		cache_miss = s->cachemiss;
	} while (!finish);

	pthread_join(s->thread, &ret);
	close(s->ring_fd);
	return 0;
}
