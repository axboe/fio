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

#ifdef CONFIG_LIBNUMA
#include <numa.h>
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
#include <libgen.h>

#include "../arch/arch.h"
#include "../os/os.h"
#include "../lib/types.h"
#include "../lib/roundup.h"
#include "../lib/rand.h"
#include "../minmax.h"
#include "../os/linux/io_uring.h"
#include "../engines/nvme.h"

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
	unsigned int nsid;	/* nsid field required for nvme-passthrough */
	unsigned int lba_shift;	/* lba_shift field required for nvme-passthrough */
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
	int enter_ring_fd;
	int index;
	struct io_sq_ring sq_ring;
	struct io_uring_sqe *sqes;
	struct io_cq_ring cq_ring;
	int inflight;
	int tid;
	unsigned long reaps;
	unsigned long done;
	unsigned long calls;
	unsigned long io_errors;
	volatile int finish;

	__s32 *fds;

	struct taus258_state rand_state;

	unsigned long *clock_batch;
	int clock_index;
	unsigned long *plat;

#ifdef CONFIG_LIBAIO
	io_context_t aio_ctx;
#endif

	int numa_node;
	int per_file_depth;
	const char *filename;

	struct file files[MAX_FDS];
	unsigned nr_files;
	unsigned cur_file;
	struct iovec iovecs[];
};

static struct submitter *submitter;
static volatile int finish;
static int stats_running;
static unsigned long max_iops;
static long t_io_uring_page_size;

static int depth = DEPTH;
static int batch_submit = BATCH_SUBMIT;
static int batch_complete = BATCH_COMPLETE;
static int bs = BS;
static int polled = 1;		/* use IO polling */
static int fixedbufs = 1;	/* use fixed user buffers */
static int register_files = 1;	/* use fixed files */
static int buffered = 0;	/* use buffered IO, not O_DIRECT */
static int sq_thread_poll = 0;	/* use kernel submission/poller thread */
static int sq_thread_cpu = -1;	/* pin above thread to this CPU */
static int do_nop = 0;		/* no-op SQ ring commands */
static int use_files = 1;
static int nthreads = 1;
static int stats = 0;		/* generate IO stats */
static int aio = 0;		/* use libaio */
static int runtime = 0;		/* runtime */
static int random_io = 1;	/* random or sequential IO */
static int register_ring = 1;	/* register ring */
static int use_sync = 0;	/* use preadv2 */
static int numa_placement = 0;	/* set to node of device */
static int vectored = 0;	/* use vectored IO */
static int pt = 0;		/* passthrough I/O or not */
static int restriction = 0;	/* for testing restriction filter */

static unsigned long tsc_rate;

#define TSC_RATE_FILE	"tsc-rate"

static float plist[] = { 1.0, 5.0, 10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0,
			80.0, 90.0, 95.0, 99.0, 99.5, 99.9, 99.95, 99.99 };
static int plist_len = 17;

static int nvme_identify(int fd, __u32 nsid, enum nvme_identify_cns cns,
			 enum nvme_csi csi, void *data)
{
	struct nvme_passthru_cmd cmd = {
		.opcode         = nvme_admin_identify,
		.nsid           = nsid,
		.addr           = (__u64)(uintptr_t)data,
		.data_len       = NVME_IDENTIFY_DATA_SIZE,
		.cdw10          = cns,
		.cdw11          = csi << NVME_IDENTIFY_CSI_SHIFT,
		.timeout_ms     = NVME_DEFAULT_IOCTL_TIMEOUT,
	};

	return ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
}

static int nvme_get_info(int fd, __u32 *nsid, __u32 *lba_sz, __u64 *nlba)
{
	struct nvme_id_ns ns;
	int namespace_id;
	int err;

	namespace_id = ioctl(fd, NVME_IOCTL_ID);
	if (namespace_id < 0) {
		fprintf(stderr, "error failed to fetch namespace-id\n");
		close(fd);
		return -errno;
	}

	/*
	 * Identify namespace to get namespace-id, namespace size in LBA's
	 * and LBA data size.
	 */
	err = nvme_identify(fd, namespace_id, NVME_IDENTIFY_CNS_NS,
				NVME_CSI_NVM, &ns);
	if (err) {
		fprintf(stderr, "error failed to fetch identify namespace\n");
		close(fd);
		return err;
	}

	*nsid = namespace_id;
	*lba_sz = 1 << ns.lbaf[(ns.flbas & 0x0f)].ds;
	*nlba = ns.nsze;

	return 0;
}

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

unsigned int calculate_clat_percentiles(unsigned long *io_u_plat,
		unsigned long nr, unsigned long **output,
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

	len = calculate_clat_percentiles(io_u_plat, nr, &ovals, &maxv, &minv);
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

static int io_uring_register_buffers(struct submitter *s)
{
	int ret;

	/*
	 * All iovecs are filled in case of readv, but it's all contig
	 * from vec0. Just register a single buffer for all buffers.
	 */
	s->iovecs[0].iov_len = bs * roundup_pow2(depth);
	ret = syscall(__NR_io_uring_register, s->ring_fd,
			IORING_REGISTER_BUFFERS, s->iovecs, 1);
	s->iovecs[0].iov_len = bs;
	return ret;
}

static int io_uring_register_files(struct submitter *s)
{
	int i;

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
	int ret;

	/*
	 * Clamp CQ ring size at our SQ ring size, we don't need more entries
	 * than that.
	 */
	p->flags |= IORING_SETUP_CQSIZE;
	p->cq_entries = entries;

	p->flags |= IORING_SETUP_COOP_TASKRUN;
	p->flags |= IORING_SETUP_SINGLE_ISSUER;
	p->flags |= IORING_SETUP_DEFER_TASKRUN;
	p->flags |= IORING_SETUP_NO_SQARRAY;
retry:
	ret = syscall(__NR_io_uring_setup, entries, p);
	if (!ret)
		return 0;

	if (errno == EINVAL && p->flags & IORING_SETUP_COOP_TASKRUN) {
		p->flags &= ~IORING_SETUP_COOP_TASKRUN;
		goto retry;
	}
	if (errno == EINVAL && p->flags & IORING_SETUP_SINGLE_ISSUER) {
		p->flags &= ~IORING_SETUP_SINGLE_ISSUER;
		goto retry;
	}
	if (errno == EINVAL && p->flags & IORING_SETUP_DEFER_TASKRUN) {
		p->flags &= ~IORING_SETUP_DEFER_TASKRUN;
		goto retry;
	}
	if (errno == EINVAL && p->flags & IORING_SETUP_NO_SQARRAY) {
		p->flags &= ~IORING_SETUP_NO_SQARRAY;
		goto retry;
	}

	return ret;
}

static int io_uring_enter(struct submitter *s, unsigned int to_submit,
			  unsigned int min_complete, unsigned int flags)
{
	if (register_ring)
		flags |= IORING_ENTER_REGISTERED_RING;
#ifdef FIO_ARCH_HAS_SYSCALL
	return __do_syscall6(__NR_io_uring_enter, s->enter_ring_fd, to_submit,
				min_complete, flags, NULL, 0);
#else
	return syscall(__NR_io_uring_enter, s->enter_ring_fd, to_submit,
			min_complete, flags, NULL, 0);
#endif
}

static unsigned long long get_offset(struct submitter *s, struct file *f)
{
	unsigned long long offset;
	long r;

	if (random_io) {
		unsigned long long block;

		r = __rand64(&s->rand_state);
		block = r % f->max_blocks;
		offset = block * (unsigned long long) bs;
	} else {
		offset = f->cur_off;
		f->cur_off += bs;
		if (f->cur_off + bs > f->max_size)
			f->cur_off = 0;
	}

	return offset;
}

static struct file *get_next_file(struct submitter *s)
{
	struct file *f;

	if (s->nr_files == 1) {
		f = &s->files[0];
	} else {
		f = &s->files[s->cur_file];
		if (f->pending_ios >= s->per_file_depth) {
			s->cur_file++;
			if (s->cur_file == s->nr_files)
				s->cur_file = 0;
			f = &s->files[s->cur_file];
		}
	}

	f->pending_ios++;
	return f;
}

static void init_io(struct submitter *s, unsigned index)
{
	struct io_uring_sqe *sqe = &s->sqes[index];
	struct file *f;

	f = get_next_file(s);

	if (do_nop) {
		sqe->rw_flags = IORING_NOP_FILE;
		if (register_files) {
			sqe->fd = f->fixed_fd;
			sqe->rw_flags |= IORING_NOP_FIXED_FILE;
		} else {
			sqe->fd = f->real_fd;
		}
		if (fixedbufs)
			sqe->rw_flags |= IORING_NOP_FIXED_BUFFER;
		sqe->rw_flags |= IORING_NOP_INJECT_RESULT;
		sqe->len = bs;
		sqe->opcode = IORING_OP_NOP;
		return;
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
		sqe->buf_index = 0;
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
	sqe->off = get_offset(s, f);
	sqe->user_data = (unsigned long) f->fileno;
	if (stats && stats_running)
		sqe->user_data |= ((uint64_t)s->clock_index << 32);
}

static void init_io_pt(struct submitter *s, unsigned index)
{
	struct io_uring_sqe *sqe = &s->sqes[index << 1];
	unsigned long offset;
	struct file *f;
	struct nvme_uring_cmd *cmd;
	unsigned long long slba;
	unsigned long long nlb;

	f = get_next_file(s);

	offset = get_offset(s, f);

	if (register_files) {
		sqe->fd = f->fixed_fd;
		sqe->flags = IOSQE_FIXED_FILE;
	} else {
		sqe->fd = f->real_fd;
		sqe->flags = 0;
	}
	sqe->opcode = IORING_OP_URING_CMD;
	sqe->user_data = (unsigned long) f->fileno;
	if (stats)
		sqe->user_data |= ((__u64) s->clock_index << 32ULL);
	sqe->cmd_op = NVME_URING_CMD_IO;
	slba = offset >> f->lba_shift;
	nlb = (bs >> f->lba_shift) - 1;
	cmd = (struct nvme_uring_cmd *)&sqe->cmd;
	/* cdw10 and cdw11 represent starting slba*/
	cmd->cdw10 = slba & 0xffffffff;
	cmd->cdw11 = slba >> 32;
	/* cdw12 represent number of lba to be read*/
	cmd->cdw12 = nlb;
	cmd->addr = (unsigned long) s->iovecs[index].iov_base;
	cmd->data_len = bs;
	if (fixedbufs) {
		sqe->uring_cmd_flags = IORING_URING_CMD_FIXED;
		sqe->buf_index = 0;
	}
	if (vectored) {
		sqe->cmd_op = NVME_URING_CMD_IO_VEC;
		cmd->addr = (unsigned long) &s->iovecs[index];
		cmd->data_len = 1;
		sqe->buf_index = 0;
	}
	cmd->nsid = f->nsid;
	cmd->opcode = 2;
}

static int prep_more_ios_uring(struct submitter *s, int max_ios)
{
	struct io_sq_ring *ring = &s->sq_ring;
	unsigned head, index, tail, next_tail, prepped = 0;

	if (sq_thread_poll)
		head = atomic_load_acquire(ring->head);
	else
		head = *ring->head;

	next_tail = tail = *ring->tail;
	do {
		next_tail++;
		if (next_tail == head)
			break;

		index = tail & sq_ring_mask;
		if (pt)
			init_io_pt(s, index);
		else
			init_io(s, index);
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
	if (pt) {
		__u64 nlba;
		__u32 lbs;
		int ret;

		if (!S_ISCHR(st.st_mode)) {
			fprintf(stderr, "passthrough works with only nvme-ns "
					"generic devices (/dev/ngXnY)\n");
			return -1;
		}
		ret = nvme_get_info(f->real_fd, &f->nsid, &lbs, &nlba);
		if (ret)
			return -1;
		if ((bs % lbs) != 0) {
			printf("error: bs:%d should be a multiple logical_block_size:%d\n",
					bs, lbs);
			return -1;
		}
		f->max_blocks = nlba;
		f->max_size = nlba;
		f->lba_shift = ilog2(lbs);
		return 0;
	} else if (S_ISBLK(st.st_mode)) {
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
	unsigned tail, head, reaped = 0;
	int last_idx = -1, stat_nr = 0;

	head = *ring->head;
	tail = atomic_load_acquire(ring->tail);
	do {
		struct file *f;

		if (head == tail)
			break;
		cqe = &ring->cqes[head & cq_ring_mask];
		if (use_files) {
			int fileno = cqe->user_data & 0xffffffff;

			f = &s->files[fileno];
			f->pending_ios--;
			if (cqe->res != bs) {
				if (cqe->res == -ENODATA || cqe->res == -EIO) {
					s->io_errors++;
				} else {
					printf("io: unexpected ret=%d\n", cqe->res);
					if (polled && cqe->res == -EOPNOTSUPP)
						printf("Your filesystem/driver/kernel doesn't support polled IO\n");
					return -1;
				}
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

static int reap_events_uring_pt(struct submitter *s)
{
	struct io_cq_ring *ring = &s->cq_ring;
	struct io_uring_cqe *cqe;
	unsigned head, tail, reaped = 0;
	int last_idx = -1, stat_nr = 0;
	unsigned index;
	int fileno;

	head = *ring->head;
	tail = atomic_load_acquire(ring->tail);
	do {
		struct file *f;

		if (head == tail)
			break;
		index = head & cq_ring_mask;
		cqe = &ring->cqes[index << 1];
		fileno = cqe->user_data & 0xffffffff;
		f = &s->files[fileno];
		f->pending_ios--;

		if (cqe->res != 0) {
			printf("io: unexpected ret=%d\n", cqe->res);
			if (polled && cqe->res == -EINVAL)
				printf("passthrough doesn't support polled IO\n");
			return -1;
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

static void set_affinity(struct submitter *s)
{
#ifdef CONFIG_LIBNUMA
	struct bitmask *mask;

	if (s->numa_node == -1)
		return;

	numa_set_preferred(s->numa_node);

	mask = numa_allocate_cpumask();
	numa_node_to_cpus(s->numa_node, mask);
	numa_sched_setaffinity(s->tid, mask);
#endif
}

static int detect_node(struct submitter *s, char *name)
{
#ifdef CONFIG_LIBNUMA
	const char *base = basename(name);
	char str[128];
	int ret, fd, node;

	if (pt)
		sprintf(str, "/sys/class/nvme-generic/%s/device/numa_node", base);
	else
		sprintf(str, "/sys/block/%s/device/numa_node", base);
	fd = open(str, O_RDONLY);
	if (fd < 0)
		return -1;

	ret = read(fd, str, sizeof(str));
	if (ret < 0) {
		close(fd);
		return -1;
	}
	node = atoi(str);
	s->numa_node = node;
	close(fd);
#else
	s->numa_node = -1;
#endif
	return 0;
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

	s->per_file_depth = (depth + s->nr_files - 1) / s->nr_files;
	return io_queue_init(roundup_pow2(depth), &s->aio_ctx);
#else
	fprintf(stderr, "Legacy AIO not available on this system/build\n");
	errno = EINVAL;
	return -1;
#endif
}

static int io_uring_register_restrictions(struct submitter *s)
{
	struct io_uring_restriction res[8] = { };
	int ret;

	res[0].opcode = IORING_RESTRICTION_SQE_OP;
	res[0].sqe_op = IORING_OP_NOP;
	res[1].opcode = IORING_RESTRICTION_SQE_OP;
	res[1].sqe_op = IORING_OP_READ;
	res[2].opcode = IORING_RESTRICTION_SQE_OP;
	res[2].sqe_op = IORING_OP_READV;
	res[3].opcode = IORING_RESTRICTION_SQE_OP;
	res[3].sqe_op = IORING_OP_READ_FIXED;

	res[4].opcode = IORING_RESTRICTION_REGISTER_OP;
	res[4].sqe_op = IORING_REGISTER_BUFFERS;
	res[5].opcode = IORING_RESTRICTION_REGISTER_OP;
	res[5].sqe_op = IORING_REGISTER_ENABLE_RINGS;
	res[6].opcode = IORING_RESTRICTION_REGISTER_OP;
	res[6].sqe_op = IORING_REGISTER_RING_FDS;
	res[7].opcode = IORING_RESTRICTION_REGISTER_OP;
	res[7].sqe_op = IORING_REGISTER_FILES;

	ret = syscall(__NR_io_uring_register, s->ring_fd,
			IORING_REGISTER_RESTRICTIONS, res, 8);
	if (ret) {
		fprintf(stderr, "IORING_REGISTER_RESTRICTIONS: %d\n", ret);
		return ret;
	}

	return syscall(__NR_io_uring_register, s->ring_fd, IORING_REGISTER_ENABLE_RINGS, NULL, 0);
}

static int setup_ring(struct submitter *s)
{
	struct io_sq_ring *sring = &s->sq_ring;
	struct io_cq_ring *cring = &s->cq_ring;
	struct io_uring_params p;
	int ret, fd, i;
	void *ptr;
	size_t len;

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
	if (pt) {
		p.flags |= IORING_SETUP_SQE128;
		p.flags |= IORING_SETUP_CQE32;
	}
	if (restriction)
		p.flags |= IORING_SETUP_R_DISABLED;

	fd = io_uring_setup(depth, &p);
	if (fd < 0) {
		perror("io_uring_setup");
		return 1;
	}
	s->ring_fd = s->enter_ring_fd = fd;

	if (restriction) {
		/* enables rings too */
		ret = io_uring_register_restrictions(s);
		if (ret) {
			fprintf(stderr, "Failed to set restrictions\n");
			return ret;
		}
	}

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
	sq_ring_mask = *sring->ring_mask;

	if (!(p.flags & IORING_SETUP_NO_SQARRAY)) {
		sring->array = ptr + p.sq_off.array;
		for (i = 0; i < p.sq_entries; i++)
			sring->array[i] = i;
	}

	if (p.flags & IORING_SETUP_SQE128)
		len = 2 * p.sq_entries * sizeof(struct io_uring_sqe);
	else
		len = p.sq_entries * sizeof(struct io_uring_sqe);
	s->sqes = mmap(0, len,
			PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
			IORING_OFF_SQES);

	if (p.flags & IORING_SETUP_CQE32) {
		len = p.cq_off.cqes +
			2 * p.cq_entries * sizeof(struct io_uring_cqe);
	} else {
		len = p.cq_off.cqes +
			p.cq_entries * sizeof(struct io_uring_cqe);
	}
	ptr = mmap(0, len,
			PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
			IORING_OFF_CQ_RING);
	cring->head = ptr + p.cq_off.head;
	cring->tail = ptr + p.cq_off.tail;
	cring->ring_mask = ptr + p.cq_off.ring_mask;
	cring->ring_entries = ptr + p.cq_off.ring_entries;
	cring->cqes = ptr + p.cq_off.cqes;
	cq_ring_mask = *cring->ring_mask;

	s->per_file_depth = INT_MAX;
	if (s->nr_files)
		s->per_file_depth = (depth + s->nr_files - 1) / s->nr_files;
	return 0;
}

static void *allocate_mem(struct submitter *s, int size)
{
	void *buf;

#ifdef CONFIG_LIBNUMA
	if (s->numa_node != -1)
		return numa_alloc_onnode(size, s->numa_node);
#endif

	if (posix_memalign(&buf, t_io_uring_page_size, size)) {
		printf("failed alloc\n");
		return NULL;
	}

	return buf;
}

static int submitter_init(struct submitter *s)
{
	int i, nr_batch, err;
	static int init_printed;
	void *mem, *ptr;
	char buf[80];

	s->tid = gettid();
	printf("submitter=%d, tid=%d, file=%s, nfiles=%d, node=%d\n", s->index,
				s->tid, s->filename, s->nr_files, s->numa_node);

	set_affinity(s);

	__init_rand64(&s->rand_state, s->tid);
	srand48(s->tid);

	for (i = 0; i < MAX_FDS; i++)
		s->files[i].fileno = i;

	mem = allocate_mem(s, bs * roundup_pow2(depth));
	for (i = 0, ptr = mem; i < roundup_pow2(depth); i++) {
		s->iovecs[i].iov_base = ptr;
		s->iovecs[i].iov_len = bs;
		ptr += bs;
	}

	if (use_sync) {
		sprintf(buf, "Engine=preadv2\n");
		err = 0;
	} else if (!aio) {
		err = setup_ring(s);
		if (!err)
			sprintf(buf, "Engine=io_uring, sq_ring=%d, cq_ring=%d\n", *s->sq_ring.ring_entries, *s->cq_ring.ring_entries);
	} else {
		sprintf(buf, "Engine=aio\n");
		err = setup_aio(s);
	}
	if (err) {
		printf("queue setup failed: %s, %d\n", strerror(errno), err);
		return -1;
	}

	if (!init_printed) {
		printf("polled=%d, fixedbufs=%d, register_files=%d, buffered=%d, QD=%d\n", polled, fixedbufs, register_files, buffered, depth);
		printf("%s", buf);
		init_printed = 1;
	}

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
	/* perform the expensive command initialization part for passthrough here
	 * rather than in the fast path
	 */
	if (pt) {
		for (i = 0; i < roundup_pow2(depth); i++) {
			struct io_uring_sqe *sqe = &s->sqes[i << 1];

			memset(&sqe->cmd, 0, sizeof(struct nvme_uring_cmd));
		}
	}
	return nr_batch;
}

#ifdef CONFIG_LIBAIO
static int prep_more_ios_aio(struct submitter *s, int max_ios, struct iocb *iocbs)
{
	uint64_t data;
	struct file *f;
	unsigned index;

	index = 0;
	while (index < max_ios) {
		struct iocb *iocb = &iocbs[index];

		f = get_next_file(s);

		io_prep_pread(iocb, f->real_fd, s->iovecs[index].iov_base,
				s->iovecs[index].iov_len, get_offset(s, f));

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
			if (events[reaped].res == -ENODATA ||
			    events[reaped].res == -EIO) {
				s->io_errors++;
			} else {
				printf("io: unexpected ret=%ld\n", events[reaped].res);
				return -1;
			}
		} else if (stats) {
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
	int nr_batch;
#endif

	ret = submitter_init(s);
	if (ret < 0)
		goto done;

#ifdef ARCH_HAVE_CPU_CLOCK
	nr_batch = ret;
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
done:
	finish = 1;
	return NULL;
}
#endif

static void io_uring_unregister_ring(struct submitter *s)
{
	struct io_uring_rsrc_update up = {
		.offset	= s->enter_ring_fd,
	};

	syscall(__NR_io_uring_register, s->ring_fd, IORING_UNREGISTER_RING_FDS,
		&up, 1);
}

static int io_uring_register_ring(struct submitter *s)
{
	struct io_uring_rsrc_update up = {
		.data	= s->ring_fd,
		.offset	= -1U,
	};
	int ret;

	ret = syscall(__NR_io_uring_register, s->ring_fd,
			IORING_REGISTER_RING_FDS, &up, 1);
	if (ret == 1) {
		s->enter_ring_fd = up.offset;
		return 0;
	}
	register_ring = 0;
	return -1;
}

static void *submitter_uring_fn(void *data)
{
	struct submitter *s = data;
	struct io_sq_ring *ring = &s->sq_ring;
	int ret, prepped;
#ifdef ARCH_HAVE_CPU_CLOCK
	int nr_batch;
#endif

	ret = submitter_init(s);
	if (ret < 0)
		goto done;

#ifdef ARCH_HAVE_CPU_CLOCK
	nr_batch = ret;
#endif

	if (register_ring)
		io_uring_register_ring(s);

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

			if (pt)
				r = reap_events_uring_pt(s);
			else
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

	if (register_ring)
		io_uring_unregister_ring(s);

done:
	finish = 1;
	return NULL;
}

#ifdef CONFIG_PWRITEV2
static void *submitter_sync_fn(void *data)
{
	struct submitter *s = data;
	int ret;

	if (submitter_init(s) < 0)
		goto done;

	do {
		uint64_t offset;
		struct file *f;

		f = get_next_file(s);

#ifdef ARCH_HAVE_CPU_CLOCK
		if (stats)
			s->clock_batch[s->clock_index] = get_cpu_clock();
#endif

		s->inflight++;
		s->calls++;

		offset = get_offset(s, f);
		if (polled)
			ret = preadv2(f->real_fd, &s->iovecs[0], 1, offset, RWF_HIPRI);
		else
			ret = preadv2(f->real_fd, &s->iovecs[0], 1, offset, 0);

		if (ret < 0) {
			perror("preadv2");
			break;
		} else if (ret != bs) {
			break;
		}

		s->done++;
		s->inflight--;
		f->pending_ios--;
		if (stats)
			add_stat(s, s->clock_index, 1);
	} while (!s->finish);

done:
	finish = 1;
	return NULL;
}
#else
static void *submitter_sync_fn(void *data)
{
	finish = 1;
	return NULL;
}
#endif

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
	if (max_iops > 1000000) {
		double miops = (double) max_iops / 1000000.0;
		printf("Maximum IOPS=%.2fM\n", miops);
	} else if (max_iops > 100000) {
		double kiops = (double) max_iops / 1000.0;
		printf("Maximum IOPS=%.2fK\n", kiops);
	} else {
		printf("Maximum IOPS=%lu\n", max_iops);
	}
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
		" -F <bool> : Register files, default %d\n"
		" -n <int>  : Number of threads, default %d\n"
		" -O <bool> : Use O_DIRECT, default %d\n"
		" -N <bool> : Perform just no-op requests, default %d\n"
		" -t <bool> : Track IO latencies, default %d\n"
		" -T <int>  : TSC rate in HZ\n"
		" -r <int>  : Runtime in seconds, default %s\n"
		" -R <bool> : Use random IO, default %d\n"
		" -a <bool> : Use legacy aio, default %d\n"
		" -S <bool> : Use sync IO (preadv2), default %d\n"
		" -X <bool> : Use registered ring %d\n"
		" -P <bool> : Automatically place on device home node %d\n"
		" -V <bool> : Vectored IO, default %d\n"
		" -e <bool> : Set restriction filter on opcodes %d\n"
		" -u <bool> : Use nvme-passthrough I/O, default %d\n",
		argv, DEPTH, BATCH_SUBMIT, BATCH_COMPLETE, BS, polled,
		fixedbufs, register_files, nthreads, !buffered, do_nop,
		stats, runtime == 0 ? "unlimited" : runtime_str, random_io, aio,
		use_sync, register_ring, numa_placement, vectored, restriction,
		pt);
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
	unsigned long done, calls, reap, io_errors;
	int i, j, flags, fd, opt, threads_per_f, threads_rem = 0, nfiles;
	struct file f;
	void *ret;

	if (!do_nop && argc < 2)
		usage(argv[0], 1);

	while ((opt = getopt(argc, argv, "e:d:s:c:b:p:B:F:n:N:O:t:T:a:r:D:R:X:S:P:V:u:h?")) != -1) {
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
		case 'R':
			random_io = !!atoi(optarg);
			break;
		case 'X':
			register_ring = !!atoi(optarg);
			break;
		case 'S':
#ifdef CONFIG_PWRITEV2
			use_sync = !!atoi(optarg);
#else
			fprintf(stderr, "preadv2 not supported\n");
			exit(1);
#endif
			break;
		case 'P':
			numa_placement = !!atoi(optarg);
			break;
		case 'V':
			vectored = !!atoi(optarg);
			break;
		case 'u':
			pt = !!atoi(optarg);
			break;
		case 'e':
			restriction = !!atoi(optarg);
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

	submitter = calloc(nthreads, sizeof(*submitter) +
				roundup_pow2(depth) * sizeof(struct iovec));
	for (j = 0; j < nthreads; j++) {
		s = get_submitter(j);
		s->numa_node = -1;
		s->index = j;
		s->done = s->calls = s->reaps = s->io_errors = 0;
	}

	flags = O_RDONLY | O_NOATIME;
	if (!buffered)
		flags |= O_DIRECT;

	j = 0;
	i = optind;
	nfiles = argc - i;
	if (use_files) {
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
	while (use_files && i < argc) {
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

			if (numa_placement)
				detect_node(s, argv[i]);

			s->filename = argv[i];
			s->nr_files++;
		}
		threads_rem--;
		i++;
		j += limit;
	}

	arm_sig_int();

	t_io_uring_page_size = sysconf(_SC_PAGESIZE);
	if (t_io_uring_page_size < 0)
		t_io_uring_page_size = 4096;

	for (j = 0; j < nthreads; j++) {
		s = get_submitter(j);
		if (use_sync)
			pthread_create(&s->thread, NULL, submitter_sync_fn, s);
		else if (!aio)
			pthread_create(&s->thread, NULL, submitter_uring_fn, s);
#ifdef CONFIG_LIBAIO
		else
			pthread_create(&s->thread, NULL, submitter_aio_fn, s);
#endif
	}

	reap = calls = done = io_errors = 0;
	do {
		unsigned long this_done = 0;
		unsigned long this_reap = 0;
		unsigned long this_call = 0;
		unsigned long this_io_errors = 0;
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
			this_io_errors += s->io_errors;
		}
		if (this_call - calls) {
			rpc = (this_done - done) / (this_call - calls);
			ipc = (this_reap - reap) / (this_call - calls);
		} else
			rpc = ipc = -1;
		iops = this_done - done;
		iops -= this_io_errors - io_errors;
		if (bs > 1048576)
			bw = iops * (bs / 1048576);
		else
			bw = iops / (1048576 / bs);
		if (iops > 1000000) {
			double miops = (double) iops / 1000000.0;
			printf("IOPS=%.2fM, ", miops);
		} else if (iops > 100000) {
			double kiops = (double) iops / 1000.0;
			printf("IOPS=%.2fK, ", kiops);
		} else {
			printf("IOPS=%lu, ", iops);
		}
		max_iops = max(max_iops, iops);
		if (!do_nop) {
			if (bw > 2000) {
				double bw_g = (double) bw / 1000.0;

				printf("BW=%.2fGiB/s, ", bw_g);
			} else {
				printf("BW=%luMiB/s, ", bw);
			}
		}
		printf("IOS/call=%ld/%ld\n", rpc, ipc);
		done = this_done;
		calls = this_call;
		reap = this_reap;
		io_errors = this_io_errors;
	} while (!finish);

	for (j = 0; j < nthreads; j++) {
		s = get_submitter(j);
		pthread_join(s->thread, &ret);
		close(s->ring_fd);

		if (s->io_errors)
			printf("%d: %lu IO errors\n", s->tid, s->io_errors);

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

	free(submitter);
	return 0;
}
