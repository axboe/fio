#include <stdio.h>
#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <assert.h>

#include "../io_ddir.h"
#include "../flist.h"
#include "../hash.h"
#include "../fifo.h"
#include "../blktrace_api.h"
#include "../os/os.h"
#include "../log.h"
#include "../lib/linux-dev-lookup.h"

#define TRACE_FIFO_SIZE	8192

static unsigned int rt_threshold = 1000000;
static unsigned int ios_threshold = 10;
static int output_ascii = 1;
static char *filename;

struct bs {
	unsigned int bs;
	unsigned int nr;
	int merges;
};

struct trace_file {
	char *name;
	int major, minor;
};

struct btrace_out {
	unsigned long ios[DDIR_RWDIR_CNT];
	unsigned long rw_bs[DDIR_RWDIR_CNT];
	unsigned long merges[DDIR_RWDIR_CNT];

	uint64_t last_end[DDIR_RWDIR_CNT];
	uint64_t seq[DDIR_RWDIR_CNT];

	struct bs *bs[DDIR_RWDIR_CNT];
	unsigned int nr_bs[DDIR_RWDIR_CNT];

	int inflight;
	unsigned int depth;
	uint64_t first_ttime;
	uint64_t last_ttime;

	struct trace_file *files;
	int nr_files;
	unsigned int last_major, last_minor;

	uint64_t start_delay;
};

struct btrace_pid {
	struct flist_head hash_list;
	struct flist_head pid_list;
	pid_t pid;
	struct btrace_out o;
};

struct inflight {
	struct flist_head list;
	struct btrace_pid *p;
	uint64_t end_sector;
};

#define PID_HASH_BITS	10
#define PID_HASH_SIZE	(1U << PID_HASH_BITS)

static struct flist_head pid_hash[PID_HASH_SIZE];
static FLIST_HEAD(pid_list);

static FLIST_HEAD(inflight_list);

static uint64_t first_ttime = -1ULL;

static struct inflight *inflight_find(uint64_t sector)
{
	struct flist_head *e;

	flist_for_each(e, &inflight_list) {
		struct inflight *i = flist_entry(e, struct inflight, list);

		if (i->end_sector == sector)
			return i;
	}

	return NULL;
}

static void inflight_remove(struct inflight *i)
{
	struct btrace_out *o = &i->p->o;

	o->inflight--;
	assert(o->inflight >= 0);
	flist_del(&i->list);
	free(i);
}

static void inflight_merge(struct inflight *i, int rw, unsigned int size)
{
	i->p->o.merges[rw]++;
	if (size)
		i->end_sector += (size >> 9);
}

static void inflight_add(struct btrace_pid *p, uint64_t sector, uint32_t len)
{
	struct btrace_out *o = &p->o;
	struct inflight *i;

	i = calloc(1, sizeof(*i));
	i->p = p;
	o->inflight++;
	o->depth = max((int) o->depth, o->inflight);
	i->end_sector = sector + (len >> 9);
	flist_add_tail(&i->list, &inflight_list);
}

/*
 * fifo refill frontend, to avoid reading data in trace sized bites
 */
static int refill_fifo(struct fifo *fifo, int fd)
{
	char buf[TRACE_FIFO_SIZE];
	unsigned int total;
	int ret;

	total = sizeof(buf);
	if (total > fifo_room(fifo))
		total = fifo_room(fifo);

	ret = read(fd, buf, total);
	if (ret < 0) {
		perror("read refill");
		return -1;
	}

	if (ret > 0)
		ret = fifo_put(fifo, buf, ret);

	return ret;
}

/*
 * Retrieve 'len' bytes from the fifo, refilling if necessary.
 */
static int trace_fifo_get(struct fifo *fifo, int fd, void *buf,
			  unsigned int len)
{
	if (fifo_len(fifo) < len) {
		int ret = refill_fifo(fifo, fd);

		if (ret < 0)
			return ret;
	}

	return fifo_get(fifo, buf, len);
}

/*
 * Just discard the pdu by seeking past it.
 */
static int discard_pdu(struct fifo *fifo, int fd, struct blk_io_trace *t)
{
	if (t->pdu_len == 0)
		return 0;

	return trace_fifo_get(fifo, fd, NULL, t->pdu_len);
}

static void handle_trace_notify(struct blk_io_trace *t)
{
	switch (t->action) {
	case BLK_TN_PROCESS:
		//printf("got process notify: %x, %d\n", t->action, t->pid);
		break;
	case BLK_TN_TIMESTAMP:
		//printf("got timestamp notify: %x, %d\n", t->action, t->pid);
		break;
	case BLK_TN_MESSAGE:
		break;
	default:
		fprintf(stderr, "unknown trace act %x\n", t->action);
		break;
	}
}

static void __add_bs(struct btrace_out *o, unsigned int len, int rw)
{
	o->bs[rw] = realloc(o->bs[rw], (o->nr_bs[rw] + 1) * sizeof(struct bs));
	o->bs[rw][o->nr_bs[rw]].bs = len;
	o->bs[rw][o->nr_bs[rw]].nr = 1;
	o->nr_bs[rw]++;
}

static void add_bs(struct btrace_out *o, unsigned int len, int rw)
{
	struct bs *bs = o->bs[rw];
	int i;

	if (!o->nr_bs[rw]) {
		__add_bs(o, len, rw);
		return;
	}

	for (i = 0; i < o->nr_bs[rw]; i++) {
		if (bs[i].bs == len) {
			bs[i].nr++;
			return;
		}
	}

	__add_bs(o, len, rw);
}

#define FMINORBITS	20
#define FMINORMASK	((1U << FMINORBITS) - 1)
#define FMAJOR(dev)	((unsigned int) ((dev) >> FMINORBITS))
#define FMINOR(dev)	((unsigned int) ((dev) & FMINORMASK))

static void btrace_add_file(struct btrace_out *o, uint32_t devno)
{
	unsigned int maj = FMAJOR(devno);
	unsigned int min = FMINOR(devno);
	struct trace_file *f;
	unsigned int i;
	char dev[256];

	if (filename)
		return;
	if (o->last_major == maj && o->last_minor == min)
		return;

	o->last_major = maj;
	o->last_minor = min;

	/*
	 * check for this file in our list
	 */
	for (i = 0; i < o->nr_files; i++) {
		f = &o->files[i];

		if (f->major == maj && f->minor == min)
			return;
	}

	strcpy(dev, "/dev");
	if (!blktrace_lookup_device(NULL, dev, maj, min)) {
		log_err("fio: failed to find device %u/%u\n", maj, min);
		return;
	}

	o->files = realloc(o->files, (o->nr_files + 1) * sizeof(*f));
	f = &o->files[o->nr_files];
	f->name = strdup(dev);
	f->major = maj;
	f->minor = min;
	o->nr_files++;
}

static void handle_trace_discard(struct blk_io_trace *t, struct btrace_out *o)
{
	btrace_add_file(o, t->device);

	if (o->first_ttime == -1ULL)
		o->first_ttime = t->time;

	o->ios[DDIR_TRIM]++;
	add_bs(o, t->bytes, DDIR_TRIM);
}

static void handle_trace_fs(struct blk_io_trace *t, struct btrace_out *o)
{
	int rw;

	btrace_add_file(o, t->device);

	first_ttime = min(first_ttime, (uint64_t) t->time);

	if (o->first_ttime == -1ULL)
		o->first_ttime = t->time;

	rw = (t->action & BLK_TC_ACT(BLK_TC_WRITE)) != 0;

	add_bs(o, t->bytes, rw);
	o->ios[rw]++;

	if (t->sector == o->last_end[rw] || o->last_end[rw] == -1ULL)
		o->seq[rw]++;

	o->last_end[rw] = t->sector + (t->bytes >> 9);
}

static void handle_queue_trace(struct blk_io_trace *t, struct btrace_out *o)
{
	if (t->action & BLK_TC_ACT(BLK_TC_NOTIFY))
		handle_trace_notify(t);
	else if (t->action & BLK_TC_ACT(BLK_TC_DISCARD))
		handle_trace_discard(t, o);
	else
		handle_trace_fs(t, o);
}

static void handle_trace(struct blk_io_trace *t, struct btrace_pid *p)
{
	unsigned int act = t->action & 0xffff;

	if (act == __BLK_TA_QUEUE) {
		inflight_add(p, t->sector, t->bytes);
		handle_queue_trace(t, &p->o);
	} else if (act == __BLK_TA_REQUEUE) {
		p->o.inflight--;
	} else if (act == __BLK_TA_BACKMERGE) {
		struct inflight *i;

		i = inflight_find(t->sector + (t->bytes >> 9));
		if (i)
			inflight_remove(i);

		i = inflight_find(t->sector);
		if (i) {
			int rw = (t->action & BLK_TC_ACT(BLK_TC_WRITE)) != 0;

			inflight_merge(i, rw, t->bytes);
		}
	} else if (act == __BLK_TA_FRONTMERGE) {
		struct inflight *i;

		i = inflight_find(t->sector + (t->bytes >> 9));
		if (i)
			inflight_remove(i);

		i = inflight_find(t->sector);
		if (i) {
			int rw = (t->action & BLK_TC_ACT(BLK_TC_WRITE)) != 0;

			inflight_merge(i, rw, 0);
		}
	} else if (act == __BLK_TA_COMPLETE) {
		struct inflight *i;

		i = inflight_find(t->sector + (t->bytes >> 9));
		if (i)
			inflight_remove(i);
	}
}

static void byteswap_trace(struct blk_io_trace *t)
{
	t->magic = fio_swap32(t->magic);
	t->sequence = fio_swap32(t->sequence);
	t->time = fio_swap64(t->time);
	t->sector = fio_swap64(t->sector);
	t->bytes = fio_swap32(t->bytes);
	t->action = fio_swap32(t->action);
	t->pid = fio_swap32(t->pid);
	t->device = fio_swap32(t->device);
	t->cpu = fio_swap32(t->cpu);
	t->error = fio_swap16(t->error);
	t->pdu_len = fio_swap16(t->pdu_len);
}

static struct btrace_pid *pid_hash_find(pid_t pid, struct flist_head *list)
{
	struct flist_head *e;
	struct btrace_pid *p;

	flist_for_each(e, list) {
		p = flist_entry(e, struct btrace_pid, hash_list);
		if (p->pid == pid)
			return p;
	}

	return NULL;
}

static struct btrace_pid *pid_hash_get(pid_t pid)
{
	struct flist_head *hash_list;
	struct btrace_pid *p;

	hash_list = &pid_hash[hash_long(pid, PID_HASH_BITS)];

	p = pid_hash_find(pid, hash_list);
	if (!p) {
		int i;

		p = calloc(1, sizeof(*p));
		p->o.first_ttime = -1ULL;
		p->o.last_ttime = -1ULL;

		for (i = 0; i < DDIR_RWDIR_CNT; i++)
			p->o.last_end[i] = -1ULL;

		p->pid = pid;
		flist_add_tail(&p->hash_list, hash_list);
		flist_add_tail(&p->pid_list, &pid_list);
	}

	return p;
}

/*
 * Load a blktrace file by reading all the blk_io_trace entries, and storing
 * them as io_pieces like the fio text version would do.
 */
static int load_blktrace(const char *filename, int need_swap)
{
	struct btrace_pid *p;
	unsigned long traces;
	struct blk_io_trace t;
	struct fifo *fifo;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open trace file\n");
		return 1;
	}

	fifo = fifo_alloc(TRACE_FIFO_SIZE);

	traces = 0;
	do {
		int ret = trace_fifo_get(fifo, fd, &t, sizeof(t));

		if (ret < 0)
			goto err;
		else if (!ret)
			break;
		else if (ret < (int) sizeof(t)) {
			fprintf(stderr, "fio: short fifo get\n");
			break;
		}

		if (need_swap)
			byteswap_trace(&t);

		if ((t.magic & 0xffffff00) != BLK_IO_TRACE_MAGIC) {
			fprintf(stderr, "fio: bad magic in blktrace data: %x\n",
								t.magic);
			goto err;
		}
		if ((t.magic & 0xff) != BLK_IO_TRACE_VERSION) {
			fprintf(stderr, "fio: bad blktrace version %d\n",
								t.magic & 0xff);
			goto err;
		}
		ret = discard_pdu(fifo, fd, &t);
		if (ret < 0) {
			fprintf(stderr, "blktrace lseek\n");
			goto err;
		} else if (t.pdu_len != ret) {
			fprintf(stderr, "fio: discarded %d of %d\n", ret, t.pdu_len);
			goto err;
		}

		p = pid_hash_get(t.pid);
		handle_trace(&t, p);
		p->o.last_ttime = t.time;
		traces++;
	} while (1);

	fifo_free(fifo);
	close(fd);

	if (output_ascii)
		printf("Traces loaded: %lu\n", traces);

	return 0;
err:
	close(fd);
	fifo_free(fifo);
	return 1;
}

static int bs_cmp(const void *ba, const void *bb)
{
	const struct bs *bsa = ba;
	const struct bs *bsb = bb;

	return bsb->nr - bsa->nr;
}

static void __output_p_ascii(struct btrace_pid *p, unsigned long *ios)
{
	const char *msg[] = { "reads", "writes", "trims" };
	struct btrace_out *o = &p->o;
	unsigned long total;
	int i, j;

	printf("[pid:\t%u]\n", p->pid);

	total = ddir_rw_sum(o->ios);
	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		float perc;

		if (!o->ios[i])
			continue;

		ios[i] += o->ios[i] + o->merges[i];
		printf("%s\n", msg[i]);
		perc = ((float) o->ios[i] * 100.0) / (float) total;
		printf("\tios:    %lu (perc=%3.2f%%)\n", o->ios[i], perc);
		perc = ((float) o->merges[i] * 100.0) / (float) total;
		printf("\tmerges: %lu (perc=%3.2f%%)\n", o->merges[i], perc);
		perc = ((float) o->seq[i] * 100.0) / (float) o->ios[i];
		printf("\tseq:    %lu (perc=%3.2f%%)\n", o->seq[i], perc);

		for (j = 0; j < o->nr_bs[i]; j++) {
			struct bs *bs = &o->bs[i][j];

			perc = (((float) bs->nr * 100.0) / (float) o->ios[i]);
			printf("\tbs=%u, perc=%3.2f%%\n", bs->bs, perc);
		}
	}

	printf("depth:\t%u\n", o->depth);
	printf("usec:\t%llu (delay=%llu)\n", (o->last_ttime - o->first_ttime) / 1000ULL, (unsigned long long) o->start_delay);

	printf("files:\t");
	for (i = 0; i < o->nr_files; i++)
		printf("%s,", o->files[i].name);
	printf("\n");

	printf("\n");
}

static int __output_p_fio(struct btrace_pid *p, unsigned long *ios)
{
	struct btrace_out *o = &p->o;
	unsigned long total;
	unsigned long long time;
	float perc;
	int i, j;

	if ((o->ios[0] + o->ios[1]) && o->ios[2]) {
		log_err("fio: trace has both read/write and trim\n");
		return 1;
	}

	printf("[pid%u]\n", p->pid);
	printf("direct=1\n");
	if (o->depth == 1)
		printf("ioengine=sync\n");
	else
		printf("ioengine=libaio\niodepth=%u\n", o->depth);

	if (o->ios[0] && !o->ios[1])
		printf("rw=randread\n");
	else if (!o->ios[0] && o->ios[1])
		printf("rw=randwrite\n");
	else if (o->ios[2])
		printf("rw=randtrim\n");
	else {
		printf("rw=randrw\n");
		total = ddir_rw_sum(o->ios);
		perc = ((float) o->ios[0] * 100.0) / (float) total;
		printf("rwmixread=%u\n", (int) (perc + 0.99));
	}

	printf("percentage_random=");
	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		if (o->seq[i] && o->ios[i]) {
			perc = ((float) o->seq[i] * 100.0) / (float) o->ios[i];
			if (perc >= 99.0)
				perc = 100.0;
		} else
			perc = 100.0;

		if (i)
			printf(",");
		perc = 100.0 - perc;
		printf("%u", (int) perc);
	}
	printf("\n");

	printf("filename=");
	for (i = 0; i < o->nr_files; i++) {
		if (i)
			printf(":");
		printf("%s", o->files[i].name);
	}
	printf("\n");

	printf("startdelay=%llus\n", o->start_delay / 1000000ULL);

	time = o->last_ttime - o->first_ttime;
	time = (time + 1000000000ULL - 1) / 1000000000ULL;
	printf("runtime=%llus\n", time);

	printf("bssplit=");
	for (i = 0; i < DDIR_RWDIR_CNT; i++) {

		if (i && o->nr_bs[i - 1] && o->nr_bs[i])
			printf(",");

		for (j = 0; j < o->nr_bs[i]; j++) {
			struct bs *bs = &o->bs[i][j];

			perc = (((float) bs->nr * 100.0) / (float) o->ios[i]);
			if (perc < 1.00)
				continue;
			if (j)
				printf(":");
			if (j + 1 == o->nr_bs[i])
				printf("%u/", bs->bs);
			else
				printf("%u/%u", bs->bs, (int) perc);
		}
	}
	printf("\n\n");

	return 0;
}

static int __output_p(struct btrace_pid *p, unsigned long *ios)
{
	struct btrace_out *o = &p->o;
	int i, ret = 0;

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		if (o->nr_bs[i] <= 1)
			continue;
		qsort(o->bs[i], o->nr_bs[i], sizeof(struct bs), bs_cmp);
	}

	if (filename) {
		o->files = malloc(sizeof(struct trace_file));
		o->nr_files++;
		o->files[0].name = filename;
	}

	if (output_ascii)
		__output_p_ascii(p, ios);
	else
		ret = __output_p_fio(p, ios);

	return ret;
}

static int prune_entry(struct btrace_out *o)
{
	uint64_t time;

	if (ddir_rw_sum(o->ios) < ios_threshold)
		return 1;

	time = (o->last_ttime - o->first_ttime) / 1000ULL;
	if (time < rt_threshold)
		return 1;

	return 0;
}

static int entry_cmp(void *priv, struct flist_head *a, struct flist_head *b)
{
	struct btrace_pid *pa = flist_entry(a, struct btrace_pid, pid_list);
	struct btrace_pid *pb = flist_entry(b, struct btrace_pid, pid_list);

	return ddir_rw_sum(pb->o.ios) - ddir_rw_sum(pa->o.ios);
}

static int output_p(void)
{
	unsigned long ios[DDIR_RWDIR_CNT];
	struct flist_head *e, *tmp;
	int ret = 0;

	flist_for_each_safe(e, tmp, &pid_list) {
		struct btrace_pid *p;

		p = flist_entry(e, struct btrace_pid, pid_list);
		if (prune_entry(&p->o)) {
			flist_del(&p->pid_list);
			flist_del(&p->hash_list);
			free(p);
			continue;
		}
		p->o.start_delay = (p->o.first_ttime / 1000ULL) - first_ttime;
	}

	memset(ios, 0, sizeof(ios));

	flist_sort(NULL, &pid_list, entry_cmp);

	flist_for_each(e, &pid_list) {
		struct btrace_pid *p;

		p = flist_entry(e, struct btrace_pid, pid_list);
		ret |= __output_p(p, ios);
	}

	if (output_ascii)
		printf("Total: reads=%lu, writes=%lu\n", ios[0], ios[1]);

	return ret;
}

static int usage(char *argv[])
{
	fprintf(stderr, "%s: <blktrace bin file>\n", argv[0]);
	fprintf(stderr, "\t-t\tUsec threshold to ignore task\n");
	fprintf(stderr, "\t-n\tNumber IOS threshold to ignore task\n");
	fprintf(stderr, "\t-f\tFio job file output\n");
	fprintf(stderr, "\t-d\tUse this file/device for replay\n");
	return 1;
}

int main(int argc, char *argv[])
{
	int fd, ret, need_swap = -1;
	struct blk_io_trace t;
	int i, c;

	if (argc < 2)
		return usage(argv);

	while ((c = getopt(argc, argv, "t:n:fd:")) != -1) {
		switch (c) {
		case 't':
			rt_threshold = atoi(optarg);
			break;
		case 'n':
			ios_threshold = atoi(optarg);
			break;
		case 'f':
			output_ascii = 0;
			break;
		case 'd':
			filename = strdup(optarg);
			break;
		case '?':
		default:
			return usage(argv);
		}
	}

	if (argc == optind)
		return usage(argv);

	fd = open(argv[optind], O_RDONLY);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	ret = read(fd, &t, sizeof(t));
	if (ret < 0) {
		perror("read");
		return 1;
	} else if (ret != sizeof(t)) {
		fprintf(stderr, "fio: short read on trace file\n");
		return 1;
	}

	close(fd);

	if ((t.magic & 0xffffff00) == BLK_IO_TRACE_MAGIC)
		need_swap = 0;
	else {
		/*
		 * Maybe it needs to be endian swapped...
		 */
		t.magic = fio_swap32(t.magic);
		if ((t.magic & 0xffffff00) == BLK_IO_TRACE_MAGIC)
			need_swap = 1;
	}

	if (need_swap == -1) {
		fprintf(stderr, "fio: blktrace appears corrupt\n");
		return 1;
	}

	for (i = 0; i < PID_HASH_SIZE; i++)
		INIT_FLIST_HEAD(&pid_hash[i]);

	load_blktrace(argv[optind], need_swap);
	first_ttime /= 1000ULL;

	return output_p();
}
