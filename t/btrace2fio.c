#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <math.h>
#include <assert.h>

#include "../io_ddir.h"
#include "../flist.h"
#include "../hash.h"
#include "../fifo.h"
#include "../blktrace_api.h"
#include "../os/os.h"
#include "../log.h"
#include "../minmax.h"
#include "../oslib/linux-dev-lookup.h"

#define TRACE_FIFO_SIZE	8192

static unsigned int rt_threshold = 1000000;
static unsigned int ios_threshold = 10;
static unsigned int rate_threshold;
static unsigned int set_rate;
static unsigned int max_depth = 256;
static int output_ascii = 1;
static char *filename;

static char **add_opts;
static int n_add_opts;

/*
 * Collapse defaults
 */
static unsigned int collapse_entries = 0;
static unsigned int depth_diff = 1;
static unsigned int random_diff = 5;

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
	unsigned long merges[DDIR_RWDIR_CNT];

	uint64_t last_end[DDIR_RWDIR_CNT];
	uint64_t seq[DDIR_RWDIR_CNT];

	struct bs *bs[DDIR_RWDIR_CNT];
	unsigned int nr_bs[DDIR_RWDIR_CNT];

	int inflight;
	unsigned int depth;
	int depth_disabled;
	int complete_seen;

	uint64_t first_ttime[DDIR_RWDIR_CNT];
	uint64_t last_ttime[DDIR_RWDIR_CNT];
	uint64_t kib[DDIR_RWDIR_CNT];

	uint64_t start_delay;
};

struct btrace_pid {
	struct flist_head hash_list;
	struct flist_head pid_list;
	pid_t pid;

	pid_t *merge_pids;
	unsigned int nr_merge_pids;

	struct trace_file *files;
	int nr_files;
	unsigned int last_major, last_minor;
	int numjobs;
	int ignore;

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

#define INFLIGHT_HASH_BITS	8
#define INFLIGHT_HASH_SIZE	(1U << INFLIGHT_HASH_BITS)
static struct flist_head inflight_hash[INFLIGHT_HASH_SIZE];

static uint64_t first_ttime = -1ULL;

static struct inflight *inflight_find(uint64_t sector)
{
	struct flist_head *inflight_list;
	struct flist_head *e;

	inflight_list = &inflight_hash[hash_long(sector, INFLIGHT_HASH_BITS)];

	flist_for_each(e, inflight_list) {
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

static void __inflight_add(struct inflight *i)
{
	struct flist_head *list;

	list = &inflight_hash[hash_long(i->end_sector, INFLIGHT_HASH_BITS)];
	flist_add_tail(&i->list, list);
}

static void inflight_add(struct btrace_pid *p, uint64_t sector, uint32_t len)
{
	struct btrace_out *o = &p->o;
	struct inflight *i;

	i = calloc(1, sizeof(*i));
	i->p = p;
	o->inflight++;
	if (!o->depth_disabled) {
		o->depth = max((int) o->depth, o->inflight);
		if (o->depth >= max_depth && !o->complete_seen) {
			o->depth_disabled = 1;
			o->depth = max_depth;
		}
	}
	i->end_sector = sector + (len >> 9);
	__inflight_add(i);
}

static void inflight_merge(struct inflight *i, int rw, unsigned int size)
{
	i->p->o.merges[rw]++;
	if (size) {
		i->end_sector += (size >> 9);
		flist_del(&i->list);
		__inflight_add(i);
	}
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

static int handle_trace_notify(struct blk_io_trace *t)
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
		log_err("unknown trace act %x\n", t->action);
		return 1;
	}

	return 0;
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

static int btrace_add_file(struct btrace_pid *p, uint32_t devno)
{
	unsigned int maj = FMAJOR(devno);
	unsigned int min = FMINOR(devno);
	struct trace_file *f;
	unsigned int i;
	char dev[256];

	if (filename)
		return 0;
	if (p->last_major == maj && p->last_minor == min)
		return 0;

	p->last_major = maj;
	p->last_minor = min;

	/*
	 * check for this file in our list
	 */
	for (i = 0; i < p->nr_files; i++) {
		f = &p->files[i];

		if (f->major == maj && f->minor == min)
			return 0;
	}

	strcpy(dev, "/dev");
	if (!blktrace_lookup_device(NULL, dev, maj, min)) {
		log_err("fio: failed to find device %u/%u\n", maj, min);
		if (!output_ascii) {
			log_err("fio: use -d to specify device\n");
			return 1;
		}
		return 0;
	}

	p->files = realloc(p->files, (p->nr_files + 1) * sizeof(*f));
	f = &p->files[p->nr_files];
	f->name = strdup(dev);
	f->major = maj;
	f->minor = min;
	p->nr_files++;
	return 0;
}

static int t_to_rwdir(struct blk_io_trace *t)
{
	if (t->action & BLK_TC_ACT(BLK_TC_DISCARD))
		return DDIR_TRIM;

	return (t->action & BLK_TC_ACT(BLK_TC_WRITE)) != 0;
}

static int handle_trace_discard(struct blk_io_trace *t, struct btrace_pid *p)
{
	struct btrace_out *o = &p->o;

	if (btrace_add_file(p, t->device))
		return 1;

	if (o->first_ttime[2] == -1ULL)
		o->first_ttime[2] = t->time;

	o->ios[DDIR_TRIM]++;
	add_bs(o, t->bytes, DDIR_TRIM);
	return 0;
}

static int handle_trace_fs(struct blk_io_trace *t, struct btrace_pid *p)
{
	struct btrace_out *o = &p->o;
	int rw;

	if (btrace_add_file(p, t->device))
		return 1;

	first_ttime = min(first_ttime, (uint64_t) t->time);

	rw = (t->action & BLK_TC_ACT(BLK_TC_WRITE)) != 0;

	if (o->first_ttime[rw] == -1ULL)
		o->first_ttime[rw] = t->time;

	add_bs(o, t->bytes, rw);
	o->ios[rw]++;

	if (t->sector == o->last_end[rw] || o->last_end[rw] == -1ULL)
		o->seq[rw]++;

	o->last_end[rw] = t->sector + (t->bytes >> 9);
	return 0;
}

static int handle_queue_trace(struct blk_io_trace *t, struct btrace_pid *p)
{
	if (t->action & BLK_TC_ACT(BLK_TC_NOTIFY))
		return handle_trace_notify(t);
	else if (t->action & BLK_TC_ACT(BLK_TC_DISCARD))
		return handle_trace_discard(t, p);
	else
		return handle_trace_fs(t, p);
}

static int handle_trace(struct blk_io_trace *t, struct btrace_pid *p)
{
	unsigned int act = t->action & 0xffff;
	int ret = 0;

	if (act == __BLK_TA_QUEUE) {
		inflight_add(p, t->sector, t->bytes);
		ret = handle_queue_trace(t, p);
	} else if (act == __BLK_TA_BACKMERGE) {
		struct inflight *i;

		i = inflight_find(t->sector + (t->bytes >> 9));
		if (i)
			inflight_remove(i);

		i = inflight_find(t->sector);
		if (i)
			inflight_merge(i, t_to_rwdir(t), t->bytes);
	} else if (act == __BLK_TA_FRONTMERGE) {
		struct inflight *i;

		i = inflight_find(t->sector + (t->bytes >> 9));
		if (i)
			inflight_remove(i);

		i = inflight_find(t->sector);
		if (i)
			inflight_merge(i, t_to_rwdir(t), 0);
	} else if (act == __BLK_TA_COMPLETE) {
		struct inflight *i;

		i = inflight_find(t->sector + (t->bytes >> 9));
		if (i) {
			i->p->o.kib[t_to_rwdir(t)] += (t->bytes >> 10);
			i->p->o.complete_seen = 1;
			inflight_remove(i);
		}
	}

	return ret;
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

		for (i = 0; i < DDIR_RWDIR_CNT; i++) {
			p->o.first_ttime[i] = -1ULL;
			p->o.last_ttime[i] = -1ULL;
			p->o.last_end[i] = -1ULL;
		}

		p->pid = pid;
		p->numjobs = 1;
		flist_add_tail(&p->hash_list, hash_list);
		flist_add_tail(&p->pid_list, &pid_list);
	}

	return p;
}

/*
 * Load a blktrace file by reading all the blk_io_trace entries, and storing
 * them as io_pieces like the fio text version would do.
 */
static int load_blktrace(const char *fname, int need_swap)
{
	struct btrace_pid *p;
	unsigned long traces;
	struct blk_io_trace t;
	struct fifo *fifo;
	int fd, ret = 0;

	fd = open(fname, O_RDONLY);
	if (fd < 0) {
		perror("open trace file\n");
		return 1;
	}

	fifo = fifo_alloc(TRACE_FIFO_SIZE);

	traces = 0;
	do {
		ret = trace_fifo_get(fifo, fd, &t, sizeof(t));
		if (ret < 0)
			goto err;
		else if (!ret)
			break;
		else if (ret < (int) sizeof(t)) {
			log_err("fio: short fifo get\n");
			break;
		}

		if (need_swap)
			byteswap_trace(&t);

		if ((t.magic & 0xffffff00) != BLK_IO_TRACE_MAGIC) {
			log_err("fio: bad magic in blktrace data: %x\n", t.magic);
			goto err;
		}
		if ((t.magic & 0xff) != BLK_IO_TRACE_VERSION) {
			log_err("fio: bad blktrace version %d\n", t.magic & 0xff);
			goto err;
		}
		ret = discard_pdu(fifo, fd, &t);
		if (ret < 0) {
			log_err("blktrace lseek\n");
			goto err;
		} else if (t.pdu_len != ret) {
			log_err("fio: discarded %d of %d\n", ret, t.pdu_len);
			goto err;
		}

		p = pid_hash_get(t.pid);
		ret = handle_trace(&t, p);
		if (ret)
			break;
		p->o.last_ttime[t_to_rwdir(&t)] = t.time;
		traces++;
	} while (1);

	fifo_free(fifo);
	close(fd);

	if (ret)
		return ret;

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

static unsigned long o_to_kib_rate(struct btrace_out *o, int rw)
{
	uint64_t usec = (o->last_ttime[rw] - o->first_ttime[rw]) / 1000ULL;
	uint64_t val;

	if (!usec)
		return 0;

	usec /= 1000;
	if (!usec)
		return 0;

	val = o->kib[rw] * 1000ULL;
	return val / usec;
}

static uint64_t o_first_ttime(struct btrace_out *o)
{
	uint64_t first;

	first = min(o->first_ttime[0], o->first_ttime[1]);
	return min(first, o->first_ttime[2]);
}

static uint64_t o_longest_ttime(struct btrace_out *o)
{
	uint64_t ret = 0;
	int i;

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		uint64_t diff;

		diff = o->last_ttime[i] - o->first_ttime[i];
		ret = max(diff, ret);
	}

	return ret;
}

static void __output_p_ascii(struct btrace_pid *p, unsigned long *ios)
{
	const char *msg[] = { "reads", "writes", "trims" };
	struct btrace_out *o = &p->o;
	unsigned long total, usec;
	int i, j;

	printf("[pid:\t%u", p->pid);
	if (p->nr_merge_pids)
		for (i = 0; i < p->nr_merge_pids; i++)
			printf(", %u", p->merge_pids[i]);
	printf("]\n");

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
		printf("\tseq:    %lu (perc=%3.2f%%)\n", (unsigned long) o->seq[i], perc);
		printf("\trate:   %lu KiB/sec\n", o_to_kib_rate(o, i));

		for (j = 0; j < o->nr_bs[i]; j++) {
			struct bs *bs = &o->bs[i][j];

			perc = (((float) bs->nr * 100.0) / (float) o->ios[i]);
			printf("\tbs=%u, perc=%3.2f%%\n", bs->bs, perc);
		}
	}

	printf("depth:\t%u\n", o->depth);
	usec = o_longest_ttime(o) / 1000ULL;
	printf("usec:\t%lu (delay=%llu)\n", usec, (unsigned long long) o->start_delay);

	printf("files:\t");
	for (i = 0; i < p->nr_files; i++)
		printf("%s,", p->files[i].name);
	printf("\n");

	printf("\n");
}

static int __output_p_fio(struct btrace_pid *p, unsigned long *ios,
			  const char *name_postfix)
{
	struct btrace_out *o = &p->o;
	unsigned long total;
	unsigned long long time;
	float perc;
	int i, j;

	if ((o->ios[0] + o->ios[1]) && o->ios[2]) {
		unsigned long ios_bak[DDIR_RWDIR_CNT];

		memcpy(ios_bak, o->ios, DDIR_RWDIR_CNT * sizeof(unsigned long));

		/* create job for read/write */
		o->ios[2] = 0;
		__output_p_fio(p, ios, "");
		o->ios[2] = ios_bak[2];

		/* create job for trim */
		o->ios[0] = 0;
		o->ios[1] = 0;
		__output_p_fio(p, ios, "_trim");
		o->ios[0] = ios_bak[0];
		o->ios[1] = ios_bak[1];

		return 0;
	}
	if (!p->nr_files) {
		log_err("fio: no devices found\n");
		return 1;
	}

	printf("[pid%u%s", p->pid, name_postfix);
	if (p->nr_merge_pids)
		for (i = 0; i < p->nr_merge_pids; i++)
			printf(",pid%u", p->merge_pids[i]);
	printf("]\n");

	printf("numjobs=%u\n", p->numjobs);
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
		printf("rwmixread=%u\n", (int) floor(perc + 0.50));
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
		printf("%u", (int) floor(perc + 0.5));
	}
	printf("\n");

	printf("filename=");
	for (i = 0; i < p->nr_files; i++) {
		if (i)
			printf(":");
		printf("%s", p->files[i].name);
	}
	printf("\n");

	if (o->start_delay / 1000000ULL)
		printf("startdelay=%llus\n", o->start_delay / 1000000ULL);

	time = o_longest_ttime(o);
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
				printf("%u/%u", bs->bs, (int) floor(perc + 0.5));
		}
	}
	printf("\n");

	if (set_rate) {
		printf("rate=");
		for (i = 0; i < DDIR_RWDIR_CNT; i++) {
			unsigned long rate;

			rate = o_to_kib_rate(o, i);
			if (i)
				printf(",");
			if (rate)
				printf("%luk", rate);
		}
		printf("\n");
	}

	if (n_add_opts)
		for (i = 0; i < n_add_opts; i++)
			printf("%s\n", add_opts[i]);

	printf("\n");
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
		p->files = malloc(sizeof(struct trace_file));
		p->nr_files++;
		p->files[0].name = filename;
	}

	if (output_ascii)
		__output_p_ascii(p, ios);
	else
		ret = __output_p_fio(p, ios, "");

	return ret;
}

static void remove_ddir(struct btrace_out *o, int rw)
{
	o->ios[rw] = 0;
}

static int prune_entry(struct btrace_out *o)
{
	unsigned long rate;
	uint64_t time;
	int i;

	if (ddir_rw_sum(o->ios) < ios_threshold)
		return 1;

	time = o_longest_ttime(o) / 1000ULL;
	if (time < rt_threshold)
		return 1;

	rate = 0;
	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		unsigned long this_rate;

		this_rate = o_to_kib_rate(o, i);
		if (this_rate < rate_threshold) {
			remove_ddir(o, i);
			this_rate = 0;
		}
		rate += this_rate;
	}

	if (rate < rate_threshold)
		return 1;

	return 0;
}

static int entry_cmp(void *priv, struct flist_head *a, struct flist_head *b)
{
	struct btrace_pid *pa = flist_entry(a, struct btrace_pid, pid_list);
	struct btrace_pid *pb = flist_entry(b, struct btrace_pid, pid_list);

	return ddir_rw_sum(pb->o.ios) - ddir_rw_sum(pa->o.ios);
}

static void free_p(struct btrace_pid *p)
{
	struct btrace_out *o = &p->o;
	int i;

	for (i = 0; i < p->nr_files; i++) {
		if (p->files[i].name && p->files[i].name != filename)
			free(p->files[i].name);
	}

	for (i = 0; i < DDIR_RWDIR_CNT; i++)
		free(o->bs[i]);

	free(p->files);
	flist_del(&p->pid_list);
	flist_del(&p->hash_list);
	free(p);
}

static int entries_close(struct btrace_pid *pida, struct btrace_pid *pidb)
{
	float perca, percb, fdiff;
	int i, idiff;

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		if ((pida->o.ios[i] && !pidb->o.ios[i]) ||
		    (pidb->o.ios[i] && !pida->o.ios[i]))
			return 0;
		if (pida->o.ios[i] && pidb->o.ios[i]) {
			perca = ((float) pida->o.seq[i] * 100.0) / (float) pida->o.ios[i];
			percb = ((float) pidb->o.seq[i] * 100.0) / (float) pidb->o.ios[i];
			fdiff = perca - percb;
			if (fabs(fdiff) > random_diff)
				return 0;
		}

		idiff = pida->o.depth - pidb->o.depth;
		if (abs(idiff) > depth_diff)
			return 0;
	}

	return 1;
}

static void merge_bs(struct bs **bsap, unsigned int *nr_bsap,
		     struct bs *bsb, unsigned int nr_bsb)
{
	struct bs *bsa = *bsap;
	unsigned int nr_bsa = *nr_bsap;
	int a, b;

	for (b = 0; b < nr_bsb; b++) {
		int next, found = 0;

		for (a = 0; a < nr_bsa; a++) {
			if (bsb[b].bs != bsa[a].bs)
				continue;

			bsa[a].nr += bsb[b].nr;
			bsa[a].merges += bsb[b].merges;
			found = 1;
			break;
		}

		if (found)
			continue;

		next = *nr_bsap;
		bsa = realloc(bsa, (next + 1) * sizeof(struct bs));
		bsa[next].bs = bsb[b].bs;
		bsa[next].nr = bsb[b].nr;
		(*nr_bsap)++;
		*bsap = bsa;
	}
}

static int merge_entries(struct btrace_pid *pida, struct btrace_pid *pidb)
{
	int i;

	if (!entries_close(pida, pidb))
		return 0;

	pida->nr_merge_pids++;
	pida->merge_pids = realloc(pida->merge_pids, pida->nr_merge_pids * sizeof(pid_t));
	pida->merge_pids[pida->nr_merge_pids - 1] = pidb->pid;

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		struct btrace_out *oa = &pida->o;
		struct btrace_out *ob = &pidb->o;

		oa->ios[i] += ob->ios[i];
		oa->merges[i] += ob->merges[i];
		oa->seq[i] += ob->seq[i];
		oa->kib[i] += ob->kib[i];
		oa->first_ttime[i] = min(oa->first_ttime[i], ob->first_ttime[i]);
		oa->last_ttime[i] = max(oa->last_ttime[i], ob->last_ttime[i]);
		merge_bs(&oa->bs[i], &oa->nr_bs[i], ob->bs[i], ob->nr_bs[i]);
	}

	pida->o.start_delay = min(pida->o.start_delay, pidb->o.start_delay);
	pida->o.depth = (pida->o.depth + pidb->o.depth) / 2;
	return 1;
}

static void check_merges(struct btrace_pid *p, struct flist_head *pidlist)
{
	struct flist_head *e, *tmp;

	if (p->ignore)
		return;

	flist_for_each_safe(e, tmp, pidlist) {
		struct btrace_pid *pidb;

		pidb = flist_entry(e, struct btrace_pid, pid_list);
		if (pidb == p)
			continue;

		if (merge_entries(p, pidb)) {
			pidb->ignore = 1;
			p->numjobs++;
		}
	}
}

static int output_p(void)
{
	unsigned long ios[DDIR_RWDIR_CNT];
	struct flist_head *e, *tmp;
	int depth_disabled = 0;
	int ret = 0;

	flist_for_each_safe(e, tmp, &pid_list) {
		struct btrace_pid *p;

		p = flist_entry(e, struct btrace_pid, pid_list);
		if (prune_entry(&p->o)) {
			free_p(p);
			continue;
		}
		p->o.start_delay = (o_first_ttime(&p->o) / 1000ULL) - first_ttime;
		depth_disabled += p->o.depth_disabled;
	}

	if (collapse_entries) {
		struct btrace_pid *p;

		flist_for_each_safe(e, tmp, &pid_list) {
			p = flist_entry(e, struct btrace_pid, pid_list);
			check_merges(p, &pid_list);
		}

		flist_for_each_safe(e, tmp, &pid_list) {
			p = flist_entry(e, struct btrace_pid, pid_list);
			if (p->ignore)
				free_p(p);
		}
	}

	if (depth_disabled)
		log_err("fio: missing completion traces, depths capped at %u\n", max_depth);

	memset(ios, 0, sizeof(ios));

	flist_sort(NULL, &pid_list, entry_cmp);

	flist_for_each(e, &pid_list) {
		struct btrace_pid *p;

		p = flist_entry(e, struct btrace_pid, pid_list);
		ret |= __output_p(p, ios);
		if (ret && !output_ascii)
			break;
	}

	if (output_ascii)
		printf("Total: reads=%lu, writes=%lu\n", ios[0], ios[1]);

	return ret;
}

static int usage(char *argv[])
{
	log_err("%s: [options] <blktrace bin file>\n", argv[0]);
	log_err("\t-t\tUsec threshold to ignore task\n");
	log_err("\t-n\tNumber IOS threshold to ignore task\n");
	log_err("\t-f\tFio job file output\n");
	log_err("\t-d\tUse this file/device for replay\n");
	log_err("\t-r\tIgnore jobs with less than this KiB/sec rate\n");
	log_err("\t-R\tSet rate in fio job (def=%u)\n", set_rate);
	log_err("\t-D\tCap queue depth at this value (def=%u)\n", max_depth);
	log_err("\t-c\tCollapse \"identical\" jobs (def=%u)\n", collapse_entries);
	log_err("\t-u\tDepth difference for collapse (def=%u)\n", depth_diff);
	log_err("\t-x\tRandom difference for collapse (def=%u)\n", random_diff);
	log_err("\t-a\tAdditional fio option to add to job file\n");
	return 1;
}

static int trace_needs_swap(const char *trace_file, int *swap)
{
	struct blk_io_trace t;
	int fd, ret;

	*swap = -1;

	fd = open(trace_file, O_RDONLY);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	ret = read(fd, &t, sizeof(t));
	if (ret < 0) {
		close(fd);
		perror("read");
		return 1;
	} else if (ret != sizeof(t)) {
		close(fd);
		log_err("fio: short read on trace file\n");
		return 1;
	}

	close(fd);

	if ((t.magic & 0xffffff00) == BLK_IO_TRACE_MAGIC)
		*swap = 0;
	else {
		/*
		 * Maybe it needs to be endian swapped...
		 */
		t.magic = fio_swap32(t.magic);
		if ((t.magic & 0xffffff00) == BLK_IO_TRACE_MAGIC)
			*swap = 1;
	}

	if (*swap == -1) {
		log_err("fio: blktrace appears corrupt\n");
		return 1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int need_swap, i, c;

	if (argc < 2)
		return usage(argv);

	while ((c = getopt(argc, argv, "t:n:fd:r:RD:c:u:x:a:")) != -1) {
		switch (c) {
		case 'R':
			set_rate = 1;
			break;
		case 'r':
			rate_threshold = atoi(optarg);
			break;
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
		case 'D':
			max_depth = atoi(optarg);
			break;
		case 'c':
			collapse_entries = atoi(optarg);
			break;
		case 'u':
			depth_diff = atoi(optarg);
			break;
		case 'x':
			random_diff = atoi(optarg);
			break;
		case 'a':
			add_opts = realloc(add_opts, (n_add_opts + 1) * sizeof(char *));
			add_opts[n_add_opts] = strdup(optarg);
			n_add_opts++;
			break;
		case '?':
		default:
			return usage(argv);
		}
	}

	if (argc == optind)
		return usage(argv);

	if (trace_needs_swap(argv[optind], &need_swap))
		return 1;

	for (i = 0; i < PID_HASH_SIZE; i++)
		INIT_FLIST_HEAD(&pid_hash[i]);
	for (i = 0; i < INFLIGHT_HASH_SIZE; i++)
		INIT_FLIST_HEAD(&inflight_hash[i]);

	load_blktrace(argv[optind], need_swap);
	first_ttime /= 1000ULL;

	return output_p();
}
