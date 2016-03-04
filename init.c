/*
 * This file contains job initialization and setup functions.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "fio.h"
#ifndef FIO_NO_HAVE_SHM_H
#include <sys/shm.h>
#endif

#include "parse.h"
#include "smalloc.h"
#include "filehash.h"
#include "verify.h"
#include "profile.h"
#include "server.h"
#include "idletime.h"
#include "filelock.h"

#include "oslib/getopt.h"
#include "oslib/strcasestr.h"

#include "crc/test.h"

const char fio_version_string[] = FIO_VERSION;

#define FIO_RANDSEED		(0xb1899bedUL)

static char **ini_file;
static int max_jobs = FIO_MAX_JOBS;
static int dump_cmdline;
static long long def_timeout;
static int parse_only;

static struct thread_data def_thread;
struct thread_data *threads = NULL;
static char **job_sections;
static int nr_job_sections;

int exitall_on_terminate = 0;
int exitall_on_terminate_error = 0;
int output_format = FIO_OUTPUT_NORMAL;
int eta_print = FIO_ETA_AUTO;
int eta_new_line = 0;
FILE *f_out = NULL;
FILE *f_err = NULL;
char *exec_profile = NULL;
int warnings_fatal = 0;
int terse_version = 3;
int is_backend = 0;
int nr_clients = 0;
int log_syslog = 0;

int write_bw_log = 0;
int read_only = 0;
int status_interval = 0;

char *trigger_file = NULL;
long long trigger_timeout = 0;
char *trigger_cmd = NULL;
char *trigger_remote_cmd = NULL;

char *aux_path = NULL;

static int prev_group_jobs;

unsigned long fio_debug = 0;
unsigned int fio_debug_jobno = -1;
unsigned int *fio_debug_jobp = NULL;

static char cmd_optstr[256];
static int did_arg;

#define FIO_CLIENT_FLAG		(1 << 16)

/*
 * Command line options. These will contain the above, plus a few
 * extra that only pertain to fio itself and not jobs.
 */
static struct option l_opts[FIO_NR_OPTIONS] = {
	{
		.name		= (char *) "output",
		.has_arg	= required_argument,
		.val		= 'o' | FIO_CLIENT_FLAG,
	},
	{
		.name		= (char *) "timeout",
		.has_arg	= required_argument,
		.val		= 't' | FIO_CLIENT_FLAG,
	},
	{
		.name		= (char *) "latency-log",
		.has_arg	= required_argument,
		.val		= 'l' | FIO_CLIENT_FLAG,
	},
	{
		.name		= (char *) "bandwidth-log",
		.has_arg	= required_argument,
		.val		= 'b' | FIO_CLIENT_FLAG,
	},
	{
		.name		= (char *) "minimal",
		.has_arg	= no_argument,
		.val		= 'm' | FIO_CLIENT_FLAG,
	},
	{
		.name		= (char *) "output-format",
		.has_arg	= optional_argument,
		.val		= 'F' | FIO_CLIENT_FLAG,
	},
	{
		.name		= (char *) "append-terse",
		.has_arg	= optional_argument,
		.val		= 'f',
	},
	{
		.name		= (char *) "version",
		.has_arg	= no_argument,
		.val		= 'v' | FIO_CLIENT_FLAG,
	},
	{
		.name		= (char *) "help",
		.has_arg	= no_argument,
		.val		= 'h' | FIO_CLIENT_FLAG,
	},
	{
		.name		= (char *) "cmdhelp",
		.has_arg	= optional_argument,
		.val		= 'c' | FIO_CLIENT_FLAG,
	},
	{
		.name		= (char *) "enghelp",
		.has_arg	= optional_argument,
		.val		= 'i' | FIO_CLIENT_FLAG,
	},
	{
		.name		= (char *) "showcmd",
		.has_arg	= no_argument,
		.val		= 's' | FIO_CLIENT_FLAG,
	},
	{
		.name		= (char *) "readonly",
		.has_arg	= no_argument,
		.val		= 'r' | FIO_CLIENT_FLAG,
	},
	{
		.name		= (char *) "eta",
		.has_arg	= required_argument,
		.val		= 'e' | FIO_CLIENT_FLAG,
	},
	{
		.name		= (char *) "eta-newline",
		.has_arg	= required_argument,
		.val		= 'E' | FIO_CLIENT_FLAG,
	},
	{
		.name		= (char *) "debug",
		.has_arg	= required_argument,
		.val		= 'd' | FIO_CLIENT_FLAG,
	},
	{
		.name		= (char *) "parse-only",
		.has_arg	= no_argument,
		.val		= 'P' | FIO_CLIENT_FLAG,
	},
	{
		.name		= (char *) "section",
		.has_arg	= required_argument,
		.val		= 'x' | FIO_CLIENT_FLAG,
	},
#ifdef CONFIG_ZLIB
	{
		.name		= (char *) "inflate-log",
		.has_arg	= required_argument,
		.val		= 'X' | FIO_CLIENT_FLAG,
	},
#endif
	{
		.name		= (char *) "alloc-size",
		.has_arg	= required_argument,
		.val		= 'a' | FIO_CLIENT_FLAG,
	},
	{
		.name		= (char *) "profile",
		.has_arg	= required_argument,
		.val		= 'p' | FIO_CLIENT_FLAG,
	},
	{
		.name		= (char *) "warnings-fatal",
		.has_arg	= no_argument,
		.val		= 'w' | FIO_CLIENT_FLAG,
	},
	{
		.name		= (char *) "max-jobs",
		.has_arg	= required_argument,
		.val		= 'j' | FIO_CLIENT_FLAG,
	},
	{
		.name		= (char *) "terse-version",
		.has_arg	= required_argument,
		.val		= 'V' | FIO_CLIENT_FLAG,
	},
	{
		.name		= (char *) "server",
		.has_arg	= optional_argument,
		.val		= 'S',
	},
	{	.name		= (char *) "daemonize",
		.has_arg	= required_argument,
		.val		= 'D',
	},
	{
		.name		= (char *) "client",
		.has_arg	= required_argument,
		.val		= 'C',
	},
	{
		.name		= (char *) "remote-config",
		.has_arg	= required_argument,
		.val		= 'R',
	},
	{
		.name		= (char *) "cpuclock-test",
		.has_arg	= no_argument,
		.val		= 'T',
	},
	{
		.name		= (char *) "crctest",
		.has_arg	= optional_argument,
		.val		= 'G',
	},
	{
		.name		= (char *) "idle-prof",
		.has_arg	= required_argument,
		.val		= 'I',
	},
	{
		.name		= (char *) "status-interval",
		.has_arg	= required_argument,
		.val		= 'L',
	},
	{
		.name		= (char *) "trigger-file",
		.has_arg	= required_argument,
		.val		= 'W',
	},
	{
		.name		= (char *) "trigger-timeout",
		.has_arg	= required_argument,
		.val		= 'B',
	},
	{
		.name		= (char *) "trigger",
		.has_arg	= required_argument,
		.val		= 'H',
	},
	{
		.name		= (char *) "trigger-remote",
		.has_arg	= required_argument,
		.val		= 'J',
	},
	{
		.name		= (char *) "aux-path",
		.has_arg	= required_argument,
		.val		= 'K',
	},
	{
		.name		= NULL,
	},
};

void free_threads_shm(void)
{
	if (threads) {
		void *tp = threads;
#ifndef CONFIG_NO_SHM
		struct shmid_ds sbuf;

		threads = NULL;
		shmdt(tp);
		shmctl(shm_id, IPC_RMID, &sbuf);
		shm_id = -1;
#else
		threads = NULL;
		free(tp);
#endif
	}
}

static void free_shm(void)
{
	if (threads) {
		file_hash_exit();
		flow_exit();
		fio_debug_jobp = NULL;
		free_threads_shm();
	}

	free(trigger_file);
	free(trigger_cmd);
	free(trigger_remote_cmd);
	trigger_file = trigger_cmd = trigger_remote_cmd = NULL;

	options_free(fio_options, &def_thread);
	fio_filelock_exit();
	scleanup();
}

/*
 * The thread area is shared between the main process and the job
 * threads/processes. So setup a shared memory segment that will hold
 * all the job info. We use the end of the region for keeping track of
 * open files across jobs, for file sharing.
 */
static int setup_thread_area(void)
{
	void *hash;

	if (threads)
		return 0;

	/*
	 * 1024 is too much on some machines, scale max_jobs if
	 * we get a failure that looks like too large a shm segment
	 */
	do {
		size_t size = max_jobs * sizeof(struct thread_data);

		size += file_hash_size;
		size += sizeof(unsigned int);

#ifndef CONFIG_NO_SHM
		shm_id = shmget(0, size, IPC_CREAT | 0600);
		if (shm_id != -1)
			break;
		if (errno != EINVAL && errno != ENOMEM && errno != ENOSPC) {
			perror("shmget");
			break;
		}
#else
		threads = malloc(size);
		if (threads)
			break;
#endif

		max_jobs >>= 1;
	} while (max_jobs);

#ifndef CONFIG_NO_SHM
	if (shm_id == -1)
		return 1;

	threads = shmat(shm_id, NULL, 0);
	if (threads == (void *) -1) {
		perror("shmat");
		return 1;
	}
#endif

	memset(threads, 0, max_jobs * sizeof(struct thread_data));
	hash = (void *) threads + max_jobs * sizeof(struct thread_data);
	fio_debug_jobp = (void *) hash + file_hash_size;
	*fio_debug_jobp = -1;
	file_hash_init(hash);

	flow_init();

	return 0;
}

static void set_cmd_options(struct thread_data *td)
{
	struct thread_options *o = &td->o;

	if (!o->timeout)
		o->timeout = def_timeout;
}

static void dump_print_option(struct print_option *p)
{
	const char *delim;

	if (!strcmp("description", p->name))
		delim = "\"";
	else
		delim = "";

	log_info("--%s%s", p->name, p->value ? "" : " ");
	if (p->value)
		log_info("=%s%s%s ", delim, p->value, delim);
}

static void dump_opt_list(struct thread_data *td)
{
	struct flist_head *entry;
	struct print_option *p;

	if (flist_empty(&td->opt_list))
		return;

	flist_for_each(entry, &td->opt_list) {
		p = flist_entry(entry, struct print_option, list);
		dump_print_option(p);
	}
}

static void fio_dump_options_free(struct thread_data *td)
{
	while (!flist_empty(&td->opt_list)) {
		struct print_option *p;

		p = flist_first_entry(&td->opt_list, struct print_option, list);
		flist_del_init(&p->list);
		free(p->name);
		free(p->value);
		free(p);
	}
}

static void copy_opt_list(struct thread_data *dst, struct thread_data *src)
{
	struct flist_head *entry;

	if (flist_empty(&src->opt_list))
		return;

	flist_for_each(entry, &src->opt_list) {
		struct print_option *srcp, *dstp;

		srcp = flist_entry(entry, struct print_option, list);
		dstp = malloc(sizeof(*dstp));
		dstp->name = strdup(srcp->name);
		if (srcp->value)
			dstp->value = strdup(srcp->value);
		else
			dstp->value = NULL;
		flist_add_tail(&dstp->list, &dst->opt_list);
	}
}

/*
 * Return a free job structure.
 */
static struct thread_data *get_new_job(int global, struct thread_data *parent,
				       int preserve_eo, const char *jobname)
{
	struct thread_data *td;

	if (global) {
		set_cmd_options(&def_thread);
		return &def_thread;
	}
	if (setup_thread_area()) {
		log_err("error: failed to setup shm segment\n");
		return NULL;
	}
	if (thread_number >= max_jobs) {
		log_err("error: maximum number of jobs (%d) reached.\n",
				max_jobs);
		return NULL;
	}

	td = &threads[thread_number++];
	*td = *parent;

	INIT_FLIST_HEAD(&td->opt_list);
	if (parent != &def_thread)
		copy_opt_list(td, parent);

	td->io_ops = NULL;
	if (!preserve_eo)
		td->eo = NULL;

	td->o.uid = td->o.gid = -1U;

	dup_files(td, parent);
	fio_options_mem_dupe(td);

	profile_add_hooks(td);

	td->thread_number = thread_number;
	td->subjob_number = 0;

	if (jobname)
		td->o.name = strdup(jobname);

	if (!parent->o.group_reporting || parent == &def_thread)
		stat_number++;

	set_cmd_options(td);
	return td;
}

static void put_job(struct thread_data *td)
{
	if (td == &def_thread)
		return;

	profile_td_exit(td);
	flow_exit_job(td);

	if (td->error)
		log_info("fio: %s\n", td->verror);

	fio_options_free(td);
	fio_dump_options_free(td);
	if (td->io_ops)
		free_ioengine(td);

	if (td->o.name)
		free(td->o.name);

	memset(&threads[td->thread_number - 1], 0, sizeof(*td));
	thread_number--;
}

static int __setup_rate(struct thread_data *td, enum fio_ddir ddir)
{
	unsigned int bs = td->o.min_bs[ddir];

	assert(ddir_rw(ddir));

	if (td->o.rate[ddir])
		td->rate_bps[ddir] = td->o.rate[ddir];
	else
		td->rate_bps[ddir] = (uint64_t) td->o.rate_iops[ddir] * bs;

	if (!td->rate_bps[ddir]) {
		log_err("rate lower than supported\n");
		return -1;
	}

	td->rate_next_io_time[ddir] = 0;
	td->rate_io_issue_bytes[ddir] = 0;
	td->last_usec = 0;
	return 0;
}

static int setup_rate(struct thread_data *td)
{
	int ret = 0;

	if (td->o.rate[DDIR_READ] || td->o.rate_iops[DDIR_READ])
		ret = __setup_rate(td, DDIR_READ);
	if (td->o.rate[DDIR_WRITE] || td->o.rate_iops[DDIR_WRITE])
		ret |= __setup_rate(td, DDIR_WRITE);
	if (td->o.rate[DDIR_TRIM] || td->o.rate_iops[DDIR_TRIM])
		ret |= __setup_rate(td, DDIR_TRIM);

	return ret;
}

static int fixed_block_size(struct thread_options *o)
{
	return o->min_bs[DDIR_READ] == o->max_bs[DDIR_READ] &&
		o->min_bs[DDIR_WRITE] == o->max_bs[DDIR_WRITE] &&
		o->min_bs[DDIR_TRIM] == o->max_bs[DDIR_TRIM] &&
		o->min_bs[DDIR_READ] == o->min_bs[DDIR_WRITE] &&
		o->min_bs[DDIR_READ] == o->min_bs[DDIR_TRIM];
}


static unsigned long long get_rand_start_delay(struct thread_data *td)
{
	unsigned long long delayrange;
	uint64_t frand_max;
	unsigned long r;

	delayrange = td->o.start_delay_high - td->o.start_delay;

	frand_max = rand_max(&td->delay_state);
	r = __rand(&td->delay_state);
	delayrange = (unsigned long long) ((double) delayrange * (r / (frand_max + 1.0)));

	delayrange += td->o.start_delay;
	return delayrange;
}

/*
 * Lazy way of fixing up options that depend on each other. We could also
 * define option callback handlers, but this is easier.
 */
static int fixup_options(struct thread_data *td)
{
	struct thread_options *o = &td->o;
	int ret = 0;

#ifndef FIO_HAVE_PSHARED_MUTEX
	if (!o->use_thread) {
		log_info("fio: this platform does not support process shared"
			 " mutexes, forcing use of threads. Use the 'thread'"
			 " option to get rid of this warning.\n");
		o->use_thread = 1;
		ret = warnings_fatal;
	}
#endif

	if (o->write_iolog_file && o->read_iolog_file) {
		log_err("fio: read iolog overrides write_iolog\n");
		free(o->write_iolog_file);
		o->write_iolog_file = NULL;
		ret = warnings_fatal;
	}

	/*
	 * only really works with 1 file
	 */
	if (o->zone_size && o->open_files > 1)
		o->zone_size = 0;

	/*
	 * If zone_range isn't specified, backward compatibility dictates it
	 * should be made equal to zone_size.
	 */
	if (o->zone_size && !o->zone_range)
		o->zone_range = o->zone_size;

	/*
	 * Reads can do overwrites, we always need to pre-create the file
	 */
	if (td_read(td) || td_rw(td))
		o->overwrite = 1;

	if (!o->min_bs[DDIR_READ])
		o->min_bs[DDIR_READ] = o->bs[DDIR_READ];
	if (!o->max_bs[DDIR_READ])
		o->max_bs[DDIR_READ] = o->bs[DDIR_READ];
	if (!o->min_bs[DDIR_WRITE])
		o->min_bs[DDIR_WRITE] = o->bs[DDIR_WRITE];
	if (!o->max_bs[DDIR_WRITE])
		o->max_bs[DDIR_WRITE] = o->bs[DDIR_WRITE];
	if (!o->min_bs[DDIR_TRIM])
		o->min_bs[DDIR_TRIM] = o->bs[DDIR_TRIM];
	if (!o->max_bs[DDIR_TRIM])
		o->max_bs[DDIR_TRIM] = o->bs[DDIR_TRIM];

	o->rw_min_bs = min(o->min_bs[DDIR_READ], o->min_bs[DDIR_WRITE]);
	o->rw_min_bs = min(o->min_bs[DDIR_TRIM], o->rw_min_bs);

	/*
	 * For random IO, allow blockalign offset other than min_bs.
	 */
	if (!o->ba[DDIR_READ] || !td_random(td))
		o->ba[DDIR_READ] = o->min_bs[DDIR_READ];
	if (!o->ba[DDIR_WRITE] || !td_random(td))
		o->ba[DDIR_WRITE] = o->min_bs[DDIR_WRITE];
	if (!o->ba[DDIR_TRIM] || !td_random(td))
		o->ba[DDIR_TRIM] = o->min_bs[DDIR_TRIM];

	if ((o->ba[DDIR_READ] != o->min_bs[DDIR_READ] ||
	    o->ba[DDIR_WRITE] != o->min_bs[DDIR_WRITE] ||
	    o->ba[DDIR_TRIM] != o->min_bs[DDIR_TRIM]) &&
	    !o->norandommap) {
		log_err("fio: Any use of blockalign= turns off randommap\n");
		o->norandommap = 1;
		ret = warnings_fatal;
	}

	if (!o->file_size_high)
		o->file_size_high = o->file_size_low;

	if (o->start_delay_high)
		o->start_delay = get_rand_start_delay(td);

	if (o->norandommap && o->verify != VERIFY_NONE
	    && !fixed_block_size(o))  {
		log_err("fio: norandommap given for variable block sizes, "
			"verify limited\n");
		ret = warnings_fatal;
	}
	if (o->bs_unaligned && (o->odirect || td->io_ops->flags & FIO_RAWIO))
		log_err("fio: bs_unaligned may not work with raw io\n");

	/*
	 * thinktime_spin must be less than thinktime
	 */
	if (o->thinktime_spin > o->thinktime)
		o->thinktime_spin = o->thinktime;

	/*
	 * The low water mark cannot be bigger than the iodepth
	 */
	if (o->iodepth_low > o->iodepth || !o->iodepth_low)
		o->iodepth_low = o->iodepth;

	/*
	 * If batch number isn't set, default to the same as iodepth
	 */
	if (o->iodepth_batch > o->iodepth || !o->iodepth_batch)
		o->iodepth_batch = o->iodepth;

	/*
	 * If max batch complete number isn't set or set incorrectly,
	 * default to the same as iodepth_batch_complete_min
	 */
	if (o->iodepth_batch_complete_min > o->iodepth_batch_complete_max)
		o->iodepth_batch_complete_max = o->iodepth_batch_complete_min;

	if (o->nr_files > td->files_index)
		o->nr_files = td->files_index;

	if (o->open_files > o->nr_files || !o->open_files)
		o->open_files = o->nr_files;

	if (((o->rate[DDIR_READ] + o->rate[DDIR_WRITE] + o->rate[DDIR_TRIM]) &&
	    (o->rate_iops[DDIR_READ] + o->rate_iops[DDIR_WRITE] + o->rate_iops[DDIR_TRIM])) ||
	    ((o->ratemin[DDIR_READ] + o->ratemin[DDIR_WRITE] + o->ratemin[DDIR_TRIM]) &&
	    (o->rate_iops_min[DDIR_READ] + o->rate_iops_min[DDIR_WRITE] + o->rate_iops_min[DDIR_TRIM]))) {
		log_err("fio: rate and rate_iops are mutually exclusive\n");
		ret = 1;
	}
	if ((o->rate[DDIR_READ] && (o->rate[DDIR_READ] < o->ratemin[DDIR_READ])) ||
	    (o->rate[DDIR_WRITE] && (o->rate[DDIR_WRITE] < o->ratemin[DDIR_WRITE])) ||
	    (o->rate[DDIR_TRIM] && (o->rate[DDIR_TRIM] < o->ratemin[DDIR_TRIM])) ||
	    (o->rate_iops[DDIR_READ] && (o->rate_iops[DDIR_READ] < o->rate_iops_min[DDIR_READ])) ||
	    (o->rate_iops[DDIR_WRITE] && (o->rate_iops[DDIR_WRITE] < o->rate_iops_min[DDIR_WRITE])) ||
	    (o->rate_iops[DDIR_TRIM] && (o->rate_iops[DDIR_TRIM] < o->rate_iops_min[DDIR_TRIM]))) {
		log_err("fio: minimum rate exceeds rate\n");
		ret = 1;
	}

	if (!o->timeout && o->time_based) {
		log_err("fio: time_based requires a runtime/timeout setting\n");
		o->time_based = 0;
		ret = warnings_fatal;
	}

	if (o->fill_device && !o->size)
		o->size = -1ULL;

	if (o->verify != VERIFY_NONE) {
		if (td_write(td) && o->do_verify && o->numjobs > 1) {
			log_info("Multiple writers may overwrite blocks that "
				"belong to other jobs. This can cause "
				"verification failures.\n");
			ret = warnings_fatal;
		}

		if (!fio_option_is_set(o, refill_buffers))
			o->refill_buffers = 1;

		if (o->max_bs[DDIR_WRITE] != o->min_bs[DDIR_WRITE] &&
		    !o->verify_interval)
			o->verify_interval = o->min_bs[DDIR_WRITE];

		/*
		 * Verify interval must be smaller or equal to the
		 * write size.
		 */
		if (o->verify_interval > o->min_bs[DDIR_WRITE])
			o->verify_interval = o->min_bs[DDIR_WRITE];
		else if (td_read(td) && o->verify_interval > o->min_bs[DDIR_READ])
			o->verify_interval = o->min_bs[DDIR_READ];
	}

	if (o->pre_read) {
		o->invalidate_cache = 0;
		if (td->io_ops->flags & FIO_PIPEIO) {
			log_info("fio: cannot pre-read files with an IO engine"
				 " that isn't seekable. Pre-read disabled.\n");
			ret = warnings_fatal;
		}
	}

	if (!o->unit_base) {
		if (td->io_ops->flags & FIO_BIT_BASED)
			o->unit_base = 1;
		else
			o->unit_base = 8;
	}

#ifndef CONFIG_FDATASYNC
	if (o->fdatasync_blocks) {
		log_info("fio: this platform does not support fdatasync()"
			 " falling back to using fsync().  Use the 'fsync'"
			 " option instead of 'fdatasync' to get rid of"
			 " this warning\n");
		o->fsync_blocks = o->fdatasync_blocks;
		o->fdatasync_blocks = 0;
		ret = warnings_fatal;
	}
#endif

#ifdef WIN32
	/*
	 * Windows doesn't support O_DIRECT or O_SYNC with the _open interface,
	 * so fail if we're passed those flags
	 */
	if ((td->io_ops->flags & FIO_SYNCIO) && (td->o.odirect || td->o.sync_io)) {
		log_err("fio: Windows does not support direct or non-buffered io with"
				" the synchronous ioengines. Use the 'windowsaio' ioengine"
				" with 'direct=1' and 'iodepth=1' instead.\n");
		ret = 1;
	}
#endif

	/*
	 * For fully compressible data, just zero them at init time.
	 * It's faster than repeatedly filling it. For non-zero
	 * compression, we should have refill_buffers set. Set it, unless
	 * the job file already changed it.
	 */
	if (o->compress_percentage) {
		if (o->compress_percentage == 100) {
			o->zero_buffers = 1;
			o->compress_percentage = 0;
		} else if (!fio_option_is_set(o, refill_buffers))
			o->refill_buffers = 1;
	}

	/*
	 * Using a non-uniform random distribution excludes usage of
	 * a random map
	 */
	if (td->o.random_distribution != FIO_RAND_DIST_RANDOM)
		td->o.norandommap = 1;

	/*
	 * If size is set but less than the min block size, complain
	 */
	if (o->size && o->size < td_min_bs(td)) {
		log_err("fio: size too small, must be larger than the IO size: %llu\n", (unsigned long long) o->size);
		ret = 1;
	}

	/*
	 * O_ATOMIC implies O_DIRECT
	 */
	if (td->o.oatomic)
		td->o.odirect = 1;

	/*
	 * If randseed is set, that overrides randrepeat
	 */
	if (fio_option_is_set(&td->o, rand_seed))
		td->o.rand_repeatable = 0;

	if ((td->io_ops->flags & FIO_NOEXTEND) && td->o.file_append) {
		log_err("fio: can't append/extent with IO engine %s\n", td->io_ops->name);
		ret = 1;
	}

	if (fio_option_is_set(o, gtod_cpu)) {
		fio_gtod_init();
		fio_gtod_set_cpu(o->gtod_cpu);
		fio_gtod_offload = 1;
	}

	td->loops = o->loops;
	if (!td->loops)
		td->loops = 1;

	if (td->o.block_error_hist && td->o.nr_files != 1) {
		log_err("fio: block error histogram only available with "
			"with a single file per job, but %d files "
			"provided\n", td->o.nr_files);
		ret = 1;
	}

	return ret;
}

/*
 * This function leaks the buffer
 */
char *fio_uint_to_kmg(unsigned int val)
{
	char *buf = malloc(32);
	char post[] = { 0, 'K', 'M', 'G', 'P', 'E', 0 };
	char *p = post;

	do {
		if (val & 1023)
			break;

		val >>= 10;
		p++;
	} while (*p);

	snprintf(buf, 32, "%u%c", val, *p);
	return buf;
}

/* External engines are specified by "external:name.o") */
static const char *get_engine_name(const char *str)
{
	char *p = strstr(str, ":");

	if (!p)
		return str;

	p++;
	strip_blank_front(&p);
	strip_blank_end(p);
	return p;
}

static int exists_and_not_file(const char *filename)
{
	struct stat sb;

	if (lstat(filename, &sb) == -1)
		return 0;

	/* \\.\ is the device namespace in Windows, where every file
	 * is a device node */
	if (S_ISREG(sb.st_mode) && strncmp(filename, "\\\\.\\", 4) != 0)
		return 0;

	return 1;
}

static void td_fill_rand_seeds_internal(struct thread_data *td, int use64)
{
	init_rand_seed(&td->bsrange_state, td->rand_seeds[FIO_RAND_BS_OFF], use64);
	init_rand_seed(&td->verify_state, td->rand_seeds[FIO_RAND_VER_OFF], use64);
	init_rand_seed(&td->rwmix_state, td->rand_seeds[FIO_RAND_MIX_OFF], use64);

	if (td->o.file_service_type == FIO_FSERVICE_RANDOM)
		init_rand_seed(&td->next_file_state, td->rand_seeds[FIO_RAND_FILE_OFF], use64);

	init_rand_seed(&td->file_size_state, td->rand_seeds[FIO_RAND_FILE_SIZE_OFF], use64);
	init_rand_seed(&td->trim_state, td->rand_seeds[FIO_RAND_TRIM_OFF], use64);
	init_rand_seed(&td->delay_state, td->rand_seeds[FIO_RAND_START_DELAY], use64);
	init_rand_seed(&td->poisson_state, td->rand_seeds[FIO_RAND_POISSON_OFF], 0);

	if (!td_random(td))
		return;

	if (td->o.rand_repeatable)
		td->rand_seeds[FIO_RAND_BLOCK_OFF] = FIO_RANDSEED * td->thread_number;

	init_rand_seed(&td->random_state, td->rand_seeds[FIO_RAND_BLOCK_OFF], use64);
	init_rand_seed(&td->seq_rand_state[DDIR_READ], td->rand_seeds[FIO_RAND_SEQ_RAND_READ_OFF], use64);
	init_rand_seed(&td->seq_rand_state[DDIR_WRITE], td->rand_seeds[FIO_RAND_SEQ_RAND_WRITE_OFF], use64);
	init_rand_seed(&td->seq_rand_state[DDIR_TRIM], td->rand_seeds[FIO_RAND_SEQ_RAND_TRIM_OFF], use64);
}

void td_fill_rand_seeds(struct thread_data *td)
{
	int use64;

	if (td->o.allrand_repeatable) {
		unsigned int i;

		for (i = 0; i < FIO_RAND_NR_OFFS; i++)
			td->rand_seeds[i] = FIO_RANDSEED * td->thread_number
			       	+ i;
	}

	if (td->o.random_generator == FIO_RAND_GEN_TAUSWORTHE64)
		use64 = 1;
	else
		use64 = 0;

	td_fill_rand_seeds_internal(td, use64);

	init_rand_seed(&td->buf_state, td->rand_seeds[FIO_RAND_BUF_OFF], use64);
	frand_copy(&td->buf_state_prev, &td->buf_state);

	init_rand_seed(&td->dedupe_state, td->rand_seeds[FIO_DEDUPE_OFF], use64);
	init_rand_seed(&td->zone_state, td->rand_seeds[FIO_RAND_ZONE_OFF], use64);
}

/*
 * Initializes the ioengine configured for a job, if it has not been done so
 * already.
 */
int ioengine_load(struct thread_data *td)
{
	const char *engine;

	/*
	 * Engine has already been loaded.
	 */
	if (td->io_ops)
		return 0;
	if (!td->o.ioengine) {
		log_err("fio: internal fault, no IO engine specified\n");
		return 1;
	}

	engine = get_engine_name(td->o.ioengine);
	td->io_ops = load_ioengine(td, engine);
	if (!td->io_ops) {
		log_err("fio: failed to load engine %s\n", engine);
		return 1;
	}

	if (td->io_ops->option_struct_size && td->io_ops->options) {
		/*
		 * In cases where td->eo is set, clone it for a child thread.
		 * This requires that the parent thread has the same ioengine,
		 * but that requirement must be enforced by the code which
		 * cloned the thread.
		 */
		void *origeo = td->eo;
		/*
		 * Otherwise use the default thread options.
		 */
		if (!origeo && td != &def_thread && def_thread.eo &&
		    def_thread.io_ops->options == td->io_ops->options)
			origeo = def_thread.eo;

		options_init(td->io_ops->options);
		td->eo = malloc(td->io_ops->option_struct_size);
		/*
		 * Use the default thread as an option template if this uses the
		 * same options structure and there are non-default options
		 * used.
		 */
		if (origeo) {
			memcpy(td->eo, origeo, td->io_ops->option_struct_size);
			options_mem_dupe(td->eo, td->io_ops->options);
		} else {
			memset(td->eo, 0, td->io_ops->option_struct_size);
			fill_default_options(td->eo, td->io_ops->options);
		}
		*(struct thread_data **)td->eo = td;
	}

	return 0;
}

static void init_flags(struct thread_data *td)
{
	struct thread_options *o = &td->o;

	if (o->verify_backlog)
		td->flags |= TD_F_VER_BACKLOG;
	if (o->trim_backlog)
		td->flags |= TD_F_TRIM_BACKLOG;
	if (o->read_iolog_file)
		td->flags |= TD_F_READ_IOLOG;
	if (o->refill_buffers)
		td->flags |= TD_F_REFILL_BUFFERS;
	/*
	 * Always scramble buffers if asked to
	 */
	if (o->scramble_buffers && fio_option_is_set(o, scramble_buffers))
		td->flags |= TD_F_SCRAMBLE_BUFFERS;
	/*
	 * But also scramble buffers, unless we were explicitly asked
	 * to zero them.
	 */
	if (o->scramble_buffers && !(o->zero_buffers &&
	    fio_option_is_set(o, zero_buffers)))
		td->flags |= TD_F_SCRAMBLE_BUFFERS;
	if (o->verify != VERIFY_NONE)
		td->flags |= TD_F_VER_NONE;

	if (o->verify_async || o->io_submit_mode == IO_MODE_OFFLOAD)
		td->flags |= TD_F_NEED_LOCK;
}

static int setup_random_seeds(struct thread_data *td)
{
	unsigned long seed;
	unsigned int i;

	if (!td->o.rand_repeatable && !fio_option_is_set(&td->o, rand_seed))
		return init_random_state(td, td->rand_seeds, sizeof(td->rand_seeds));

	seed = td->o.rand_seed;
	for (i = 0; i < 4; i++)
		seed *= 0x9e370001UL;

	for (i = 0; i < FIO_RAND_NR_OFFS; i++) {
		td->rand_seeds[i] = seed;
		seed *= 0x9e370001UL;
	}

	td_fill_rand_seeds(td);
	return 0;
}

enum {
	FPRE_NONE = 0,
	FPRE_JOBNAME,
	FPRE_JOBNUM,
	FPRE_FILENUM
};

static struct fpre_keyword {
	const char *keyword;
	size_t strlen;
	int key;
} fpre_keywords[] = {
	{ .keyword = "$jobname",	.key = FPRE_JOBNAME, },
	{ .keyword = "$jobnum",		.key = FPRE_JOBNUM, },
	{ .keyword = "$filenum",	.key = FPRE_FILENUM, },
	{ .keyword = NULL, },
	};

static char *make_filename(char *buf, size_t buf_size,struct thread_options *o,
			   const char *jobname, int jobnum, int filenum)
{
	struct fpre_keyword *f;
	char copy[PATH_MAX];
	size_t dst_left = PATH_MAX - 1;

	if (!o->filename_format || !strlen(o->filename_format)) {
		sprintf(buf, "%s.%d.%d", jobname, jobnum, filenum);
		return NULL;
	}

	for (f = &fpre_keywords[0]; f->keyword; f++)
		f->strlen = strlen(f->keyword);

	buf[buf_size - 1] = '\0';
	strncpy(buf, o->filename_format, buf_size - 1);

	memset(copy, 0, sizeof(copy));
	for (f = &fpre_keywords[0]; f->keyword; f++) {
		do {
			size_t pre_len, post_start = 0;
			char *str, *dst = copy;

			str = strcasestr(buf, f->keyword);
			if (!str)
				break;

			pre_len = str - buf;
			if (strlen(str) != f->strlen)
				post_start = pre_len + f->strlen;

			if (pre_len) {
				strncpy(dst, buf, pre_len);
				dst += pre_len;
				dst_left -= pre_len;
			}

			switch (f->key) {
			case FPRE_JOBNAME: {
				int ret;

				ret = snprintf(dst, dst_left, "%s", jobname);
				if (ret < 0)
					break;
				else if (ret > dst_left) {
					log_err("fio: truncated filename\n");
					dst += dst_left;
					dst_left = 0;
				} else {
					dst += ret;
					dst_left -= ret;
				}
				break;
				}
			case FPRE_JOBNUM: {
				int ret;

				ret = snprintf(dst, dst_left, "%d", jobnum);
				if (ret < 0)
					break;
				else if (ret > dst_left) {
					log_err("fio: truncated filename\n");
					dst += dst_left;
					dst_left = 0;
				} else {
					dst += ret;
					dst_left -= ret;
				}
				break;
				}
			case FPRE_FILENUM: {
				int ret;

				ret = snprintf(dst, dst_left, "%d", filenum);
				if (ret < 0)
					break;
				else if (ret > dst_left) {
					log_err("fio: truncated filename\n");
					dst += dst_left;
					dst_left = 0;
				} else {
					dst += ret;
					dst_left -= ret;
				}
				break;
				}
			default:
				assert(0);
				break;
			}

			if (post_start)
				strncpy(dst, buf + post_start, dst_left);

			strncpy(buf, copy, buf_size - 1);
		} while (1);
	}

	return buf;
}

int parse_dryrun(void)
{
	return dump_cmdline || parse_only;
}

static void gen_log_name(char *name, size_t size, const char *logtype,
			 const char *logname, unsigned int num,
			 const char *suf, int per_job)
{
	if (per_job)
		snprintf(name, size, "%s_%s.%d.%s", logname, logtype, num, suf);
	else
		snprintf(name, size, "%s_%s.%s", logname, logtype, suf);
}

static int check_waitees(char *waitee)
{
	struct thread_data *td;
	int i, ret = 0;

	for_each_td(td, i) {
		if (td->subjob_number)
			continue;

		ret += !strcmp(td->o.name, waitee);
	}

	return ret;
}

static bool wait_for_ok(const char *jobname, struct thread_options *o)
{
	int nw;

	if (!o->wait_for)
		return true;

	if (!strcmp(jobname, o->wait_for)) {
		log_err("%s: a job cannot wait for itself (wait_for=%s).\n",
				jobname, o->wait_for);
		return false;
	}

	if (!(nw = check_waitees(o->wait_for))) {
		log_err("%s: waitee job %s unknown.\n", jobname, o->wait_for);
		return false;
	}

	if (nw > 1) {
		log_err("%s: multiple waitees %s found,\n"
			"please avoid duplicates when using wait_for option.\n",
				jobname, o->wait_for);
		return false;
	}

	return true;
}

/*
 * Adds a job to the list of things todo. Sanitizes the various options
 * to make sure we don't have conflicts, and initializes various
 * members of td.
 */
static int add_job(struct thread_data *td, const char *jobname, int job_add_num,
		   int recursed, int client_type)
{
	unsigned int i;
	char fname[PATH_MAX];
	int numjobs, file_alloced;
	struct thread_options *o = &td->o;
	char logname[PATH_MAX + 32];

	/*
	 * the def_thread is just for options, it's not a real job
	 */
	if (td == &def_thread)
		return 0;

	init_flags(td);

	/*
	 * if we are just dumping the output command line, don't add the job
	 */
	if (parse_dryrun()) {
		put_job(td);
		return 0;
	}

	td->client_type = client_type;

	if (profile_td_init(td))
		goto err;

	if (ioengine_load(td))
		goto err;

	if (o->odirect)
		td->io_ops->flags |= FIO_RAWIO;

	file_alloced = 0;
	if (!o->filename && !td->files_index && !o->read_iolog_file) {
		file_alloced = 1;

		if (o->nr_files == 1 && exists_and_not_file(jobname))
			add_file(td, jobname, job_add_num, 0);
		else {
			for (i = 0; i < o->nr_files; i++)
				add_file(td, make_filename(fname, sizeof(fname), o, jobname, job_add_num, i), job_add_num, 0);
		}
	}

	if (fixup_options(td))
		goto err;

	/*
	 * Belongs to fixup_options, but o->name is not necessarily set as yet
	 */
	if (!wait_for_ok(jobname, o))
		goto err;

	flow_init_job(td);

	/*
	 * IO engines only need this for option callbacks, and the address may
	 * change in subprocesses.
	 */
	if (td->eo)
		*(struct thread_data **)td->eo = NULL;

	if (td->io_ops->flags & FIO_DISKLESSIO) {
		struct fio_file *f;

		for_each_file(td, f, i)
			f->real_file_size = -1ULL;
	}

	td->mutex = fio_mutex_init(FIO_MUTEX_LOCKED);

	td->ts.clat_percentiles = o->clat_percentiles;
	td->ts.percentile_precision = o->percentile_precision;
	memcpy(td->ts.percentile_list, o->percentile_list, sizeof(o->percentile_list));

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		td->ts.clat_stat[i].min_val = ULONG_MAX;
		td->ts.slat_stat[i].min_val = ULONG_MAX;
		td->ts.lat_stat[i].min_val = ULONG_MAX;
		td->ts.bw_stat[i].min_val = ULONG_MAX;
	}
	td->ddir_seq_nr = o->ddir_seq_nr;

	if ((o->stonewall || o->new_group) && prev_group_jobs) {
		prev_group_jobs = 0;
		groupid++;
		if (groupid == INT_MAX) {
			log_err("fio: too many groups defined\n");
			goto err;
		}
	}

	td->groupid = groupid;
	prev_group_jobs++;

	if (setup_random_seeds(td)) {
		td_verror(td, errno, "init_random_state");
		goto err;
	}

	if (setup_rate(td))
		goto err;

	if (o->lat_log_file) {
		struct log_params p = {
			.td = td,
			.avg_msec = o->log_avg_msec,
			.log_type = IO_LOG_TYPE_LAT,
			.log_offset = o->log_offset,
			.log_gz = o->log_gz,
			.log_gz_store = o->log_gz_store,
		};
		const char *suf;

		if (p.log_gz_store)
			suf = "log.fz";
		else
			suf = "log";

		gen_log_name(logname, sizeof(logname), "lat", o->lat_log_file,
				td->thread_number, suf, o->per_job_logs);
		setup_log(&td->lat_log, &p, logname);

		gen_log_name(logname, sizeof(logname), "slat", o->lat_log_file,
				td->thread_number, suf, o->per_job_logs);
		setup_log(&td->slat_log, &p, logname);

		gen_log_name(logname, sizeof(logname), "clat", o->lat_log_file,
				td->thread_number, suf, o->per_job_logs);
		setup_log(&td->clat_log, &p, logname);
	}
	if (o->bw_log_file) {
		struct log_params p = {
			.td = td,
			.avg_msec = o->log_avg_msec,
			.log_type = IO_LOG_TYPE_BW,
			.log_offset = o->log_offset,
			.log_gz = o->log_gz,
			.log_gz_store = o->log_gz_store,
		};
		const char *suf;

		if (p.log_gz_store)
			suf = "log.fz";
		else
			suf = "log";

		gen_log_name(logname, sizeof(logname), "bw", o->bw_log_file,
				td->thread_number, suf, o->per_job_logs);
		setup_log(&td->bw_log, &p, logname);
	}
	if (o->iops_log_file) {
		struct log_params p = {
			.td = td,
			.avg_msec = o->log_avg_msec,
			.log_type = IO_LOG_TYPE_IOPS,
			.log_offset = o->log_offset,
			.log_gz = o->log_gz,
			.log_gz_store = o->log_gz_store,
		};
		const char *suf;

		if (p.log_gz_store)
			suf = "log.fz";
		else
			suf = "log";

		gen_log_name(logname, sizeof(logname), "iops", o->iops_log_file,
				td->thread_number, suf, o->per_job_logs);
		setup_log(&td->iops_log, &p, logname);
	}

	if (!o->name)
		o->name = strdup(jobname);

	if (output_format & FIO_OUTPUT_NORMAL) {
		if (!job_add_num) {
			if (is_backend && !recursed)
				fio_server_send_add_job(td);

			if (!(td->io_ops->flags & FIO_NOIO)) {
				char *c1, *c2, *c3, *c4;
				char *c5 = NULL, *c6 = NULL;

				c1 = fio_uint_to_kmg(o->min_bs[DDIR_READ]);
				c2 = fio_uint_to_kmg(o->max_bs[DDIR_READ]);
				c3 = fio_uint_to_kmg(o->min_bs[DDIR_WRITE]);
				c4 = fio_uint_to_kmg(o->max_bs[DDIR_WRITE]);

				if (!o->bs_is_seq_rand) {
					c5 = fio_uint_to_kmg(o->min_bs[DDIR_TRIM]);
					c6 = fio_uint_to_kmg(o->max_bs[DDIR_TRIM]);
				}

				log_info("%s: (g=%d): rw=%s, ", td->o.name,
							td->groupid,
							ddir_str(o->td_ddir));

				if (o->bs_is_seq_rand)
					log_info("bs(seq/rand)=%s-%s/%s-%s, ",
							c1, c2, c3, c4);
				else
					log_info("bs=%s-%s/%s-%s/%s-%s, ",
							c1, c2, c3, c4, c5, c6);

				log_info("ioengine=%s, iodepth=%u\n",
						td->io_ops->name, o->iodepth);

				free(c1);
				free(c2);
				free(c3);
				free(c4);
				free(c5);
				free(c6);
			}
		} else if (job_add_num == 1)
			log_info("...\n");
	}

	/*
	 * recurse add identical jobs, clear numjobs and stonewall options
	 * as they don't apply to sub-jobs
	 */
	numjobs = o->numjobs;
	while (--numjobs) {
		struct thread_data *td_new = get_new_job(0, td, 1, jobname);

		if (!td_new)
			goto err;

		td_new->o.numjobs = 1;
		td_new->o.stonewall = 0;
		td_new->o.new_group = 0;
		td_new->subjob_number = numjobs;

		if (file_alloced) {
			if (td_new->files) {
				struct fio_file *f;
				for_each_file(td_new, f, i) {
					if (f->file_name)
						sfree(f->file_name);
					sfree(f);
				}
				free(td_new->files);
				td_new->files = NULL;
			}
			td_new->files_index = 0;
			td_new->files_size = 0;
			if (td_new->o.filename) {
				free(td_new->o.filename);
				td_new->o.filename = NULL;
			}
		}

		if (add_job(td_new, jobname, numjobs, 1, client_type))
			goto err;
	}

	return 0;
err:
	put_job(td);
	return -1;
}

/*
 * Parse as if 'o' was a command line
 */
void add_job_opts(const char **o, int client_type)
{
	struct thread_data *td, *td_parent;
	int i, in_global = 1;
	char jobname[32];

	i = 0;
	td_parent = td = NULL;
	while (o[i]) {
		if (!strncmp(o[i], "name", 4)) {
			in_global = 0;
			if (td)
				add_job(td, jobname, 0, 0, client_type);
			td = NULL;
			sprintf(jobname, "%s", o[i] + 5);
		}
		if (in_global && !td_parent)
			td_parent = get_new_job(1, &def_thread, 0, jobname);
		else if (!in_global && !td) {
			if (!td_parent)
				td_parent = &def_thread;
			td = get_new_job(0, td_parent, 0, jobname);
		}
		if (in_global)
			fio_options_parse(td_parent, (char **) &o[i], 1);
		else
			fio_options_parse(td, (char **) &o[i], 1);
		i++;
	}

	if (td)
		add_job(td, jobname, 0, 0, client_type);
}

static int skip_this_section(const char *name)
{
	int i;

	if (!nr_job_sections)
		return 0;
	if (!strncmp(name, "global", 6))
		return 0;

	for (i = 0; i < nr_job_sections; i++)
		if (!strcmp(job_sections[i], name))
			return 0;

	return 1;
}

static int is_empty_or_comment(char *line)
{
	unsigned int i;

	for (i = 0; i < strlen(line); i++) {
		if (line[i] == ';')
			return 1;
		if (line[i] == '#')
			return 1;
		if (!isspace((int) line[i]) && !iscntrl((int) line[i]))
			return 0;
	}

	return 1;
}

/*
 * This is our [ini] type file parser.
 */
int __parse_jobs_ini(struct thread_data *td,
		char *file, int is_buf, int stonewall_flag, int type,
		int nested, char *name, char ***popts, int *aopts, int *nopts)
{
	unsigned int global = 0;
	char *string;
	FILE *f;
	char *p;
	int ret = 0, stonewall;
	int first_sect = 1;
	int skip_fgets = 0;
	int inside_skip = 0;
	char **opts;
	int i, alloc_opts, num_opts;

	dprint(FD_PARSE, "Parsing ini file %s\n", file);
	assert(td || !nested);

	if (is_buf)
		f = NULL;
	else {
		if (!strcmp(file, "-"))
			f = stdin;
		else
			f = fopen(file, "r");

		if (!f) {
			int __err = errno;

			log_err("fio: unable to open '%s' job file\n", file);
			if (td)
				td_verror(td, __err, "job file open");
			return 1;
		}
	}

	string = malloc(4096);

	/*
	 * it's really 256 + small bit, 280 should suffice
	 */
	if (!nested) {
		name = malloc(280);
		memset(name, 0, 280);
	}

	opts = NULL;
	if (nested && popts) {
		opts = *popts;
		alloc_opts = *aopts;
		num_opts = *nopts;
	}

	if (!opts) {
		alloc_opts = 8;
		opts = malloc(sizeof(char *) * alloc_opts);
		num_opts = 0;
	}

	stonewall = stonewall_flag;
	do {
		/*
		 * if skip_fgets is set, we already have loaded a line we
		 * haven't handled.
		 */
		if (!skip_fgets) {
			if (is_buf)
				p = strsep(&file, "\n");
			else
				p = fgets(string, 4096, f);
			if (!p)
				break;
		}

		skip_fgets = 0;
		strip_blank_front(&p);
		strip_blank_end(p);

		dprint(FD_PARSE, "%s\n", p);
		if (is_empty_or_comment(p))
			continue;

		if (!nested) {
			if (sscanf(p, "[%255[^\n]]", name) != 1) {
				if (inside_skip)
					continue;

				log_err("fio: option <%s> outside of "
					"[] job section\n", p);
				ret = 1;
				break;
			}

			name[strlen(name) - 1] = '\0';

			if (skip_this_section(name)) {
				inside_skip = 1;
				continue;
			} else
				inside_skip = 0;

			dprint(FD_PARSE, "Parsing section [%s]\n", name);

			global = !strncmp(name, "global", 6);

			if (dump_cmdline) {
				if (first_sect)
					log_info("fio ");
				if (!global)
					log_info("--name=%s ", name);
				first_sect = 0;
			}

			td = get_new_job(global, &def_thread, 0, name);
			if (!td) {
				ret = 1;
				break;
			}

			/*
			 * Separate multiple job files by a stonewall
			 */
			if (!global && stonewall) {
				td->o.stonewall = stonewall;
				stonewall = 0;
			}

			num_opts = 0;
			memset(opts, 0, alloc_opts * sizeof(char *));
		}
		else
			skip_fgets = 1;

		while (1) {
			if (!skip_fgets) {
				if (is_buf)
					p = strsep(&file, "\n");
				else
					p = fgets(string, 4096, f);
				if (!p)
					break;
				dprint(FD_PARSE, "%s", p);
			}
			else
				skip_fgets = 0;

			if (is_empty_or_comment(p))
				continue;

			strip_blank_front(&p);

			/*
			 * new section, break out and make sure we don't
			 * fgets() a new line at the top.
			 */
			if (p[0] == '[') {
				if (nested) {
					log_err("No new sections in included files\n");
					return 1;
				}

				skip_fgets = 1;
				break;
			}

			strip_blank_end(p);

			if (!strncmp(p, "include", strlen("include"))) {
				char *filename = p + strlen("include") + 1,
					*ts, *full_fn = NULL;

				/*
				 * Allow for the include filename
				 * specification to be relative.
				 */
				if (access(filename, F_OK) &&
				    (ts = strrchr(file, '/'))) {
					int len = ts - file +
						strlen(filename) + 2;

					if (!(full_fn = calloc(1, len))) {
						ret = ENOMEM;
						break;
					}

					strncpy(full_fn,
						file, (ts - file) + 1);
					strncpy(full_fn + (ts - file) + 1,
						filename, strlen(filename));
					full_fn[len - 1] = 0;
					filename = full_fn;
				}

				ret = __parse_jobs_ini(td, filename, is_buf,
						       stonewall_flag, type, 1,
						       name, &opts,
						       &alloc_opts, &num_opts);

				if (ret) {
					log_err("Error %d while parsing "
						"include file %s\n",
						ret, filename);
				}

				if (full_fn)
					free(full_fn);

				if (ret)
					break;

				continue;
			}

			if (num_opts == alloc_opts) {
				alloc_opts <<= 1;
				opts = realloc(opts,
						alloc_opts * sizeof(char *));
			}

			opts[num_opts] = strdup(p);
			num_opts++;
		}

		if (nested) {
			*popts = opts;
			*aopts = alloc_opts;
			*nopts = num_opts;
			goto out;
		}

		ret = fio_options_parse(td, opts, num_opts);
		if (!ret) {
			if (dump_cmdline)
				dump_opt_list(td);

			ret = add_job(td, name, 0, 0, type);
		} else {
			log_err("fio: job %s dropped\n", name);
			put_job(td);
		}

		for (i = 0; i < num_opts; i++)
			free(opts[i]);
		num_opts = 0;
	} while (!ret);

	if (dump_cmdline)
		log_info("\n");

	i = 0;
	while (i < nr_job_sections) {
		free(job_sections[i]);
		i++;
	}

	free(opts);
out:
	free(string);
	if (!nested)
		free(name);
	if (!is_buf && f != stdin)
		fclose(f);
	return ret;
}

int parse_jobs_ini(char *file, int is_buf, int stonewall_flag, int type)
{
	return __parse_jobs_ini(NULL, file, is_buf, stonewall_flag, type,
			0, NULL, NULL, NULL, NULL);
}

static int fill_def_thread(void)
{
	memset(&def_thread, 0, sizeof(def_thread));
	INIT_FLIST_HEAD(&def_thread.opt_list);

	fio_getaffinity(getpid(), &def_thread.o.cpumask);
	def_thread.o.error_dump = 1;

	/*
	 * fill default options
	 */
	fio_fill_default_options(&def_thread);
	return 0;
}

static void show_debug_categories(void)
{
#ifdef FIO_INC_DEBUG
	struct debug_level *dl = &debug_levels[0];
	int curlen, first = 1;

	curlen = 0;
	while (dl->name) {
		int has_next = (dl + 1)->name != NULL;

		if (first || curlen + strlen(dl->name) >= 80) {
			if (!first) {
				printf("\n");
				curlen = 0;
			}
			curlen += printf("\t\t\t%s", dl->name);
			curlen += 3 * (8 - 1);
			if (has_next)
				curlen += printf(",");
		} else {
			curlen += printf("%s", dl->name);
			if (has_next)
				curlen += printf(",");
		}
		dl++;
		first = 0;
	}
	printf("\n");
#endif
}

static void usage(const char *name)
{
	printf("%s\n", fio_version_string);
	printf("%s [options] [job options] <job file(s)>\n", name);
	printf("  --debug=options\tEnable debug logging. May be one/more of:\n");
	show_debug_categories();
	printf("  --parse-only\t\tParse options only, don't start any IO\n");
	printf("  --output\t\tWrite output to file\n");
	printf("  --runtime\t\tRuntime in seconds\n");
	printf("  --bandwidth-log\tGenerate per-job bandwidth logs\n");
	printf("  --minimal\t\tMinimal (terse) output\n");
	printf("  --output-format=x\tOutput format (terse,json,json+,normal)\n");
	printf("  --terse-version=x\tSet terse version output format to 'x'\n");
	printf("  --version\t\tPrint version info and exit\n");
	printf("  --help\t\tPrint this page\n");
	printf("  --cpuclock-test\tPerform test/validation of CPU clock\n");
	printf("  --crctest\t\tTest speed of checksum functions\n");
	printf("  --cmdhelp=cmd\t\tPrint command help, \"all\" for all of"
		" them\n");
	printf("  --enghelp=engine\tPrint ioengine help, or list"
		" available ioengines\n");
	printf("  --enghelp=engine,cmd\tPrint help for an ioengine"
		" cmd\n");
	printf("  --showcmd\t\tTurn a job file into command line options\n");
	printf("  --eta=when\t\tWhen ETA estimate should be printed\n");
	printf("            \t\tMay be \"always\", \"never\" or \"auto\"\n");
	printf("  --eta-newline=time\tForce a new line for every 'time'");
	printf(" period passed\n");
	printf("  --status-interval=t\tForce full status dump every");
	printf(" 't' period passed\n");
	printf("  --readonly\t\tTurn on safety read-only checks, preventing"
		" writes\n");
	printf("  --section=name\tOnly run specified section in job file\n");
	printf("  --alloc-size=kb\tSet smalloc pool to this size in kb"
		" (def 1024)\n");
	printf("  --warnings-fatal\tFio parser warnings are fatal\n");
	printf("  --max-jobs=nr\t\tMaximum number of threads/processes to support\n");
	printf("  --server=args\t\tStart a backend fio server\n");
	printf("  --daemonize=pidfile\tBackground fio server, write pid to file\n");
	printf("  --client=hostname\tTalk to remote backend fio server at hostname\n");
	printf("  --remote-config=file\tTell fio server to load this local job file\n");
	printf("  --idle-prof=option\tReport cpu idleness on a system or percpu basis\n"
		"\t\t\t(option=system,percpu) or run unit work\n"
		"\t\t\tcalibration only (option=calibrate)\n");
#ifdef CONFIG_ZLIB
	printf("  --inflate-log=log\tInflate and output compressed log\n");
#endif
	printf("  --trigger-file=file\tExecute trigger cmd when file exists\n");
	printf("  --trigger-timeout=t\tExecute trigger af this time\n");
	printf("  --trigger=cmd\t\tSet this command as local trigger\n");
	printf("  --trigger-remote=cmd\tSet this command as remote trigger\n");
	printf("  --aux-path=path\tUse this path for fio state generated files\n");
	printf("\nFio was written by Jens Axboe <jens.axboe@oracle.com>");
	printf("\n                   Jens Axboe <jaxboe@fusionio.com>");
	printf("\n                   Jens Axboe <axboe@fb.com>\n");
}

#ifdef FIO_INC_DEBUG
struct debug_level debug_levels[] = {
	{ .name = "process",
	  .help = "Process creation/exit logging",
	  .shift = FD_PROCESS,
	},
	{ .name = "file",
	  .help = "File related action logging",
	  .shift = FD_FILE,
	},
	{ .name = "io",
	  .help = "IO and IO engine action logging (offsets, queue, completions, etc)",
	  .shift = FD_IO,
	},
	{ .name = "mem",
	  .help = "Memory allocation/freeing logging",
	  .shift = FD_MEM,
	},
	{ .name = "blktrace",
	  .help = "blktrace action logging",
	  .shift = FD_BLKTRACE,
	},
	{ .name = "verify",
	  .help = "IO verification action logging",
	  .shift = FD_VERIFY,
	},
	{ .name = "random",
	  .help = "Random generation logging",
	  .shift = FD_RANDOM,
	},
	{ .name = "parse",
	  .help = "Parser logging",
	  .shift = FD_PARSE,
	},
	{ .name = "diskutil",
	  .help = "Disk utility logging actions",
	  .shift = FD_DISKUTIL,
	},
	{ .name = "job",
	  .help = "Logging related to creating/destroying jobs",
	  .shift = FD_JOB,
	},
	{ .name = "mutex",
	  .help = "Mutex logging",
	  .shift = FD_MUTEX
	},
	{ .name	= "profile",
	  .help = "Logging related to profiles",
	  .shift = FD_PROFILE,
	},
	{ .name = "time",
	  .help = "Logging related to time keeping functions",
	  .shift = FD_TIME,
	},
	{ .name = "net",
	  .help = "Network logging",
	  .shift = FD_NET,
	},
	{ .name = "rate",
	  .help = "Rate logging",
	  .shift = FD_RATE,
	},
	{ .name = "compress",
	  .help = "Log compression logging",
	  .shift = FD_COMPRESS,
	},
	{ .name = NULL, },
};

static int set_debug(const char *string)
{
	struct debug_level *dl;
	char *p = (char *) string;
	char *opt;
	int i;

	if (!string)
		return 0;

	if (!strcmp(string, "?") || !strcmp(string, "help")) {
		log_info("fio: dumping debug options:");
		for (i = 0; debug_levels[i].name; i++) {
			dl = &debug_levels[i];
			log_info("%s,", dl->name);
		}
		log_info("all\n");
		return 1;
	}

	while ((opt = strsep(&p, ",")) != NULL) {
		int found = 0;

		if (!strncmp(opt, "all", 3)) {
			log_info("fio: set all debug options\n");
			fio_debug = ~0UL;
			continue;
		}

		for (i = 0; debug_levels[i].name; i++) {
			dl = &debug_levels[i];
			found = !strncmp(opt, dl->name, strlen(dl->name));
			if (!found)
				continue;

			if (dl->shift == FD_JOB) {
				opt = strchr(opt, ':');
				if (!opt) {
					log_err("fio: missing job number\n");
					break;
				}
				opt++;
				fio_debug_jobno = atoi(opt);
				log_info("fio: set debug jobno %d\n",
							fio_debug_jobno);
			} else {
				log_info("fio: set debug option %s\n", opt);
				fio_debug |= (1UL << dl->shift);
			}
			break;
		}

		if (!found)
			log_err("fio: debug mask %s not found\n", opt);
	}
	return 0;
}
#else
static int set_debug(const char *string)
{
	log_err("fio: debug tracing not included in build\n");
	return 1;
}
#endif

static void fio_options_fill_optstring(void)
{
	char *ostr = cmd_optstr;
	int i, c;

	c = i = 0;
	while (l_opts[i].name) {
		ostr[c++] = l_opts[i].val;
		if (l_opts[i].has_arg == required_argument)
			ostr[c++] = ':';
		else if (l_opts[i].has_arg == optional_argument) {
			ostr[c++] = ':';
			ostr[c++] = ':';
		}
		i++;
	}
	ostr[c] = '\0';
}

static int client_flag_set(char c)
{
	int i;

	i = 0;
	while (l_opts[i].name) {
		int val = l_opts[i].val;

		if (c == (val & 0xff))
			return (val & FIO_CLIENT_FLAG);

		i++;
	}

	return 0;
}

static void parse_cmd_client(void *client, char *opt)
{
	fio_client_add_cmd_option(client, opt);
}

static void show_closest_option(const char *name)
{
	int best_option, best_distance;
	int i, distance;

	while (*name == '-')
		name++;

	best_option = -1;
	best_distance = INT_MAX;
	i = 0;
	while (l_opts[i].name) {
		distance = string_distance(name, l_opts[i].name);
		if (distance < best_distance) {
			best_distance = distance;
			best_option = i;
		}
		i++;
	}

	if (best_option != -1 && string_distance_ok(name, best_distance))
		log_err("Did you mean %s?\n", l_opts[best_option].name);
}

static int parse_output_format(const char *optarg)
{
	char *p, *orig, *opt;
	int ret = 0;

	p = orig = strdup(optarg);

	output_format = 0;

	while ((opt = strsep(&p, ",")) != NULL) {
		if (!strcmp(opt, "minimal") ||
		    !strcmp(opt, "terse") ||
		    !strcmp(opt, "csv"))
			output_format |= FIO_OUTPUT_TERSE;
		else if (!strcmp(opt, "json"))
			output_format |= FIO_OUTPUT_JSON;
		else if (!strcmp(opt, "json+"))
			output_format |= (FIO_OUTPUT_JSON | FIO_OUTPUT_JSON_PLUS);
		else if (!strcmp(opt, "normal"))
			output_format |= FIO_OUTPUT_NORMAL;
		else {
			log_err("fio: invalid output format %s\n", opt);
			ret = 1;
			break;
		}
	}

	free(orig);
	return ret;
}

int parse_cmd_line(int argc, char *argv[], int client_type)
{
	struct thread_data *td = NULL;
	int c, ini_idx = 0, lidx, ret = 0, do_exit = 0, exit_val = 0;
	char *ostr = cmd_optstr;
	void *pid_file = NULL;
	void *cur_client = NULL;
	int backend = 0;

	/*
	 * Reset optind handling, since we may call this multiple times
	 * for the backend.
	 */
	optind = 1;

	while ((c = getopt_long_only(argc, argv, ostr, l_opts, &lidx)) != -1) {
		if ((c & FIO_CLIENT_FLAG) || client_flag_set(c)) {
			parse_cmd_client(cur_client, argv[optind - 1]);
			c &= ~FIO_CLIENT_FLAG;
		}

		switch (c) {
		case 'a':
			smalloc_pool_size = atoi(optarg);
			break;
		case 't':
			if (check_str_time(optarg, &def_timeout, 1)) {
				log_err("fio: failed parsing time %s\n", optarg);
				do_exit++;
				exit_val = 1;
			}
			break;
		case 'l':
			log_err("fio: --latency-log is deprecated. Use per-job latency log options.\n");
			do_exit++;
			exit_val = 1;
			break;
		case 'b':
			write_bw_log = 1;
			break;
		case 'o':
			if (f_out && f_out != stdout)
				fclose(f_out);

			f_out = fopen(optarg, "w+");
			if (!f_out) {
				perror("fopen output");
				exit(1);
			}
			f_err = f_out;
			break;
		case 'm':
			output_format = FIO_OUTPUT_TERSE;
			break;
		case 'F':
			if (!optarg) {
				log_err("fio: missing --output-format argument\n");
				exit_val = 1;
				do_exit++;
				break;
			}
			if (parse_output_format(optarg)) {
				log_err("fio: failed parsing output-format\n");
				exit_val = 1;
				do_exit++;
				break;
			}
			break;
		case 'f':
			output_format |= FIO_OUTPUT_TERSE;
			break;
		case 'h':
			did_arg = 1;
			if (!cur_client) {
				usage(argv[0]);
				do_exit++;
			}
			break;
		case 'c':
			did_arg = 1;
			if (!cur_client) {
				fio_show_option_help(optarg);
				do_exit++;
			}
			break;
		case 'i':
			did_arg = 1;
			if (!cur_client) {
				fio_show_ioengine_help(optarg);
				do_exit++;
			}
			break;
		case 's':
			did_arg = 1;
			dump_cmdline = 1;
			break;
		case 'r':
			read_only = 1;
			break;
		case 'v':
			did_arg = 1;
			if (!cur_client) {
				log_info("%s\n", fio_version_string);
				do_exit++;
			}
			break;
		case 'V':
			terse_version = atoi(optarg);
			if (!(terse_version == 2 || terse_version == 3 ||
			     terse_version == 4)) {
				log_err("fio: bad terse version format\n");
				exit_val = 1;
				do_exit++;
			}
			break;
		case 'e':
			if (!strcmp("always", optarg))
				eta_print = FIO_ETA_ALWAYS;
			else if (!strcmp("never", optarg))
				eta_print = FIO_ETA_NEVER;
			break;
		case 'E': {
			long long t = 0;

			if (check_str_time(optarg, &t, 1)) {
				log_err("fio: failed parsing eta time %s\n", optarg);
				exit_val = 1;
				do_exit++;
			}
			eta_new_line = t / 1000;
			break;
			}
		case 'd':
			if (set_debug(optarg))
				do_exit++;
			break;
		case 'P':
			did_arg = 1;
			parse_only = 1;
			break;
		case 'x': {
			size_t new_size;

			if (!strcmp(optarg, "global")) {
				log_err("fio: can't use global as only "
					"section\n");
				do_exit++;
				exit_val = 1;
				break;
			}
			new_size = (nr_job_sections + 1) * sizeof(char *);
			job_sections = realloc(job_sections, new_size);
			job_sections[nr_job_sections] = strdup(optarg);
			nr_job_sections++;
			break;
			}
#ifdef CONFIG_ZLIB
		case 'X':
			exit_val = iolog_file_inflate(optarg);
			did_arg++;
			do_exit++;
			break;
#endif
		case 'p':
			did_arg = 1;
			if (exec_profile)
				free(exec_profile);
			exec_profile = strdup(optarg);
			break;
		case FIO_GETOPT_JOB: {
			const char *opt = l_opts[lidx].name;
			char *val = optarg;

			if (!strncmp(opt, "name", 4) && td) {
				ret = add_job(td, td->o.name ?: "fio", 0, 0, client_type);
				if (ret)
					goto out_free;
				td = NULL;
				did_arg = 1;
			}
			if (!td) {
				int is_section = !strncmp(opt, "name", 4);
				int global = 0;

				if (!is_section || !strncmp(val, "global", 6))
					global = 1;

				if (is_section && skip_this_section(val))
					continue;

				td = get_new_job(global, &def_thread, 1, NULL);
				if (!td || ioengine_load(td)) {
					if (td) {
						put_job(td);
						td = NULL;
					}
					do_exit++;
					exit_val = 1;
					break;
				}
				fio_options_set_ioengine_opts(l_opts, td);
			}

			if ((!val || !strlen(val)) &&
			    l_opts[lidx].has_arg == required_argument) {
				log_err("fio: option %s requires an argument\n", opt);
				ret = 1;
			} else
				ret = fio_cmd_option_parse(td, opt, val);

			if (ret) {
				if (td) {
					put_job(td);
					td = NULL;
				}
				do_exit++;
				exit_val = 1;
			}

			if (!ret && !strcmp(opt, "ioengine")) {
				free_ioengine(td);
				if (ioengine_load(td)) {
					put_job(td);
					td = NULL;
					do_exit++;
					exit_val = 1;
					break;
				}
				fio_options_set_ioengine_opts(l_opts, td);
			}
			break;
		}
		case FIO_GETOPT_IOENGINE: {
			const char *opt = l_opts[lidx].name;
			char *val = optarg;

			if (!td)
				break;

			ret = fio_cmd_ioengine_option_parse(td, opt, val);
			break;
		}
		case 'w':
			warnings_fatal = 1;
			break;
		case 'j':
			max_jobs = atoi(optarg);
			if (!max_jobs || max_jobs > REAL_MAX_JOBS) {
				log_err("fio: invalid max jobs: %d\n", max_jobs);
				do_exit++;
				exit_val = 1;
			}
			break;
		case 'S':
			did_arg = 1;
#ifndef CONFIG_NO_SHM
			if (nr_clients) {
				log_err("fio: can't be both client and server\n");
				do_exit++;
				exit_val = 1;
				break;
			}
			if (optarg)
				fio_server_set_arg(optarg);
			is_backend = 1;
			backend = 1;
#else
			log_err("fio: client/server requires SHM support\n");
			do_exit++;
			exit_val = 1;
#endif
			break;
		case 'D':
			if (pid_file)
				free(pid_file);
			pid_file = strdup(optarg);
			break;
		case 'I':
			if ((ret = fio_idle_prof_parse_opt(optarg))) {
				/* exit on error and calibration only */
				did_arg = 1;
				do_exit++;
				if (ret == -1)
					exit_val = 1;
			}
			break;
		case 'C':
			did_arg = 1;
			if (is_backend) {
				log_err("fio: can't be both client and server\n");
				do_exit++;
				exit_val = 1;
				break;
			}
			/* if --client parameter contains a pathname */
			if (0 == access(optarg, R_OK)) {
				/* file contains a list of host addrs or names */
				char hostaddr[PATH_MAX] = {0};
				char formatstr[8];
				FILE * hostf = fopen(optarg, "r");
				if (!hostf) {
					log_err("fio: could not open client list file %s for read\n", optarg);
					do_exit++;
					exit_val = 1;
					break;
				}
				sprintf(formatstr, "%%%ds", PATH_MAX - 1);
				/*
				 * read at most PATH_MAX-1 chars from each
				 * record in this file
				 */
				while (fscanf(hostf, formatstr, hostaddr) == 1) {
					/* expect EVERY host in file to be valid */
					if (fio_client_add(&fio_client_ops, hostaddr, &cur_client)) {
						log_err("fio: failed adding client %s from file %s\n", hostaddr, optarg);
						do_exit++;
						exit_val = 1;
						break;
					}
				}
				fclose(hostf);
				break; /* no possibility of job file for "this client only" */
			}
			if (fio_client_add(&fio_client_ops, optarg, &cur_client)) {
				log_err("fio: failed adding client %s\n", optarg);
				do_exit++;
				exit_val = 1;
				break;
			}
			/*
			 * If the next argument exists and isn't an option,
			 * assume it's a job file for this client only.
			 */
			while (optind < argc) {
				if (!strncmp(argv[optind], "--", 2) ||
				    !strncmp(argv[optind], "-", 1))
					break;

				if (fio_client_add_ini_file(cur_client, argv[optind], 0))
					break;
				optind++;
			}
			break;
		case 'R':
			did_arg = 1;
			if (fio_client_add_ini_file(cur_client, optarg, 1)) {
				do_exit++;
				exit_val = 1;
			}
			break;
		case 'T':
			did_arg = 1;
			do_exit++;
			exit_val = fio_monotonic_clocktest(1);
			break;
		case 'G':
			did_arg = 1;
			do_exit++;
			exit_val = fio_crctest(optarg);
			break;
		case 'L': {
			long long val;

			if (check_str_time(optarg, &val, 1)) {
				log_err("fio: failed parsing time %s\n", optarg);
				do_exit++;
				exit_val = 1;
				break;
			}
			status_interval = val / 1000;
			break;
			}
		case 'W':
			if (trigger_file)
				free(trigger_file);
			trigger_file = strdup(optarg);
			break;
		case 'H':
			if (trigger_cmd)
				free(trigger_cmd);
			trigger_cmd = strdup(optarg);
			break;
		case 'J':
			if (trigger_remote_cmd)
				free(trigger_remote_cmd);
			trigger_remote_cmd = strdup(optarg);
			break;
		case 'K':
			if (aux_path)
				free(aux_path);
			aux_path = strdup(optarg);
			break;
		case 'B':
			if (check_str_time(optarg, &trigger_timeout, 1)) {
				log_err("fio: failed parsing time %s\n", optarg);
				do_exit++;
				exit_val = 1;
			}
			trigger_timeout /= 1000000;
			break;
		case '?':
			log_err("%s: unrecognized option '%s'\n", argv[0],
							argv[optind - 1]);
			show_closest_option(argv[optind - 1]);
		default:
			do_exit++;
			exit_val = 1;
			break;
		}
		if (do_exit)
			break;
	}

	if (do_exit && !(is_backend || nr_clients))
		exit(exit_val);

	if (nr_clients && fio_clients_connect())
		exit(1);

	if (is_backend && backend)
		return fio_start_server(pid_file);
	else if (pid_file)
		free(pid_file);

	if (td) {
		if (!ret) {
			ret = add_job(td, td->o.name ?: "fio", 0, 0, client_type);
			if (ret)
				did_arg = 1;
		}
	}

	while (!ret && optind < argc) {
		ini_idx++;
		ini_file = realloc(ini_file, ini_idx * sizeof(char *));
		ini_file[ini_idx - 1] = strdup(argv[optind]);
		optind++;
	}

out_free:
	if (pid_file)
		free(pid_file);

	return ini_idx;
}

int fio_init_options(void)
{
	f_out = stdout;
	f_err = stderr;

	fio_options_fill_optstring();
	fio_options_dup_and_init(l_opts);

	atexit(free_shm);

	if (fill_def_thread())
		return 1;

	return 0;
}

extern int fio_check_options(struct thread_options *);

int parse_options(int argc, char *argv[])
{
	const int type = FIO_CLIENT_TYPE_CLI;
	int job_files, i;

	if (fio_init_options())
		return 1;
	if (fio_test_cconv(&def_thread.o))
		log_err("fio: failed internal cconv test\n");

	job_files = parse_cmd_line(argc, argv, type);

	if (job_files > 0) {
		for (i = 0; i < job_files; i++) {
			if (i && fill_def_thread())
				return 1;
			if (nr_clients) {
				if (fio_clients_send_ini(ini_file[i]))
					return 1;
				free(ini_file[i]);
			} else if (!is_backend) {
				if (parse_jobs_ini(ini_file[i], 0, i, type))
					return 1;
				free(ini_file[i]);
			}
		}
	} else if (nr_clients) {
		if (fill_def_thread())
			return 1;
		if (fio_clients_send_ini(NULL))
			return 1;
	}

	free(ini_file);
	fio_options_free(&def_thread);
	filesetup_mem_free();

	if (!thread_number) {
		if (parse_dryrun())
			return 0;
		if (exec_profile)
			return 0;
		if (is_backend || nr_clients)
			return 0;
		if (did_arg)
			return 0;

		log_err("No jobs(s) defined\n\n");

		if (!did_arg) {
			usage(argv[0]);
			return 1;
		}

		return 0;
	}

	if (output_format & FIO_OUTPUT_NORMAL)
		log_info("%s\n", fio_version_string);

	return 0;
}

void options_default_fill(struct thread_options *o)
{
	memcpy(o, &def_thread.o, sizeof(*o));
}

struct thread_data *get_global_options(void)
{
	return &def_thread;
}
