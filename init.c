/*
 * This file contains job initialization and setup functions.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/types.h>
#include <dlfcn.h>
#ifdef CONFIG_VALGRIND_DEV
#include <valgrind/drd.h>
#else
#define DRD_IGNORE_VAR(x) do { } while (0)
#endif

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
#include "steadystate.h"
#include "blktrace.h"

#include "oslib/asprintf.h"
#include "oslib/getopt.h"
#include "oslib/strcasestr.h"

#include "crc/test.h"
#include "lib/pow2.h"
#include "lib/memcpy.h"

const char fio_version_string[] = FIO_VERSION;

#define FIO_RANDSEED		(0xb1899bedUL)

static char **ini_file;
static bool dump_cmdline;
static bool parse_only;
static bool merge_blktrace_only;

static struct thread_data def_thread;
struct thread_segment segments[REAL_MAX_SEG];
static char **job_sections;
static int nr_job_sections;

bool exitall_on_terminate = false;
int output_format = FIO_OUTPUT_NORMAL;
int eta_print = FIO_ETA_AUTO;
unsigned int eta_interval_msec = 1000;
int eta_new_line = 0;
FILE *f_out = NULL;
FILE *f_err = NULL;
char *exec_profile = NULL;
int warnings_fatal = 0;
int terse_version = 3;
bool is_backend = false;
bool is_local_backend = false;
int nr_clients = 0;
bool log_syslog = false;

bool write_bw_log = false;
bool read_only = false;
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
unsigned int *fio_warned = NULL;

static char cmd_optstr[256];
static bool did_arg;

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
		.name		= (char *) "latency-log",
		.has_arg	= required_argument,
		.val		= 'l' | FIO_CLIENT_FLAG,
	},
	{
		.name		= (char *) "bandwidth-log",
		.has_arg	= no_argument,
		.val		= 'b' | FIO_CLIENT_FLAG,
	},
	{
		.name		= (char *) "minimal",
		.has_arg	= no_argument,
		.val		= 'm' | FIO_CLIENT_FLAG,
	},
	{
		.name		= (char *) "output-format",
		.has_arg	= required_argument,
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
		.name		= (char *) "eta-interval",
		.has_arg	= required_argument,
		.val		= 'O' | FIO_CLIENT_FLAG,
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
#ifdef WIN32
	{
		.name		= (char *) "server-internal",
		.has_arg	= required_argument,
		.val		= 'N',
	},
#endif
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
		.name		= (char *) "memcpytest",
		.has_arg	= optional_argument,
		.val		= 'M',
	},
	{
		.name		= (char *) "idle-prof",
		.has_arg	= required_argument,
		.val		= 'I',
	},
	{
		.name		= (char *) "status-interval",
		.has_arg	= required_argument,
		.val		= 'L' | FIO_CLIENT_FLAG,
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
		.name		= (char *) "merge-blktrace-only",
		.has_arg	= no_argument,
		.val		= 'A' | FIO_CLIENT_FLAG,
	},
	{
		.name		= NULL,
	},
};

void free_threads_shm(void)
{
	int i;

	for (i = 0; i < nr_segments; i++) {
		struct thread_segment *seg = &segments[i];

		if (seg->threads) {
			void *tp = seg->threads;
#ifndef CONFIG_NO_SHM
			struct shmid_ds sbuf;

			seg->threads = NULL;
			shmdt(tp);
			shmctl(seg->shm_id, IPC_RMID, &sbuf);
			seg->shm_id = -1;
#else
			seg->threads = NULL;
			free(tp);
#endif
		}
	}

	nr_segments = 0;
	cur_segment = 0;
}

static void free_shm(void)
{
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	if (nr_segments) {
		flow_exit();
		fio_debug_jobp = NULL;
		fio_warned = NULL;
		free_threads_shm();
	}

	free(trigger_file);
	free(trigger_cmd);
	free(trigger_remote_cmd);
	trigger_file = trigger_cmd = trigger_remote_cmd = NULL;

	options_free(fio_options, &def_thread.o);
	fio_filelock_exit();
	file_hash_exit();
	scleanup();
#endif
}

static int add_thread_segment(void)
{
	struct thread_segment *seg = &segments[nr_segments];
	size_t size = JOBS_PER_SEG * sizeof(struct thread_data);
	int i;

	if (nr_segments + 1 >= REAL_MAX_SEG) {
		log_err("error: maximum number of jobs reached.\n");
		return -1;
	}

	size += 2 * sizeof(unsigned int);

#ifndef CONFIG_NO_SHM
	seg->shm_id = shmget(0, size, IPC_CREAT | 0600);
	if (seg->shm_id == -1) {
		if (errno != EINVAL && errno != ENOMEM && errno != ENOSPC)
			perror("shmget");
		return -1;
	}
#else
	seg->threads = malloc(size);
	if (!seg->threads)
		return -1;
#endif

#ifndef CONFIG_NO_SHM
	seg->threads = shmat(seg->shm_id, NULL, 0);
	if (seg->threads == (void *) -1) {
		perror("shmat");
		return 1;
	}
	if (shm_attach_to_open_removed())
		shmctl(seg->shm_id, IPC_RMID, NULL);
#endif

	nr_segments++;

	memset(seg->threads, 0, JOBS_PER_SEG * sizeof(struct thread_data));
	for (i = 0; i < JOBS_PER_SEG; i++)
		DRD_IGNORE_VAR(seg->threads[i]);
	seg->nr_threads = 0;

	/* Not first segment, we're done */
	if (nr_segments != 1) {
		cur_segment++;
		return 0;
	}

	fio_debug_jobp = (unsigned int *)(seg->threads + JOBS_PER_SEG);
	*fio_debug_jobp = -1;
	fio_warned = fio_debug_jobp + 1;
	*fio_warned = 0;

	flow_init();
	return 0;
}

/*
 * The thread areas are shared between the main process and the job
 * threads/processes, and is split into chunks of JOBS_PER_SEG. If the current
 * segment has no more room, add a new chunk.
 */
static int expand_thread_area(void)
{
	struct thread_segment *seg = &segments[cur_segment];

	if (nr_segments && seg->nr_threads < JOBS_PER_SEG)
		return 0;

	return add_thread_segment();
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
static struct thread_data *get_new_job(bool global, struct thread_data *parent,
				       bool preserve_eo, const char *jobname)
{
	struct thread_segment *seg;
	struct thread_data *td;

	if (global)
		return &def_thread;
	if (expand_thread_area()) {
		log_err("error: failed to setup shm segment\n");
		return NULL;
	}

	seg = &segments[cur_segment];
	td = &seg->threads[seg->nr_threads++];
	thread_number++;
	*td = *parent;

	INIT_FLIST_HEAD(&td->opt_list);
	if (parent != &def_thread)
		copy_opt_list(td, parent);

	td->io_ops = NULL;
	td->io_ops_init = 0;
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

	memset(td, 0, sizeof(*td));
	segments[cur_segment].nr_threads--;
	thread_number--;
}

static int __setup_rate(struct thread_data *td, enum fio_ddir ddir)
{
	unsigned long long bs = td->o.min_bs[ddir];

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
	td->last_usec[ddir] = 0;
	return 0;
}

static int setup_rate(struct thread_data *td)
{
	int ret = 0;

	for_each_rw_ddir(ddir) {
		if (td->o.rate[ddir] || td->o.rate_iops[ddir]) {
			ret |= __setup_rate(td, ddir);
		}
	}
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

/*
 * <3 Johannes
 */
static unsigned int gcd(unsigned int m, unsigned int n)
{
	if (!n)
		return m;

	return gcd(n, m % n);
}

/*
 * Lazy way of fixing up options that depend on each other. We could also
 * define option callback handlers, but this is easier.
 */
static int fixup_options(struct thread_data *td)
{
	struct thread_options *o = &td->o;
	int ret = 0;

	/*
	 * Denote whether we are verifying trims. Now we only have to check a
	 * single variable instead of having to check all three options.
	 */
	td->trim_verify = o->verify && o->trim_backlog && o->trim_percentage;
	dprint(FD_VERIFY, "td->trim_verify=%d\n", td->trim_verify);

	if (read_only && (td_write(td) || td_trim(td) || td->trim_verify)) {
		log_err("fio: trim and write operations are not allowed"
			 " with the --readonly parameter.\n");
		ret |= 1;
	}

	if (td_trimwrite(td) && o->num_range > 1) {
		log_err("fio: trimwrite cannot be used with multiple"
			" ranges.\n");
		ret |= 1;
	}

	if (td_trim(td) && o->num_range > 1 &&
	    !td_ioengine_flagged(td, FIO_MULTI_RANGE_TRIM)) {
		log_err("fio: can't use multiple ranges with IO engine %s\n",
			td->io_ops->name);
		ret |= 1;
	}

#ifndef CONFIG_PSHARED
	if (!o->use_thread) {
		log_info("fio: this platform does not support process shared"
			 " mutexes, forcing use of threads. Use the 'thread'"
			 " option to get rid of this warning.\n");
		o->use_thread = 1;
		ret |= warnings_fatal;
	}
#endif

	if (o->write_iolog_file && o->read_iolog_file) {
		log_err("fio: read iolog overrides write_iolog\n");
		free(o->write_iolog_file);
		o->write_iolog_file = NULL;
		ret |= warnings_fatal;
	}

	if (o->zone_mode == ZONE_MODE_NONE && o->zone_size) {
		log_err("fio: --zonemode=none and --zonesize are not compatible.\n");
		ret |= 1;
	}

	if (o->zone_mode == ZONE_MODE_ZBD && !o->create_serialize) {
		log_err("fio: --zonemode=zbd and --create_serialize=0 are not compatible.\n");
		ret |= 1;
	}

	if (o->zone_mode == ZONE_MODE_STRIDED && !o->zone_size) {
		log_err("fio: --zonesize must be specified when using --zonemode=strided.\n");
		ret |= 1;
	}

	if (o->zone_mode == ZONE_MODE_NOT_SPECIFIED) {
		if (o->zone_size)
			o->zone_mode = ZONE_MODE_STRIDED;
		else
			o->zone_mode = ZONE_MODE_NONE;
	}

	/*
	 * Strided zone mode only really works with 1 file.
	 */
	if (o->zone_mode == ZONE_MODE_STRIDED && o->open_files > 1)
		o->zone_mode = ZONE_MODE_NONE;

	/*
	 * If zone_range isn't specified, backward compatibility dictates it
	 * should be made equal to zone_size.
	 */
	if (o->zone_mode == ZONE_MODE_STRIDED && !o->zone_range)
		o->zone_range = o->zone_size;

	/*
	 * SPRandom Requires: random write, random_generator=lfsr, norandommap=1
	 */
	if (o->sprandom) {
		if (td_write(td) && td_random(td)) {
			if (fio_option_is_set(o, random_generator)) {
				if (o->random_generator != FIO_RAND_GEN_LFSR) {
					log_err("fio: sprandom requires random_generator=lfsr\n");
					ret |= 1;
				}
			} else {
				log_info("fio: sprandom sets random_generator=lfsr\n");
				o->random_generator = FIO_RAND_GEN_LFSR;
			}
			if (fio_option_is_set(o, norandommap)) {
				if (o->norandommap == 0) {
					log_err("fio: sprandom requires norandommap=1\n");
					ret |= 1;
				}
				/* if == 1, OK */
			} else {
				log_info("fio: sprandom sets norandommap=1\n");
				o->norandommap = 1;
			}
		} else {
			log_err("fio: sprandom requires random write, random_generator=lfsr, norandommap=1");
			ret |= 1;
		}
	}

	/*
	 * Reads can do overwrites, we always need to pre-create the file
	 */
	if (td_read(td))
		o->overwrite = 1;

	for_each_rw_ddir(ddir) {
		if (!o->min_bs[ddir])
			o->min_bs[ddir] = o->bs[ddir];
		if (!o->max_bs[ddir])
			o->max_bs[ddir] = o->bs[ddir];
	}

	o->rw_min_bs = -1;
	for_each_rw_ddir(ddir) {
		o->rw_min_bs = min(o->rw_min_bs, o->min_bs[ddir]);
	}

	/*
	 * For random IO, allow blockalign offset other than min_bs.
	 */
	for_each_rw_ddir(ddir) {
		if (!o->ba[ddir] || !td_random(td))
			o->ba[ddir] = o->min_bs[ddir];
	}

	if ((o->ba[DDIR_READ] != o->min_bs[DDIR_READ] ||
	    o->ba[DDIR_WRITE] != o->min_bs[DDIR_WRITE] ||
	    o->ba[DDIR_TRIM] != o->min_bs[DDIR_TRIM]) &&
	    !o->norandommap) {
		log_err("fio: Any use of blockalign= turns off randommap\n");
		o->norandommap = 1;
		ret |= warnings_fatal;
	}

	if (!o->file_size_high)
		o->file_size_high = o->file_size_low;

	if (o->start_delay_high) {
		if (!o->start_delay_orig)
			o->start_delay_orig = o->start_delay;
		o->start_delay = rand_between(&td->delay_state,
						o->start_delay_orig,
						o->start_delay_high);
	}

	if (o->norandommap && o->verify != VERIFY_NONE
	    && !fixed_block_size(o))  {
		log_err("fio: norandommap given for variable block sizes, "
			"verify limited\n");
		ret |= warnings_fatal;
	}
	if (o->bs_unaligned && (o->odirect || td_ioengine_flagged(td, FIO_RAWIO)))
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

	/*
	 * There's no need to check for in-flight overlapping IOs if the job
	 * isn't changing data or the maximum iodepth is guaranteed to be 1
	 * when we are not in offload mode
	 */
	if (o->serialize_overlap && !(td->flags & TD_F_READ_IOLOG) &&
	    (!(td_write(td) || td_trim(td)) || o->iodepth == 1) &&
	    o->io_submit_mode != IO_MODE_OFFLOAD)
		o->serialize_overlap = 0;

	if (o->nr_files > td->files_index)
		o->nr_files = td->files_index;

	if (o->open_files > o->nr_files || !o->open_files)
		o->open_files = o->nr_files;

	if (((o->rate[DDIR_READ] + o->rate[DDIR_WRITE] + o->rate[DDIR_TRIM]) &&
	    (o->rate_iops[DDIR_READ] + o->rate_iops[DDIR_WRITE] + o->rate_iops[DDIR_TRIM])) ||
	    ((o->ratemin[DDIR_READ] + o->ratemin[DDIR_WRITE] + o->ratemin[DDIR_TRIM]) &&
	    (o->rate_iops_min[DDIR_READ] + o->rate_iops_min[DDIR_WRITE] + o->rate_iops_min[DDIR_TRIM]))) {
		log_err("fio: rate and rate_iops are mutually exclusive\n");
		ret |= 1;
	}
	for_each_rw_ddir(ddir) {
		if ((o->rate[ddir] && (o->rate[ddir] < o->ratemin[ddir])) ||
		    (o->rate_iops[ddir] && (o->rate_iops[ddir] < o->rate_iops_min[ddir]))) {
			log_err("fio: minimum rate exceeds rate, ddir %d\n", +ddir);
			ret |= 1;
		}
	}

	if (!o->timeout && o->time_based) {
		log_err("fio: time_based requires a runtime/timeout setting\n");
		o->time_based = 0;
		ret |= warnings_fatal;
	}

	if (o->fill_device && !o->size)
		o->size = -1ULL;

	if (o->verify != VERIFY_NONE) {
		if (td_write(td) && o->do_verify && o->numjobs > 1 &&
		    (o->filename ||
		     !(o->unique_filename &&
		       strstr(o->filename_format, "$jobname") &&
		       strstr(o->filename_format, "$jobnum") &&
		       strstr(o->filename_format, "$filenum")))) {
			log_info("fio: multiple writers may overwrite blocks "
				"that belong to other jobs. This can cause "
				"verification failures.\n");
			ret |= warnings_fatal;
		}

		/*
		 * Warn if verification is requested but no verification of any
		 * kind can be started due to time constraints
		 */
		if (td_write(td) && o->do_verify && o->timeout &&
		    o->time_based && !td_read(td) && !o->verify_backlog) {
			log_info("fio: verification read phase will never "
				 "start because write phase uses all of "
				 "runtime\n");
			ret |= warnings_fatal;
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

		/*
		 * Verify interval must be a factor of both min and max
		 * write size
		 */
		if (!o->verify_interval ||
		    (o->min_bs[DDIR_WRITE] % o->verify_interval) ||
		    (o->max_bs[DDIR_WRITE] % o->verify_interval))
			o->verify_interval = gcd(o->min_bs[DDIR_WRITE],
							o->max_bs[DDIR_WRITE]);

		if (o->verify_only) {
			if (!fio_option_is_set(o, verify_write_sequence))
				o->verify_write_sequence = 0;

			if (!fio_option_is_set(o, verify_header_seed))
				o->verify_header_seed = 0;
		}

		if (o->norandommap && !td_ioengine_flagged(td, FIO_SYNCIO) &&
		    o->iodepth > 1) {
			/*
			 * Disable write sequence checks with norandommap and
			 * iodepth > 1.
			 * Unless we were explicitly asked to enable it.
			 */
			if (!fio_option_is_set(o, verify_write_sequence))
				o->verify_write_sequence = 0;
		}

		/*
		 * Verify header should not be offset beyond the verify
		 * interval.
		 */
		if (o->verify_offset + sizeof(struct verify_header) >
		    o->verify_interval) {
			log_err("fio: cannot offset verify header beyond the "
				"verify interval.\n");
			ret |= 1;
		}

		/*
		 * Disable rand_seed check when we have verify_backlog,
		 * zone reset frequency for zonemode=zbd, or if we are using
		 * an RB tree for IO history logs.
		 * Unless we were explicitly asked to enable it.
		 */
		if (!td_write(td) || (td->flags & TD_F_VER_BACKLOG) ||
		    o->zrf.u.f || fio_offset_overlap_risk(td)) {
			if (!fio_option_is_set(o, verify_header_seed))
				o->verify_header_seed = 0;
		}
	}

	if (td->o.oatomic) {
		if (!td_ioengine_flagged(td, FIO_ATOMICWRITES)) {
			log_err("fio: engine does not support atomic writes\n");
			td->o.oatomic = 0;
			ret |= 1;
		}

		if (!td_write(td))
			td->o.oatomic = 0;
	}

	if (o->pre_read) {
		if (o->invalidate_cache)
			o->invalidate_cache = 0;
		if (td_ioengine_flagged(td, FIO_PIPEIO)) {
			log_info("fio: cannot pre-read files with an IO engine"
				 " that isn't seekable. Pre-read disabled.\n");
			ret |= warnings_fatal;
		}
	}

	if (o->unit_base == N2S_NONE) {
		if (td_ioengine_flagged(td, FIO_BIT_BASED))
			o->unit_base = N2S_BITPERSEC;
		else
			o->unit_base = N2S_BYTEPERSEC;
	}

#ifndef CONFIG_FDATASYNC
	if (o->fdatasync_blocks) {
		log_info("fio: this platform does not support fdatasync()"
			 " falling back to using fsync().  Use the 'fsync'"
			 " option instead of 'fdatasync' to get rid of"
			 " this warning\n");
		o->fsync_blocks = o->fdatasync_blocks;
		o->fdatasync_blocks = 0;
		ret |= warnings_fatal;
	}
#endif

#ifdef WIN32
	/*
	 * Windows doesn't support O_DIRECT or O_SYNC with the _open interface,
	 * so fail if we're passed those flags
	 */
	if (td_ioengine_flagged(td, FIO_SYNCIO) && (o->odirect || o->sync_io)) {
		log_err("fio: Windows does not support direct or non-buffered io with"
				" the synchronous ioengines. Use the 'windowsaio' ioengine"
				" with 'direct=1' and 'iodepth=1' instead.\n");
		ret |= 1;
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
		} else if (!fio_option_is_set(o, refill_buffers)) {
			o->refill_buffers = 1;
			td->flags |= TD_F_REFILL_BUFFERS;
		}
	}

	/*
	 * Using a non-uniform random distribution excludes usage of
	 * a random map
	 */
	if (o->random_distribution != FIO_RAND_DIST_RANDOM)
		o->norandommap = 1;

	/*
	 * If size is set but less than the min block size, complain
	 */
	if (o->size && o->size < td_min_bs(td)) {
		log_err("fio: size too small, must not be less than minimum block size: %llu < %llu\n",
			(unsigned long long) o->size, td_min_bs(td));
		ret |= 1;
	}

	/*
	 * If randseed is set, that overrides randrepeat
	 */
	if (fio_option_is_set(o, rand_seed))
		o->rand_repeatable = 0;

	if (td_ioengine_flagged(td, FIO_NOEXTEND) && o->file_append) {
		log_err("fio: can't append/extent with IO engine %s\n", td->io_ops->name);
		ret |= 1;
	}

	if (fio_option_is_set(o, gtod_cpu)) {
		fio_gtod_init();
		fio_gtod_set_cpu(o->gtod_cpu);
		fio_gtod_offload = 1;
	}

	td->loops = o->loops;
	if (!td->loops)
		td->loops = 1;

	if (o->block_error_hist && o->nr_files != 1) {
		log_err("fio: block error histogram only available "
			"with a single file per job, but %d files "
			"provided\n", o->nr_files);
		ret |= 1;
	}

	if (o->disable_lat)
		o->lat_percentiles = 0;
	if (o->disable_clat)
		o->clat_percentiles = 0;
	if (o->disable_slat)
		o->slat_percentiles = 0;

	/* Do this only for the parent job */
	if (!td->subjob_number) {
		/*
		 * Fix these up to be nsec internally
		 */
		for_each_rw_ddir(ddir)
			o->max_latency[ddir] *= 1000ULL;

		o->latency_target *= 1000ULL;
	}

	/*
	 * Dedupe working set verifications
	 */
	if (o->dedupe_percentage && o->dedupe_mode == DEDUPE_MODE_WORKING_SET) {
		if (!fio_option_is_set(o, size)) {
			log_err("fio: pregenerated dedupe working set "
					"requires size to be set\n");
			ret |= 1;
		} else if (o->nr_files != 1) {
			log_err("fio: dedupe working set mode supported with "
					"single file per job, but %d files "
					"provided\n", o->nr_files);
			ret |= 1;
		} else if (o->dedupe_working_set_percentage + o->dedupe_percentage > 100) {
			log_err("fio: impossible to reach expected dedupe percentage %u "
					"since %u percentage of size is reserved to dedupe working set "
					"(those are unique pages)\n",
					o->dedupe_percentage, o->dedupe_working_set_percentage);
			ret |= 1;
		}
	}

	for_each_td(td2) {
		if (td->o.ss_check_interval != td2->o.ss_check_interval) {
			log_err("fio: conflicting ss_check_interval: %llu and %llu, must be globally equal\n",
					td->o.ss_check_interval, td2->o.ss_check_interval);
			ret |= 1;
		}
	} end_for_each();
	if (td->o.ss_dur && td->o.ss_check_interval / 1000L < 1000) {
		log_err("fio: ss_check_interval must be at least 1s\n");
		ret |= 1;

	}
	if (td->o.ss_dur && (td->o.ss_dur % td->o.ss_check_interval != 0 || td->o.ss_dur <= td->o.ss_check_interval)) {
		log_err("fio: ss_duration %lluus must be multiple of ss_check_interval %lluus\n",
				td->o.ss_dur, td->o.ss_check_interval);
		ret |= 1;
	}

	if (td->o.fdp) {
		if (fio_option_is_set(&td->o, dp_type) &&
			(td->o.dp_type == FIO_DP_STREAMS || td->o.dp_type == FIO_DP_NONE)) {
			log_err("fio: fdp=1 is not compatible with dataplacement={streams, none}\n");
			ret |= 1;
		} else {
			td->o.dp_type = FIO_DP_FDP;
		}
	}
	return ret;
}

static void init_rand_file_service(struct thread_data *td)
{
	unsigned long nranges = td->o.nr_files << FIO_FSERVICE_SHIFT;
	const unsigned int seed = td->rand_seeds[FIO_RAND_FILE_OFF];

	if (td->o.file_service_type == FIO_FSERVICE_ZIPF) {
		zipf_init(&td->next_file_zipf, nranges, td->zipf_theta, td->random_center, seed);
		zipf_disable_hash(&td->next_file_zipf);
	} else if (td->o.file_service_type == FIO_FSERVICE_PARETO) {
		pareto_init(&td->next_file_zipf, nranges, td->pareto_h, td->random_center, seed);
		zipf_disable_hash(&td->next_file_zipf);
	} else if (td->o.file_service_type == FIO_FSERVICE_GAUSS) {
		gauss_init(&td->next_file_gauss, nranges, td->gauss_dev, td->random_center, seed);
		gauss_disable_hash(&td->next_file_gauss);
	}
}

void td_fill_rand_seeds(struct thread_data *td)
{
	uint64_t read_seed = td->rand_seeds[FIO_RAND_BS_OFF];
	uint64_t write_seed = td->rand_seeds[FIO_RAND_BS1_OFF];
	uint64_t trim_seed = td->rand_seeds[FIO_RAND_BS2_OFF];
	int i;
	bool use64;

	if (td->o.random_generator == FIO_RAND_GEN_TAUSWORTHE64)
		use64 = true;
	else
		use64 = false;

	/*
	 * trimwrite is special in that we need to generate the same
	 * offsets to get the "write after trim" effect. If we are
	 * using bssplit to set buffer length distributions, ensure that
	 * we seed the trim and write generators identically. Ditto for
	 * verify, read and writes must have the same seed, if we are doing
	 * read verify.
	 */
	if (td->o.verify != VERIFY_NONE)
		write_seed = read_seed;
	if (td_trimwrite(td))
		trim_seed = write_seed;
	init_rand_seed(&td->bsrange_state[DDIR_READ], read_seed, use64);
	init_rand_seed(&td->bsrange_state[DDIR_WRITE], write_seed, use64);
	init_rand_seed(&td->bsrange_state[DDIR_TRIM], trim_seed, use64);

	init_rand_seed(&td->verify_state, td->rand_seeds[FIO_RAND_VER_OFF],
		use64);
	init_rand_seed(&td->rwmix_state, td->rand_seeds[FIO_RAND_MIX_OFF], false);

	if (td->o.file_service_type == FIO_FSERVICE_RANDOM)
		init_rand_seed(&td->next_file_state, td->rand_seeds[FIO_RAND_FILE_OFF], use64);
	else if (td->o.file_service_type & __FIO_FSERVICE_NONUNIFORM)
		init_rand_file_service(td);

	init_rand_seed(&td->file_size_state, td->rand_seeds[FIO_RAND_FILE_SIZE_OFF], use64);
	init_rand_seed(&td->trim_state, td->rand_seeds[FIO_RAND_TRIM_OFF], use64);
	init_rand_seed(&td->delay_state, td->rand_seeds[FIO_RAND_START_DELAY], use64);
	init_rand_seed(&td->poisson_state[0], td->rand_seeds[FIO_RAND_POISSON_OFF], 0);
	init_rand_seed(&td->poisson_state[1], td->rand_seeds[FIO_RAND_POISSON2_OFF], 0);
	init_rand_seed(&td->poisson_state[2], td->rand_seeds[FIO_RAND_POISSON3_OFF], 0);
	init_rand_seed(&td->dedupe_state, td->rand_seeds[FIO_DEDUPE_OFF], false);
	init_rand_seed(&td->zone_state, td->rand_seeds[FIO_RAND_ZONE_OFF], false);
	init_rand_seed(&td->prio_state, td->rand_seeds[FIO_RAND_PRIO_CMDS], false);
	init_rand_seed(&td->dedupe_working_set_index_state, td->rand_seeds[FIO_RAND_DEDUPE_WORKING_SET_IX], use64);

	init_rand_seed(&td->random_state, td->rand_seeds[FIO_RAND_BLOCK_OFF], use64);

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		struct frand_state *s = &td->seq_rand_state[i];

		init_rand_seed(s, td->rand_seeds[FIO_RAND_SEQ_RAND_READ_OFF], false);
	}

	init_rand_seed(&td->buf_state, td->rand_seeds[FIO_RAND_BUF_OFF], use64);
	frand_copy(&td->buf_state_prev, &td->buf_state);

	init_rand_seed(&td->fdp_state, td->rand_seeds[FIO_RAND_FDP_OFF], use64);
	init_rand_seed(&td->sprandom_state, td->rand_seeds[FIO_RAND_SPRANDOM_OFF], false);
}

static int setup_random_seeds(struct thread_data *td)
{
	uint64_t seed;
	unsigned int i;

	if (!td->o.rand_repeatable && !fio_option_is_set(&td->o, rand_seed)) {
		int ret = init_random_seeds(td->rand_seeds, sizeof(td->rand_seeds));
		dprint(FD_RANDOM, "using system RNG for random seeds\n");
		if (ret)
			return ret;
	} else {
		seed = td->o.rand_seed;
		for (i = 0; i < 4; i++)
			seed *= 0x9e370001UL;

		for (i = 0; i < FIO_RAND_NR_OFFS; i++) {
			td->rand_seeds[i] = seed * td->thread_number + i;
			seed *= 0x9e370001UL;
		}
	}

	td_fill_rand_seeds(td);

	dprint(FD_RANDOM, "FIO_RAND_NR_OFFS=%d\n", FIO_RAND_NR_OFFS);
	for (int i = 0; i < FIO_RAND_NR_OFFS; i++)
		dprint(FD_RANDOM, "rand_seeds[%d]=%" PRIu64 "\n", i, td->rand_seeds[i]);

	return 0;
}

/*
 * Initializes the ioengine configured for a job, if it has not been done so
 * already.
 */
int ioengine_load(struct thread_data *td)
{
	if (!td->o.ioengine) {
		log_err("fio: internal fault, no IO engine specified\n");
		return 1;
	}

	if (td->io_ops) {
		struct ioengine_ops *ops;
		void *dlhandle;

		/* An engine is loaded, but the requested ioengine
		 * may have changed.
		 */
		if (!strcmp(td->io_ops->name, td->o.ioengine)) {
			/* The right engine is already loaded */
			return 0;
		}

		/*
		 * Name of file and engine may be different, load ops
		 * for this name and see if they match. If they do, then
		 * the engine is unchanged.
		 */
		dlhandle = td->io_ops->dlhandle;
		ops = load_ioengine(td);
		if (!ops)
			goto fail;

		if (ops == td->io_ops && dlhandle == td->io_ops->dlhandle)
			return 0;

		if (dlhandle && dlhandle != td->io_ops->dlhandle)
			dlclose(dlhandle);

		/* Unload the old engine. */
		free_ioengine(td);
	}

	td->io_ops = load_ioengine(td);
	if (!td->io_ops)
		goto fail;

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
			options_mem_dupe(td->io_ops->options, td->eo);
		} else {
			memset(td->eo, 0, td->io_ops->option_struct_size);
			fill_default_options(td->eo, td->io_ops->options);
		}
		*(struct thread_data **)td->eo = td;
	}

	if (td->o.odirect)
		td->io_ops->flags |= FIO_RAWIO;

	td_set_ioengine_flags(td);
	return 0;

fail:
	log_err("fio: failed to load engine\n");
	return 1;

}

static void init_flags(struct thread_data *td)
{
	struct thread_options *o = &td->o;
	int i;

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
		td->flags |= TD_F_DO_VERIFY;

	if (o->verify_async || o->io_submit_mode == IO_MODE_OFFLOAD)
		td->flags |= TD_F_NEED_LOCK;

	if (o->mem_type == MEM_CUDA_MALLOC)
		td->flags &= ~TD_F_SCRAMBLE_BUFFERS;

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		if (option_check_rate(td, i)) {
			td->flags |= TD_F_CHECK_RATE;
			break;
		}
	}
}

enum {
	FPRE_NONE = 0,
	FPRE_JOBNAME,
	FPRE_JOBNUM,
	FPRE_FILENUM,
	FPRE_CLIENTUID
};

static struct fpre_keyword {
	const char *keyword;
	size_t strlen;
	int key;
} fpre_keywords[] = {
	{ .keyword = "$jobname",	.key = FPRE_JOBNAME, },
	{ .keyword = "$jobnum",		.key = FPRE_JOBNUM, },
	{ .keyword = "$filenum",	.key = FPRE_FILENUM, },
	{ .keyword = "$clientuid",	.key = FPRE_CLIENTUID, },
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
		return buf;
	}

	for (f = &fpre_keywords[0]; f->keyword; f++)
		f->strlen = strlen(f->keyword);

	snprintf(buf, buf_size, "%s", o->filename_format);

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
			case FPRE_CLIENTUID: {
				int ret;
				ret = snprintf(dst, dst_left, "%s", client_sockaddr_str);
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

			snprintf(buf, buf_size, "%s", copy);
		} while (1);
	}

	return buf;
}

bool parse_dryrun(void)
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
	int ret = 0;

	for_each_td(td) {
		if (td->subjob_number)
			continue;

		ret += !strcmp(td->o.name, waitee);
	} end_for_each();

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

static int verify_per_group_options(struct thread_data *td, const char *jobname)
{
	for_each_td(td2) {
		if (td->groupid != td2->groupid)
			continue;

		if (td->o.stats &&
		    td->o.lat_percentiles != td2->o.lat_percentiles) {
			log_err("fio: lat_percentiles in job: %s differs from group\n",
				jobname);
			return 1;
		}
	} end_for_each();

	return 0;
}

/*
 * Treat an empty log file name the same as a one not given
 */
static const char *make_log_name(const char *logname, const char *jobname)
{
	if (logname && strcmp(logname, ""))
		return logname;

	return jobname;
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
	char fname[PATH_MAX + 1];
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

	file_alloced = 0;
	if (!o->filename && !td->files_index && !o->read_iolog_file) {
		file_alloced = 1;

		if (o->nr_files == 1 && exists_and_not_regfile(jobname))
			add_file(td, jobname, job_add_num, 0);
		else {
			for (i = 0; i < o->nr_files; i++)
				add_file(td, make_filename(fname, sizeof(fname), o, jobname, job_add_num, i), job_add_num, 0);
		}
	}

	if (setup_random_seeds(td)) {
		td_verror(td, errno, "setup_random_seeds");
		goto err;
	}

	if (fixup_options(td))
		goto err;

	if (!td->o.dedupe_global && init_dedupe_working_set_seeds(td, 0))
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

	if (td_ioengine_flagged(td, FIO_DISKLESSIO)) {
		struct fio_file *f;

		for_each_file(td, f, i)
			f->real_file_size = -1ULL;
	}

	td->sem = fio_sem_init(FIO_SEM_LOCKED);

	td->ts.clat_percentiles = o->clat_percentiles;
	td->ts.lat_percentiles = o->lat_percentiles;
	td->ts.slat_percentiles = o->slat_percentiles;
	td->ts.percentile_precision = o->percentile_precision;
	memcpy(td->ts.percentile_list, o->percentile_list, sizeof(o->percentile_list));
	td->ts.sig_figs = o->sig_figs;

	init_thread_stat_min_vals(&td->ts);

	/*
	 * td->>ddir_seq_nr needs to be initialized to 1, NOT o->ddir_seq_nr,
	 * so that get_next_offset gets a new random offset the first time it
	 * is called, instead of keeping an initial offset of 0 for the first
	 * nr-1 calls
	 */
	td->ddir_seq_nr = 1;

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

	if (td->o.group_reporting && prev_group_jobs > 1 &&
	    verify_per_group_options(td, jobname))
		goto err;

	if (setup_rate(td))
		goto err;

	if (td_ramp_period_init(td))
		goto err;

	if (o->write_lat_log) {
		struct log_params p = {
			.td = td,
			.avg_msec = o->log_avg_msec,
			.hist_msec = o->log_hist_msec,
			.hist_coarseness = o->log_hist_coarseness,
			.log_type = IO_LOG_TYPE_LAT,
			.log_offset = o->log_offset,
			.log_prio = o->log_prio,
			.log_issue_time = o->log_issue_time,
			.log_gz = o->log_gz,
			.log_gz_store = o->log_gz_store,
		};
		const char *pre = make_log_name(o->lat_log_file, o->name);
		const char *suf;

		if (o->log_issue_time && !o->log_offset) {
			log_err("fio: log_issue_time option requires write_lat_log and log_offset options\n");
			goto err;
		}

		if (p.log_gz_store)
			suf = "log.fz";
		else
			suf = "log";

		if (!o->disable_lat) {
			gen_log_name(logname, sizeof(logname), "lat", pre,
				     td->thread_number, suf, o->per_job_logs);
			setup_log(&td->lat_log, &p, logname);
		}

		if (!o->disable_slat) {
			gen_log_name(logname, sizeof(logname), "slat", pre,
				     td->thread_number, suf, o->per_job_logs);
			setup_log(&td->slat_log, &p, logname);
		}

		if (!o->disable_clat) {
			gen_log_name(logname, sizeof(logname), "clat", pre,
				     td->thread_number, suf, o->per_job_logs);
			setup_log(&td->clat_log, &p, logname);
		}

	} else if (o->log_issue_time) {
		log_err("fio: log_issue_time option requires write_lat_log and log_offset options\n");
		goto err;
	}

	if (o->write_hist_log) {
		struct log_params p = {
			.td = td,
			.avg_msec = o->log_avg_msec,
			.hist_msec = o->log_hist_msec,
			.hist_coarseness = o->log_hist_coarseness,
			.log_type = IO_LOG_TYPE_HIST,
			.log_offset = o->log_offset,
			.log_prio = o->log_prio,
			.log_issue_time = o->log_issue_time,
			.log_gz = o->log_gz,
			.log_gz_store = o->log_gz_store,
		};
		const char *pre = make_log_name(o->hist_log_file, o->name);
		const char *suf;

#ifndef CONFIG_ZLIB
		if (is_backend) {
			log_err("fio: --write_hist_log requires zlib in client/server mode\n");
			goto err;
		}
#endif

		if (p.log_gz_store)
			suf = "log.fz";
		else
			suf = "log";

		gen_log_name(logname, sizeof(logname), "clat_hist", pre,
				td->thread_number, suf, o->per_job_logs);
		setup_log(&td->clat_hist_log, &p, logname);
	}

	if (o->write_bw_log) {
		struct log_params p = {
			.td = td,
			.avg_msec = o->log_avg_msec,
			.hist_msec = o->log_hist_msec,
			.hist_coarseness = o->log_hist_coarseness,
			.log_type = IO_LOG_TYPE_BW,
			.log_offset = o->log_offset,
			.log_prio = o->log_prio,
			.log_issue_time = o->log_issue_time,
			.log_gz = o->log_gz,
			.log_gz_store = o->log_gz_store,
		};
		const char *pre = make_log_name(o->bw_log_file, o->name);
		const char *suf;

		if (fio_option_is_set(o, bw_avg_time))
			p.avg_msec = min(o->log_avg_msec, o->bw_avg_time);
		else
			o->bw_avg_time = p.avg_msec;

		p.hist_msec = o->log_hist_msec;
		p.hist_coarseness = o->log_hist_coarseness;

		if (p.log_gz_store)
			suf = "log.fz";
		else
			suf = "log";

		gen_log_name(logname, sizeof(logname), "bw", pre,
				td->thread_number, suf, o->per_job_logs);
		setup_log(&td->bw_log, &p, logname);
	}
	if (o->write_iops_log) {
		struct log_params p = {
			.td = td,
			.avg_msec = o->log_avg_msec,
			.hist_msec = o->log_hist_msec,
			.hist_coarseness = o->log_hist_coarseness,
			.log_type = IO_LOG_TYPE_IOPS,
			.log_offset = o->log_offset,
			.log_prio = o->log_prio,
			.log_issue_time = o->log_issue_time,
			.log_gz = o->log_gz,
			.log_gz_store = o->log_gz_store,
		};
		const char *pre = make_log_name(o->iops_log_file, o->name);
		const char *suf;

		if (fio_option_is_set(o, iops_avg_time))
			p.avg_msec = min(o->log_avg_msec, o->iops_avg_time);
		else
			o->iops_avg_time = p.avg_msec;

		p.hist_msec = o->log_hist_msec;
		p.hist_coarseness = o->log_hist_coarseness;

		if (p.log_gz_store)
			suf = "log.fz";
		else
			suf = "log";

		gen_log_name(logname, sizeof(logname), "iops", pre,
				td->thread_number, suf, o->per_job_logs);
		setup_log(&td->iops_log, &p, logname);
	}

	if (!o->name)
		o->name = strdup(jobname);

	if (output_format & FIO_OUTPUT_NORMAL) {
		if (!job_add_num) {
			if (is_backend && !recursed)
				fio_server_send_add_job(td);

			if (!td_ioengine_flagged(td, FIO_NOIO)) {
				char *c1, *c2, *c3, *c4;
				char *c5 = NULL, *c6 = NULL;
				int i2p = is_power_of_2(o->kb_base);
				struct buf_output out;

				c1 = num2str(o->min_bs[DDIR_READ], o->sig_figs, 1, i2p, N2S_BYTE);
				c2 = num2str(o->max_bs[DDIR_READ], o->sig_figs, 1, i2p, N2S_BYTE);
				c3 = num2str(o->min_bs[DDIR_WRITE], o->sig_figs, 1, i2p, N2S_BYTE);
				c4 = num2str(o->max_bs[DDIR_WRITE], o->sig_figs, 1, i2p, N2S_BYTE);

				if (!o->bs_is_seq_rand) {
					c5 = num2str(o->min_bs[DDIR_TRIM], o->sig_figs, 1, i2p, N2S_BYTE);
					c6 = num2str(o->max_bs[DDIR_TRIM], o->sig_figs, 1, i2p, N2S_BYTE);
				}

				buf_output_init(&out);
				__log_buf(&out, "%s: (g=%d): rw=%s, ", td->o.name,
							td->groupid,
							ddir_str(o->td_ddir));

				if (o->bs_is_seq_rand)
					__log_buf(&out, "bs=(R) %s-%s, (W) %s-%s, bs_is_seq_rand, ",
							c1, c2, c3, c4);
				else
					__log_buf(&out, "bs=(R) %s-%s, (W) %s-%s, (T) %s-%s, ",
							c1, c2, c3, c4, c5, c6);

				__log_buf(&out, "ioengine=%s, iodepth=%u\n",
						td->io_ops->name, o->iodepth);
				log_info_buf(out.buf, out.buflen);
				buf_output_free(&out);

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

	if (td_steadystate_init(td))
		goto err;

	if (o->merge_blktrace_file && !merge_blktrace_iologs(td))
		goto err;

	if (merge_blktrace_only) {
		put_job(td);
		return 0;
	}

	/*
	 * recurse add identical jobs, clear numjobs and stonewall options
	 * as they don't apply to sub-jobs
	 */
	numjobs = o->numjobs;
	while (--numjobs) {
		struct thread_data *td_new = get_new_job(false, td, true, jobname);

		if (!td_new)
			goto err;

		td_new->o.numjobs = 1;
		td_new->o.stonewall = 0;
		td_new->o.new_group = 0;
		td_new->subjob_number = numjobs;
		td_new->o.ss_dur = o->ss_dur * 1000000l;
		td_new->o.ss_limit = o->ss_limit;

		if (file_alloced) {
			if (td_new->files) {
				struct fio_file *f;
				for_each_file(td_new, f, i)
					fio_file_free(f);
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
			td_parent = get_new_job(true, &def_thread, false, jobname);
		else if (!in_global && !td) {
			if (!td_parent)
				td_parent = &def_thread;
			td = get_new_job(false, td_parent, false, jobname);
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
static int __parse_jobs_ini(struct thread_data *td,
		char *file, int is_buf, int stonewall_flag, int type,
		int nested, char *name, char ***popts, int *aopts, int *nopts)
{
	bool global = false;
	bool stdin_occupied = false;
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
		if (!strcmp(file, "-")) {
			f = stdin;
			stdin_occupied = true;
		} else
			f = fopen(file, "r");

		if (!f) {
			int __err = errno;

			log_err("fio: unable to open '%s' job file\n", file);
			if (td)
				td_verror(td, __err, "job file open");
			return 1;
		}
	}

	string = malloc(OPT_LEN_MAX);

	/*
	 * it's really 256 + small bit, 280 should suffice
	 */
	if (!nested) {
		name = calloc(1, 280);
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
				p = fgets(string, OPT_LEN_MAX, f);
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

			td = get_new_job(global, &def_thread, false, name);
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
					p = fgets(string, OPT_LEN_MAX, f);
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
					ret = 1;
					goto out;
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
					if (asprintf(&full_fn, "%.*s%s",
						 (int)(ts - file + 1), file,
						 filename) < 0) {
						ret = ENOMEM;
						break;
					}
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

		if (!ret && td->o.read_iolog_file != NULL) {
			char *fname = get_name_by_idx(td->o.read_iolog_file,
						      td->subjob_number);
			if (!strcmp(fname, "-")) {
				if (stdin_occupied) {
					log_err("fio: only one user (read_iolog_file/job "
						"file) of stdin is permitted at once but "
						"more than one was found.\n");
					ret = 1;
				}
				stdin_occupied = true;
			}
		}
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

	free(job_sections);
	job_sections = NULL;
	nr_job_sections = 0;

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
	const struct debug_level *dl = &debug_levels[0];
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

/*
 * Following options aren't printed by usage().
 * --append-terse - Equivalent to --output-format=terse, see f6a7df53.
 * --latency-log - Deprecated option.
 */
static void usage(const char *name)
{
	printf("%s\n", fio_version_string);
	printf("%s [options] [job options] <job file(s)>\n", name);
	printf("  --debug=options\tEnable debug logging. May be one/more of:\n");
	show_debug_categories();
	printf("  --parse-only\t\tParse options only, don't start any IO\n");
	printf("  --merge-blktrace-only\tMerge blktraces only, don't start any IO\n");
	printf("  --output\t\tWrite output to file\n");
	printf("  --bandwidth-log\tGenerate aggregate bandwidth logs\n");
	printf("  --minimal\t\tMinimal (terse) output\n");
	printf("  --output-format=type\tOutput format (terse,json,json+,normal)\n");
	printf("  --terse-version=type\tSet terse version output format"
		" (default 3, or 2 or 4 or 5)\n");
	printf("  --version\t\tPrint version info and exit\n");
	printf("  --help\t\tPrint this page\n");
	printf("  --cpuclock-test\tPerform test/validation of CPU clock\n");
	printf("  --crctest=[type]\tTest speed of checksum functions\n");
	printf("  --cmdhelp=cmd\t\tPrint command help, \"all\" for all of"
		" them\n");
	printf("  --enghelp=engine\tPrint ioengine help, or list"
		" available ioengines\n");
	printf("  --enghelp=engine,cmd\tPrint help for an ioengine"
		" cmd\n");
	printf("  --showcmd\t\tTurn a job file into command line options\n");
	printf("  --eta=when\t\tWhen ETA estimate should be printed\n");
	printf("            \t\tMay be \"always\", \"never\" or \"auto\"\n");
	printf("  --eta-newline=t\tForce a new line for every 't'");
	printf(" period passed\n");
	printf("  --status-interval=t\tForce full status dump every");
	printf(" 't' period passed\n");
	printf("  --readonly\t\tTurn on safety read-only checks, preventing"
		" writes\n");
	printf("  --section=name\tOnly run specified section in job file,"
		" multiple sections can be specified\n");
	printf("  --alloc-size=kb\tSet smalloc pool to this size in kb"
		" (def 16384)\n");
	printf("  --warnings-fatal\tFio parser warnings are fatal\n");
	printf("  --max-jobs=nr\t\tMaximum number of threads/processes to support\n");
	printf("  --server=args\t\tStart a backend fio server\n");
	printf("  --daemonize=pidfile\tBackground fio server, write pid to file\n");
	printf("  --client=hostname\tTalk to remote backend(s) fio server at hostname\n");
	printf("  --remote-config=file\tTell fio server to load this local job file\n");
	printf("  --idle-prof=option\tReport cpu idleness on a system or percpu basis\n"
		"\t\t\t(option=system,percpu) or run unit work\n"
		"\t\t\tcalibration only (option=calibrate)\n");
#ifdef CONFIG_ZLIB
	printf("  --inflate-log=log\tInflate and output compressed log\n");
#endif
	printf("  --trigger-file=file\tExecute trigger cmd when file exists\n");
	printf("  --trigger-timeout=t\tExecute trigger at this time\n");
	printf("  --trigger=cmd\t\tSet this command as local trigger\n");
	printf("  --trigger-remote=cmd\tSet this command as remote trigger\n");
	printf("  --aux-path=path\tUse this path for fio state generated files\n");
	printf("\nFio was written by Jens Axboe <axboe@kernel.dk>\n");
}

#ifdef FIO_INC_DEBUG
const struct debug_level debug_levels[] = {
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
	{ .name = "steadystate",
	  .help = "Steady state detection logging",
	  .shift = FD_STEADYSTATE,
	},
	{ .name = "helperthread",
	  .help = "Helper thread logging",
	  .shift = FD_HELPERTHREAD,
	},
	{ .name = "zbd",
	  .help = "Zoned Block Device logging",
	  .shift = FD_ZBD,
	},
	{ .name = "sprandom",
	  .help = "SPRandom logging",
	  .shift = FD_SPRANDOM,
	},
	{ .name = NULL, },
};

static int set_debug(const char *string)
{
	const struct debug_level *dl;
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
	char *pid_file = NULL;
	void *cur_client = NULL;
	bool backend = false;

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
			smalloc_pool_size <<= 10;
			sinit();
			break;
		case 'l':
			log_err("fio: --latency-log is deprecated. Use per-job latency log options.\n");
			do_exit++;
			exit_val = 1;
			break;
		case 'b':
			write_bw_log = true;
			break;
		case 'o': {
			FILE *tmp;

			if (f_out && f_out != stdout)
				fclose(f_out);

			tmp = fopen(optarg, "w+");
			if (!tmp) {
				log_err("fio: output file open error: %s\n", strerror(errno));
				exit_val = 1;
				do_exit++;
				break;
			}
			f_err = f_out = tmp;
			break;
			}
		case 'm':
			output_format = FIO_OUTPUT_TERSE;
			break;
		case 'F':
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
			did_arg = true;
			if (!cur_client) {
				usage(argv[0]);
				do_exit++;
			}
			break;
		case 'c':
			did_arg = true;
			if (!cur_client) {
				fio_show_option_help(optarg);
				do_exit++;
			}
			break;
		case 'i':
			did_arg = true;
			if (!cur_client) {
				exit_val = fio_show_ioengine_help(optarg);
				do_exit++;
			}
			break;
		case 's':
			did_arg = true;
			dump_cmdline = true;
			break;
		case 'r':
			read_only = 1;
			break;
		case 'v':
			did_arg = true;
			if (!cur_client) {
				log_info("%s\n", fio_version_string);
				do_exit++;
			}
			break;
		case 'V':
			terse_version = atoi(optarg);
			if (!(terse_version >= 2 && terse_version <= 5)) {
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
				break;
			}
			eta_new_line = t / 1000;
			if (!eta_new_line) {
				log_err("fio: eta new line time too short\n");
				exit_val = 1;
				do_exit++;
			}
			break;
			}
		case 'O': {
			long long t = 0;

			if (check_str_time(optarg, &t, 1)) {
				log_err("fio: failed parsing eta interval %s\n", optarg);
				exit_val = 1;
				do_exit++;
				break;
			}
			eta_interval_msec = t / 1000;
			if (eta_interval_msec < DISK_UTIL_MSEC) {
				log_err("fio: eta interval time too short (%umsec min)\n", DISK_UTIL_MSEC);
				exit_val = 1;
				do_exit++;
			}
			break;
			}
		case 'd':
			if (set_debug(optarg))
				do_exit++;
			break;
		case 'P':
			did_arg = true;
			parse_only = true;
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
			did_arg = true;
			do_exit++;
			break;
#endif
		case 'p':
			did_arg = true;
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
				did_arg = true;
			}
			if (!td) {
				int is_section = !strncmp(opt, "name", 4);
				int global = 0;

				if (!is_section || !strncmp(val, "global", 6))
					global = 1;

				if (is_section && skip_this_section(val))
					continue;

				td = get_new_job(global, &def_thread, true, NULL);
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

			if (ret) {
				if (td) {
					put_job(td);
					td = NULL;
				}
				do_exit++;
				exit_val = 1;
			}
			break;
		}
		case 'w':
			warnings_fatal = 1;
			break;
		case 'j':
			/* we don't track/need this anymore, ignore it */
			break;
		case 'S':
			did_arg = true;
#ifndef CONFIG_NO_SHM
			if (nr_clients) {
				log_err("fio: can't be both client and server\n");
				do_exit++;
				exit_val = 1;
				break;
			}
			if (optarg)
				fio_server_set_arg(optarg);
			is_backend = true;
			backend = true;
#else
			log_err("fio: client/server requires SHM support\n");
			do_exit++;
			exit_val = 1;
#endif
			break;
#ifdef WIN32
		case 'N':
			did_arg = true;
			fio_server_internal_set(optarg);
			break;
#endif
		case 'D':
			if (pid_file)
				free(pid_file);
			pid_file = strdup(optarg);
			break;
		case 'I':
			if ((ret = fio_idle_prof_parse_opt(optarg))) {
				/* exit on error and calibration only */
				did_arg = true;
				do_exit++;
				if (ret == -1)
					exit_val = 1;
			}
			break;
		case 'C':
			did_arg = true;
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

				if (fio_client_add_ini_file(cur_client, argv[optind], false))
					break;
				optind++;
			}
			break;
		case 'R':
			did_arg = true;
			if (fio_client_add_ini_file(cur_client, optarg, true)) {
				do_exit++;
				exit_val = 1;
			}
			break;
		case 'T':
			did_arg = true;
			do_exit++;
			exit_val = fio_monotonic_clocktest(1);
			break;
		case 'G':
			did_arg = true;
			do_exit++;
			exit_val = fio_crctest(optarg);
			break;
		case 'M':
			did_arg = true;
			do_exit++;
			exit_val = fio_memcpy_test(optarg);
			break;
		case 'L': {
			long long val;

			if (check_str_time(optarg, &val, 1)) {
				log_err("fio: failed parsing time %s\n", optarg);
				do_exit++;
				exit_val = 1;
				break;
			}
			if (val < 1000) {
				log_err("fio: status interval too small\n");
				do_exit++;
				exit_val = 1;
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

		case 'A':
			did_arg = true;
			merge_blktrace_only = true;
			break;
		case '?':
			log_err("%s: unrecognized option '%s'\n", argv[0],
							argv[optind - 1]);
			show_closest_option(argv[optind - 1]);
			fio_fallthrough;
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
				exit(1);
		}
	}

	while (!ret && optind < argc) {
		ini_idx++;
		ini_file = realloc(ini_file, ini_idx * sizeof(char *));
		ini_file[ini_idx - 1] = strdup(argv[optind]);
		optind++;
	}

out_free:
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

		log_err("No job(s) defined\n\n");
		usage(argv[0]);
		return 1;
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
