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
#include <getopt.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "fio.h"
#include "parse.h"

static char fio_version_string[] = "fio 1.14a";

#define FIO_RANDSEED		(0xb1899bedUL)

static char **ini_file;
static int max_jobs = MAX_JOBS;

struct thread_data def_thread;
struct thread_data *threads = NULL;

int exitall_on_terminate = 0;
int terse_output = 0;
unsigned long long mlock_size = 0;
FILE *f_out = NULL;
FILE *f_err = NULL;

int write_bw_log = 0;

static int def_timeout = 0;
static int write_lat_log = 0;

static int prev_group_jobs;

/*
 * Command line options. These will contain the above, plus a few
 * extra that only pertain to fio itself and not jobs.
 */
static struct option long_options[FIO_NR_OPTIONS] = {
	{
		.name		= "output",
		.has_arg	= required_argument,
		.val		= 'o',
	},
	{
		.name		= "timeout",
		.has_arg	= required_argument,
		.val		= 't',
	},
	{
		.name		= "latency-log",
		.has_arg	= required_argument,
		.val		= 'l',
	},
	{
		.name		= "bandwidth-log",
		.has_arg	= required_argument,
		.val		= 'b',
	},
	{
		.name		= "minimal",
		.has_arg	= optional_argument,
		.val		= 'm',
	},
	{
		.name		= "version",
		.has_arg	= no_argument,
		.val		= 'v',
	},
	{
		.name		= "help",
		.has_arg	= no_argument,
		.val		= 'h',
	},
	{
		.name		= "cmdhelp",
		.has_arg	= optional_argument,
		.val		= 'c',
	},
	{
		.name		= NULL,
	},
};

FILE *get_f_out()
{
	return f_out;
}

FILE *get_f_err()
{
	return f_err;
}

/*
 * Return a free job structure.
 */
static struct thread_data *get_new_job(int global, struct thread_data *parent)
{
	struct thread_data *td;

	if (global)
		return &def_thread;
	if (thread_number >= max_jobs)
		return NULL;

	td = &threads[thread_number++];
	*td = *parent;

	td->thread_number = thread_number;
	return td;
}

static void put_job(struct thread_data *td)
{
	if (td == &def_thread)
		return;

	if (td->error)
		log_info("fio: %s\n", td->verror);

	memset(&threads[td->thread_number - 1], 0, sizeof(*td));
	thread_number--;
}

static int setup_rate(struct thread_data *td)
{
	unsigned long nr_reads_per_msec;
	unsigned long long rate;
	unsigned int bs;

	if (!td->o.rate && !td->o.rate_iops)
		return 0;

	if (td_rw(td))
		bs = td->o.rw_min_bs;
	else if (td_read(td))
		bs = td->o.min_bs[DDIR_READ];
	else
		bs = td->o.min_bs[DDIR_WRITE];

	if (td->o.rate) {
		rate = td->o.rate;
		nr_reads_per_msec = (rate * 1024 * 1000LL) / bs;
	} else
		nr_reads_per_msec = td->o.rate_iops * 1000UL;

	if (!nr_reads_per_msec) {
		log_err("rate lower than supported\n");
		return -1;
	}

	td->rate_usec_cycle = 1000000000ULL / nr_reads_per_msec;
	td->rate_pending_usleep = 0;
	return 0;
}

/*
 * Lazy way of fixing up options that depend on each other. We could also
 * define option callback handlers, but this is easier.
 */
static int fixup_options(struct thread_data *td)
{
	struct thread_options *o = &td->o;

	if (!o->rwmixread && o->rwmixwrite)
		o->rwmixread = 100 - o->rwmixwrite;

	if (o->write_iolog_file && o->read_iolog_file) {
		log_err("fio: read iolog overrides write_iolog\n");
		free(o->write_iolog_file);
		o->write_iolog_file = NULL;
	}

	if (td->io_ops->flags & FIO_SYNCIO)
		o->iodepth = 1;
	else {
		if (!o->iodepth)
			o->iodepth = o->open_files;
	}

	/*
	 * only really works for sequential io for now, and with 1 file
	 */
	if (o->zone_size && td_random(td) && o->open_files == 1)
		o->zone_size = 0;

	/*
	 * Reads can do overwrites, we always need to pre-create the file
	 */
	if (td_read(td) || td_rw(td))
		o->overwrite = 1;

	if (!o->min_bs[DDIR_READ])
		o->min_bs[DDIR_READ]= o->bs[DDIR_READ];
	if (!o->max_bs[DDIR_READ])
		o->max_bs[DDIR_READ] = o->bs[DDIR_READ];
	if (!o->min_bs[DDIR_WRITE])
		o->min_bs[DDIR_WRITE]= o->bs[DDIR_WRITE];
	if (!o->max_bs[DDIR_WRITE])
		o->max_bs[DDIR_WRITE] = o->bs[DDIR_WRITE];

	o->rw_min_bs = min(o->min_bs[DDIR_READ], o->min_bs[DDIR_WRITE]);

	if (!o->file_size_high)
		o->file_size_high = o->file_size_low;

	if (td_read(td) && !td_rw(td))
		o->verify = 0;

	if (o->norandommap && o->verify != VERIFY_NONE) {
		log_err("fio: norandommap given, verify disabled\n");
		o->verify = VERIFY_NONE;
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
	if (o->iodepth_low > o->iodepth || !o->iodepth_low) {
		/*
		 * syslet work around - if the workload is sequential,
		 * we want to let the queue drain all the way down to
		 * avoid seeking between async threads
		 */
		if (!strcmp(td->io_ops->name, "syslet-rw") && !td_random(td))
			o->iodepth_low = 1;
		else
			o->iodepth_low = o->iodepth;
	}

	/*
	 * If batch number isn't set, default to the same as iodepth
	 */
	if (o->iodepth_batch > o->iodepth || !o->iodepth_batch)
		o->iodepth_batch = o->iodepth;

	if (o->nr_files > td->files_index)
		o->nr_files = td->files_index;

	if (o->open_files > o->nr_files || !o->open_files)
		o->open_files = o->nr_files;

	if ((o->rate && o->rate_iops) || (o->ratemin && o->rate_iops_min)) {
		log_err("fio: rate and rate_iops are mutually exclusive\n");
		return 1;
	}
	if ((o->rate < o->ratemin) || (o->rate_iops < o->rate_iops_min)) {
		log_err("fio: minimum rate exceeds rate\n");
		return 1;
	}

	return 0;
}

/*
 * This function leaks the buffer
 */
static char *to_kmg(unsigned int val)
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

	snprintf(buf, 31, "%u%c", val, *p);
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

	if (S_ISREG(sb.st_mode))
		return 0;

	return 1;
}

/*
 * Initialize the various random states we need (random io, block size ranges,
 * read/write mix, etc).
 */
static int init_random_state(struct thread_data *td)
{
	unsigned long seeds[6];
	int fd;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd == -1) {
		td_verror(td, errno, "open");
		return 1;
	}

	if (read(fd, seeds, sizeof(seeds)) < (int) sizeof(seeds)) {
		td_verror(td, EIO, "read");
		close(fd);
		return 1;
	}

	close(fd);

	os_random_seed(seeds[0], &td->bsrange_state);
	os_random_seed(seeds[1], &td->verify_state);
	os_random_seed(seeds[2], &td->rwmix_state);

	if (td->o.file_service_type == FIO_FSERVICE_RANDOM)
		os_random_seed(seeds[3], &td->next_file_state);

	os_random_seed(seeds[5], &td->file_size_state);

	if (!td_random(td))
		return 0;

	if (td->o.rand_repeatable)
		seeds[4] = FIO_RANDSEED * td->thread_number;

	os_random_seed(seeds[4], &td->random_state);
	return 0;
}


/*
 * Adds a job to the list of things todo. Sanitizes the various options
 * to make sure we don't have conflicts, and initializes various
 * members of td.
 */
static int add_job(struct thread_data *td, const char *jobname, int job_add_num)
{
	const char *ddir_str[] = { NULL, "read", "write", "rw", NULL,
				   "randread", "randwrite", "randrw" };
	unsigned int i;
	struct fio_file *f;
	const char *engine;
	char fname[PATH_MAX];
	int numjobs, file_alloced;

	/*
	 * the def_thread is just for options, it's not a real job
	 */
	if (td == &def_thread)
		return 0;

	engine = get_engine_name(td->o.ioengine);
	td->io_ops = load_ioengine(td, engine);
	if (!td->io_ops) {
		log_err("fio: failed to load engine %s\n", engine);
		goto err;
	}

	if (td->o.use_thread)
		nr_thread++;
	else
		nr_process++;

	if (td->o.odirect)
		td->io_ops->flags |= FIO_RAWIO;

	file_alloced = 0;
	if (!td->o.filename && !td->files_index) {
		file_alloced = 1;

		if (td->o.nr_files == 1 && exists_and_not_file(jobname))
			add_file(td, jobname);
		else {
			for (i = 0; i < td->o.nr_files; i++) {
				sprintf(fname, "%s.%d.%d", jobname, td->thread_number, i);
				add_file(td, fname);
			}
		}
	}

	if (fixup_options(td))
		goto err;

	for_each_file(td, f, i) {
		if (td->o.directory && f->filetype == FIO_TYPE_FILE) {
			sprintf(fname, "%s/%s", td->o.directory, f->file_name);
			f->file_name = strdup(fname);
		}
	}
		
	td->mutex = fio_sem_init(0);

	td->ts.clat_stat[0].min_val = td->ts.clat_stat[1].min_val = ULONG_MAX;
	td->ts.slat_stat[0].min_val = td->ts.slat_stat[1].min_val = ULONG_MAX;
	td->ts.bw_stat[0].min_val = td->ts.bw_stat[1].min_val = ULONG_MAX;

	if ((td->o.stonewall || td->o.numjobs > 1) && prev_group_jobs) {
		prev_group_jobs = 0;
		groupid++;
	}

	td->groupid = groupid;
	prev_group_jobs++;

	if (init_random_state(td))
		goto err;

	if (setup_rate(td))
		goto err;

	if (td->o.write_lat_log) {
		setup_log(&td->ts.slat_log);
		setup_log(&td->ts.clat_log);
	}
	if (td->o.write_bw_log)
		setup_log(&td->ts.bw_log);

	if (!td->o.name)
		td->o.name = strdup(jobname);

	if (!terse_output) {
		if (!job_add_num) {
			if (!strcmp(td->io_ops->name, "cpuio"))
				log_info("%s: ioengine=cpu, cpuload=%u, cpucycle=%u\n", td->o.name, td->o.cpuload, td->o.cpucycle);
			else {
				char *c1, *c2, *c3, *c4;

				c1 = to_kmg(td->o.min_bs[DDIR_READ]);
				c2 = to_kmg(td->o.max_bs[DDIR_READ]);
				c3 = to_kmg(td->o.min_bs[DDIR_WRITE]);
				c4 = to_kmg(td->o.max_bs[DDIR_WRITE]);

				log_info("%s: (g=%d): rw=%s, bs=%s-%s/%s-%s, ioengine=%s, iodepth=%u\n", td->o.name, td->groupid, ddir_str[td->o.td_ddir], c1, c2, c3, c4, td->io_ops->name, td->o.iodepth);

				free(c1);
				free(c2);
				free(c3);
				free(c4);
			}
		} else if (job_add_num == 1)
			log_info("...\n");
	}

	/*
	 * recurse add identical jobs, clear numjobs and stonewall options
	 * as they don't apply to sub-jobs
	 */
	numjobs = td->o.numjobs;
	while (--numjobs) {
		struct thread_data *td_new = get_new_job(0, td);

		if (!td_new)
			goto err;

		td_new->o.numjobs = 1;
		td_new->o.stonewall = 0;

		if (file_alloced) {
			td_new->o.filename = NULL;
			td_new->files_index = 0;
			td_new->files = NULL;
		}

		job_add_num = numjobs - 1;

		if (add_job(td_new, jobname, job_add_num))
			goto err;
	}

	if (td->o.numjobs > 1) {
		groupid++;
		prev_group_jobs = 0;
	}

	return 0;
err:
	put_job(td);
	return -1;
}

static int is_empty_or_comment(char *line)
{
	unsigned int i;

	for (i = 0; i < strlen(line); i++) {
		if (line[i] == ';')
			return 1;
		if (line[i] == '#')
			return 1;
		if (!isspace(line[i]) && !iscntrl(line[i]))
			return 0;
	}

	return 1;
}

/*
 * This is our [ini] type file parser.
 */
static int parse_jobs_ini(char *file, int stonewall_flag)
{
	unsigned int global;
	struct thread_data *td;
	char *string, *name;
	fpos_t off;
	FILE *f;
	char *p;
	int ret = 0, stonewall;

	f = fopen(file, "r");
	if (!f) {
		perror("fopen job file");
		return 1;
	}

	string = malloc(4096);
	name = malloc(256);
	memset(name, 0, 256);

	stonewall = stonewall_flag;
	do {
		p = fgets(string, 4095, f);
		if (!p)
			break;
		if (is_empty_or_comment(p))
			continue;
		if (sscanf(p, "[%255s]", name) != 1)
			continue;

		global = !strncmp(name, "global", 6);

		name[strlen(name) - 1] = '\0';

		td = get_new_job(global, &def_thread);
		if (!td) {
			ret = 1;
			break;
		}

		/*
		 * Seperate multiple job files by a stonewall
		 */
		if (!global && stonewall) {
			td->o.stonewall = stonewall;
			stonewall = 0;
		}

		fgetpos(f, &off);
		while ((p = fgets(string, 4096, f)) != NULL) {
			if (is_empty_or_comment(p))
				continue;

			strip_blank_front(&p);

			if (p[0] == '[')
				break;

			strip_blank_end(p);

			fgetpos(f, &off);

			/*
			 * Don't break here, continue parsing options so we
			 * dump all the bad ones. Makes trial/error fixups
			 * easier on the user.
			 */
			ret |= fio_option_parse(td, p);
		}

		if (!ret) {
			fsetpos(f, &off);
			ret = add_job(td, name, 0);
		} else {
			log_err("fio: job %s dropped\n", name);
			put_job(td);
		}
	} while (!ret);

	free(string);
	free(name);
	fclose(f);
	return ret;
}

static int fill_def_thread(void)
{
	memset(&def_thread, 0, sizeof(def_thread));

	if (fio_getaffinity(getpid(), &def_thread.o.cpumask) == -1) {
		perror("sched_getaffinity");
		return 1;
	}

	/*
	 * fill default options
	 */
	fio_fill_default_options(&def_thread);

	def_thread.o.timeout = def_timeout;
	def_thread.o.write_bw_log = write_bw_log;
	def_thread.o.write_lat_log = write_lat_log;

#ifdef FIO_HAVE_DISK_UTIL
	def_thread.o.do_disk_util = 1;
#endif

	return 0;
}

static void free_shm(void)
{
	struct shmid_ds sbuf;

	if (threads) {
		shmdt((void *) threads);
		threads = NULL;
		shmctl(shm_id, IPC_RMID, &sbuf);
	}
}

/*
 * The thread area is shared between the main process and the job
 * threads/processes. So setup a shared memory segment that will hold
 * all the job info.
 */
static int setup_thread_area(void)
{
	/*
	 * 1024 is too much on some machines, scale max_jobs if
	 * we get a failure that looks like too large a shm segment
	 */
	do {
		size_t size = max_jobs * sizeof(struct thread_data);

		shm_id = shmget(0, size, IPC_CREAT | 0600);
		if (shm_id != -1)
			break;
		if (errno != EINVAL) {
			perror("shmget");
			break;
		}

		max_jobs >>= 1;
	} while (max_jobs);

	if (shm_id == -1)
		return 1;

	threads = shmat(shm_id, NULL, 0);
	if (threads == (void *) -1) {
		perror("shmat");
		return 1;
	}

	atexit(free_shm);
	return 0;
}

static void usage(void)
{
	printf("%s\n", fio_version_string);
	printf("\t--output\tWrite output to file\n");
	printf("\t--timeout\tRuntime in seconds\n");
	printf("\t--latency-log\tGenerate per-job latency logs\n");
	printf("\t--bandwidth-log\tGenerate per-job bandwidth logs\n");
	printf("\t--minimal\tMinimal (terse) output\n");
	printf("\t--version\tPrint version info and exit\n");
	printf("\t--help\t\tPrint this page\n");
	printf("\t--cmdhelp=cmd\tPrint command help, \"all\" for all of them\n");
}

static int parse_cmd_line(int argc, char *argv[])
{
	struct thread_data *td = NULL;
	int c, ini_idx = 0, lidx, ret, dont_add_job = 0;

	while ((c = getopt_long_only(argc, argv, "", long_options, &lidx)) != -1) {
		switch (c) {
		case 't':
			def_timeout = atoi(optarg);
			break;
		case 'l':
			write_lat_log = 1;
			break;
		case 'w':
			write_bw_log = 1;
			break;
		case 'o':
			f_out = fopen(optarg, "w+");
			if (!f_out) {
				perror("fopen output");
				exit(1);
			}
			f_err = f_out;
			break;
		case 'm':
			terse_output = 1;
			break;
		case 'h':
			usage();
			exit(0);
		case 'c':
			exit(fio_show_option_help(optarg));
		case 'v':
			printf("%s\n", fio_version_string);
			exit(0);
		case FIO_GETOPT_JOB: {
			const char *opt = long_options[lidx].name;
			char *val = optarg;

			if (!strncmp(opt, "name", 4) && td) {
				ret = add_job(td, td->o.name ?: "fio", 0);
				if (ret) {
					put_job(td);
					return 0;
				}
				td = NULL;
			}
			if (!td) {
				int global = !strncmp(val, "global", 6);

				td = get_new_job(global, &def_thread);
				if (!td)
					return 0;
			}

			ret = fio_cmd_option_parse(td, opt, val);
			if (ret)
				dont_add_job = 1;
			break;
		}
		default:
			break;
		}
	}

	if (td) {
		if (dont_add_job)
			put_job(td);
		else {
			ret = add_job(td, td->o.name ?: "fio", 0);
			if (ret)
				put_job(td);
		}
	}

	while (optind < argc) {
		ini_idx++;
		ini_file = realloc(ini_file, ini_idx * sizeof(char *));
		ini_file[ini_idx - 1] = strdup(argv[optind]);
		optind++;
	}

	return ini_idx;
}


int parse_options(int argc, char *argv[])
{
	int job_files, i;

	f_out = stdout;
	f_err = stderr;

	fio_options_dup_and_init(long_options);

	if (setup_thread_area())
		return 1;
	if (fill_def_thread())
		return 1;

	job_files = parse_cmd_line(argc, argv);

	for (i = 0; i < job_files; i++) {
		if (fill_def_thread())
			return 1;
		if (parse_jobs_ini(ini_file[i], i))
			return 1;
		free(ini_file[i]);
	}

	free(ini_file);

	if (!thread_number) {
		log_err("No jobs defined(s)\n");
		return 1;
	}

	return 0;
}
