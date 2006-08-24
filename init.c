/*
 * This file contains the ini and command liner parser. It will create
 * and initialize the specified jobs.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "fio.h"

/*
 * The default options
 */
#define DEF_BS			(4096)
#define DEF_TIMEOUT		(0)
#define DEF_RATE_CYCLE		(1000)
#define DEF_ODIRECT		(1)
#define DEF_IO_ENGINE		(FIO_SYNCIO)
#define DEF_IO_ENGINE_NAME	"sync"
#define DEF_SEQUENTIAL		(1)
#define DEF_RAND_REPEAT		(1)
#define DEF_OVERWRITE		(1)
#define DEF_CREATE		(1)
#define DEF_INVALIDATE		(1)
#define DEF_SYNCIO		(0)
#define DEF_RANDSEED		(0xb1899bedUL)
#define DEF_BWAVGTIME		(500)
#define DEF_CREATE_SER		(1)
#define DEF_CREATE_FSYNC	(1)
#define DEF_LOOPS		(1)
#define DEF_VERIFY		(0)
#define DEF_STONEWALL		(0)
#define DEF_NUMJOBS		(1)
#define DEF_USE_THREAD		(0)
#define DEF_FILE_SIZE		(1024 * 1024 * 1024UL)
#define DEF_ZONE_SIZE		(0)
#define DEF_ZONE_SKIP		(0)
#define DEF_RWMIX_CYCLE		(500)
#define DEF_RWMIX_READ		(50)
#define DEF_NICE		(0)

static int def_timeout = DEF_TIMEOUT;

static char fio_version_string[] = "fio 1.5";

static char **ini_file;
static int max_jobs = MAX_JOBS;

struct thread_data def_thread;
struct thread_data *threads = NULL;

int rate_quit = 0;
int write_lat_log = 0;
int write_bw_log = 0;
int exitall_on_terminate = 0;
int terse_output = 0;
unsigned long long mlock_size = 0;
FILE *f_out = NULL;
FILE *f_err = NULL;

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
	td->name[0] = '\0';

	td->fd = -1;
	td->thread_number = thread_number;
	return td;
}

static void put_job(struct thread_data *td)
{
	memset(&threads[td->thread_number - 1], 0, sizeof(*td));
	thread_number--;
}

/*
 * Adds a job to the list of things todo. Sanitizes the various options
 * to make sure we don't have conflicts, and initializes various
 * members of td.
 */
static int add_job(struct thread_data *td, const char *jobname, int job_add_num)
{
	char *ddir_str[] = { "read", "write", "randread", "randwrite",
			     "rw", NULL, "randrw" };
	struct stat sb;
	int numjobs, ddir;

#ifndef FIO_HAVE_LIBAIO
	if (td->io_engine == FIO_LIBAIO) {
		log_err("Linux libaio not available\n");
		return 1;
	}
#endif
#ifndef FIO_HAVE_POSIXAIO
	if (td->io_engine == FIO_POSIXAIO) {
		log_err("posix aio not available\n");
		return 1;
	}
#endif

	/*
	 * the def_thread is just for options, it's not a real job
	 */
	if (td == &def_thread)
		return 0;

	if (td->io_engine & FIO_SYNCIO)
		td->iodepth = 1;
	else {
		if (!td->iodepth)
			td->iodepth = 1;
	}

	/*
	 * only really works for sequential io for now
	 */
	if (td->zone_size && !td->sequential)
		td->zone_size = 0;

	/*
	 * Reads can do overwrites, we always need to pre-create the file
	 */
	if (td_read(td) || td_rw(td))
		td->overwrite = 1;

	td->filetype = FIO_TYPE_FILE;
	if (!stat(jobname, &sb)) {
		if (S_ISBLK(sb.st_mode))
			td->filetype = FIO_TYPE_BD;
		else if (S_ISCHR(sb.st_mode))
			td->filetype = FIO_TYPE_CHAR;
	}

	if (td->filetype == FIO_TYPE_FILE) {
		char tmp[PATH_MAX];

		if (td->directory && td->directory[0] != '\0')
			sprintf(tmp, "%s/%s.%d", td->directory, jobname, td->thread_number);
		else
			sprintf(tmp, "%s.%d", jobname, td->thread_number);
		td->file_name = strdup(tmp);
	} else
		td->file_name = strdup(jobname);

	fio_sem_init(&td->mutex, 0);

	td->clat_stat[0].min_val = td->clat_stat[1].min_val = ULONG_MAX;
	td->slat_stat[0].min_val = td->slat_stat[1].min_val = ULONG_MAX;
	td->bw_stat[0].min_val = td->bw_stat[1].min_val = ULONG_MAX;

	if (td->min_bs == -1U)
		td->min_bs = td->bs;
	if (td->max_bs == -1U)
		td->max_bs = td->bs;
	if (td_read(td) && !td_rw(td))
		td->verify = 0;

	if (td->stonewall && td->thread_number > 1)
		groupid++;

	td->groupid = groupid;

	if (setup_rate(td))
		goto err;

	if (write_lat_log) {
		setup_log(&td->slat_log);
		setup_log(&td->clat_log);
	}
	if (write_bw_log)
		setup_log(&td->bw_log);

	if (td->name[0] == '\0')
		snprintf(td->name, sizeof(td->name)-1, "client%d", td->thread_number);

	ddir = td->ddir + (!td->sequential << 1) + (td->iomix << 2);

	if (!terse_output) {
		if (!job_add_num)
			fprintf(f_out, "%s: (g=%d): rw=%s, odir=%d, bs=%d-%d, rate=%d, ioengine=%s, iodepth=%d\n", td->name, td->groupid, ddir_str[ddir], td->odirect, td->min_bs, td->max_bs, td->rate, td->io_engine_name, td->iodepth);
		else if (job_add_num == 1)
			fprintf(f_out, "...\n");
	}

	/*
	 * recurse add identical jobs, clear numjobs and stonewall options
	 * as they don't apply to sub-jobs
	 */
	numjobs = td->numjobs;
	while (--numjobs) {
		struct thread_data *td_new = get_new_job(0, td);

		if (!td_new)
			goto err;

		td_new->numjobs = 1;
		td_new->stonewall = 0;
		job_add_num = numjobs - 1;

		if (add_job(td_new, jobname, job_add_num))
			goto err;
	}
	return 0;
err:
	put_job(td);
	return -1;
}

/*
 * Initialize the various random states we need (random io, block size ranges,
 * read/write mix, etc).
 */
int init_random_state(struct thread_data *td)
{
	unsigned long seeds[4];
	int fd, num_maps, blocks;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd == -1) {
		td_verror(td, errno);
		return 1;
	}

	if (read(fd, seeds, sizeof(seeds)) < (int) sizeof(seeds)) {
		td_verror(td, EIO);
		close(fd);
		return 1;
	}

	close(fd);

	os_random_seed(seeds[0], &td->bsrange_state);
	os_random_seed(seeds[1], &td->verify_state);
	os_random_seed(seeds[2], &td->rwmix_state);

	if (td->sequential)
		return 0;

	if (td->rand_repeatable)
		seeds[3] = DEF_RANDSEED;

	blocks = (td->io_size + td->min_bs - 1) / td->min_bs;
	num_maps = blocks / BLOCKS_PER_MAP;
	td->file_map = malloc(num_maps * sizeof(long));
	td->num_maps = num_maps;
	memset(td->file_map, 0, num_maps * sizeof(long));

	os_random_seed(seeds[3], &td->random_state);
	return 0;
}

static void fill_cpu_mask(os_cpu_mask_t cpumask, int cpu)
{
#ifdef FIO_HAVE_CPU_AFFINITY
	unsigned int i;

	CPU_ZERO(&cpumask);

	for (i = 0; i < sizeof(int) * 8; i++) {
		if ((1 << i) & cpu)
			CPU_SET(i, &cpumask);
	}
#endif
}

static unsigned long get_mult_time(char c)
{
	switch (c) {
		case 'm':
		case 'M':
			return 60;
		case 'h':
		case 'H':
			return 60 * 60;
		case 'd':
		case 'D':
			return 24 * 60 * 60;
		default:
			return 1;
	}
}

static unsigned long get_mult_bytes(char c)
{
	switch (c) {
		case 'k':
		case 'K':
			return 1024;
		case 'm':
		case 'M':
			return 1024 * 1024;
		case 'g':
		case 'G':
			return 1024 * 1024 * 1024;
		default:
			return 1;
	}
}

/*
 * convert string after '=' into decimal value, noting any size suffix
 */
static int str_to_decimal(char *p, unsigned long long *val, int kilo)
{
	char *str;
	int len;

	str = strchr(p, '=');
	if (!str)
		return 1;

	str++;
	len = strlen(str);

	*val = strtoul(str, NULL, 10);
	if (*val == ULONG_MAX && errno == ERANGE)
		return 1;

	if (kilo)
		*val *= get_mult_bytes(str[len - 1]);
	else
		*val *= get_mult_time(str[len - 1]);
	return 0;
}

static int check_str_bytes(char *p, char *name, unsigned long long *val)
{
	if (strncmp(p, name, strlen(name) - 1))
		return 1;

	return str_to_decimal(p, val, 1);
}

static int check_str_time(char *p, char *name, unsigned long long *val)
{
	if (strncmp(p, name, strlen(name) - 1))
		return 1;

	return str_to_decimal(p, val, 0);
}

static void strip_blank_front(char **p)
{
	char *s = *p;

	while (isspace(*s))
		s++;
}

static void strip_blank_end(char *p)
{
	char *s = p + strlen(p) - 1;

	while (isspace(*s) || iscntrl(*s))
		s--;

	*(s + 1) = '\0';
}

typedef int (str_cb_fn)(struct thread_data *, char *);

static int check_str(char *p, char *name, str_cb_fn *cb, struct thread_data *td)
{
	char *s;

	if (strncmp(p, name, strlen(name)))
		return 1;

	s = strstr(p, name);
	if (!s)
		return 1;

	s = strchr(s, '=');
	if (!s)
		return 1;

	s++;
	strip_blank_front(&s);
	return cb(td, s);
}

static int check_strstore(char *p, char *name, char *dest)
{
	char *s;

	if (strncmp(p, name, strlen(name)))
		return 1;

	s = strstr(p, name);
	if (!s)
		return 1;

	s = strchr(p, '=');
	if (!s)
		return 1;

	s++;
	strip_blank_front(&s);

	strcpy(dest, s);
	return 0;
}

static int __check_range_bytes(char *str, unsigned long *val)
{
	char suffix;

	if (sscanf(str, "%lu%c", val, &suffix) == 2) {
		*val *= get_mult_bytes(suffix);
		return 0;
	}

	if (sscanf(str, "%lu", val) == 1)
		return 0;

	return 1;
}

static int check_range_bytes(char *p, char *name, unsigned long *s,
			     unsigned long *e)
{
	char option[128];
	char *str, *p1, *p2;

	if (strncmp(p, name, strlen(name)))
		return 1;

	strcpy(option, p);
	p = option;

	str = strstr(p, name);
	if (!str)
		return 1;

	p += strlen(name);

	str = strchr(p, '=');
	if (!str)
		return 1;

	/*
	 * 'p' now holds whatever is after the '=' sign
	 */
	p1 = str + 1;

	/*
	 * terminate p1 at the '-' sign
	 */
	p = strchr(p1, '-');
	if (!p)
		return 1;

	p2 = p + 1;
	*p = '\0';

	if (!__check_range_bytes(p1, s) && !__check_range_bytes(p2, e))
		return 0;

	return 1;
}

static int check_int(char *p, char *name, unsigned int *val)
{
	char *str;

	if (strncmp(p, name, strlen(name)))
		return 1;

	str = strstr(p, name);
	if (!str)
		return 1;

	str = strchr(p, '=');
	if (!str)
		return 1;

	str++;

	if (sscanf(str, "%u", val) == 1)
		return 0;

	return 1;
}

static int check_strset(char *p, char *name)
{
	return strncmp(p, name, strlen(name));
}

static int is_empty_or_comment(char *line)
{
	unsigned int i;

	for (i = 0; i < strlen(line); i++) {
		if (line[i] == ';')
			return 1;
		if (!isspace(line[i]) && !iscntrl(line[i]))
			return 0;
	}

	return 1;
}

static int str_rw_cb(struct thread_data *td, char *mem)
{
	if (!strncmp(mem, "read", 4) || !strncmp(mem, "0", 1)) {
		td->ddir = DDIR_READ;
		td->sequential = 1;
		return 0;
	} else if (!strncmp(mem, "randread", 8)) {
		td->ddir = DDIR_READ;
		td->sequential = 0;
		return 0;
	} else if (!strncmp(mem, "write", 5) || !strncmp(mem, "1", 1)) {
		td->ddir = DDIR_WRITE;
		td->sequential = 1;
		return 0;
	} else if (!strncmp(mem, "randwrite", 9)) {
		td->ddir = DDIR_WRITE;
		td->sequential = 0;
		return 0;
	} else if (!strncmp(mem, "rw", 2)) {
		td->ddir = 0;
		td->iomix = 1;
		td->sequential = 1;
		return 0;
	} else if (!strncmp(mem, "randrw", 6)) {
		td->ddir = 0;
		td->iomix = 1;
		td->sequential = 0;
		return 0;
	}

	log_err("fio: data direction: read, write, randread, randwrite, rw, randrw\n");
	return 1;
}

static int str_verify_cb(struct thread_data *td, char *mem)
{
	if (!strncmp(mem, "0", 1)) {
		td->verify = VERIFY_NONE;
		return 0;
	} else if (!strncmp(mem, "md5", 3) || !strncmp(mem, "1", 1)) {
		td->verify = VERIFY_MD5;
		return 0;
	} else if (!strncmp(mem, "crc32", 5)) {
		td->verify = VERIFY_CRC32;
		return 0;
	}

	log_err("fio: verify types: md5, crc32\n");
	return 1;
}

static int str_mem_cb(struct thread_data *td, char *mem)
{
	if (!strncmp(mem, "malloc", 6)) {
		td->mem_type = MEM_MALLOC;
		return 0;
	} else if (!strncmp(mem, "shm", 3)) {
		td->mem_type = MEM_SHM;
		return 0;
	} else if (!strncmp(mem, "mmap", 4)) {
		td->mem_type = MEM_MMAP;
		return 0;
	}

	log_err("fio: mem type: malloc, shm, mmap\n");
	return 1;
}

static int str_ioengine_cb(struct thread_data *td, char *str)
{
	if (!strncmp(str, "linuxaio", 8) || !strncmp(str, "aio", 3) ||
	    !strncmp(str, "libaio", 6)) {
		strcpy(td->io_engine_name, "libaio");
		td->io_engine = FIO_LIBAIO;
		return 0;
	} else if (!strncmp(str, "posixaio", 8)) {
		strcpy(td->io_engine_name, "posixaio");
		td->io_engine = FIO_POSIXAIO;
		return 0;
	} else if (!strncmp(str, "sync", 4)) {
		strcpy(td->io_engine_name, "sync");
		td->io_engine = FIO_SYNCIO;
		return 0;
	} else if (!strncmp(str, "mmap", 4)) {
		strcpy(td->io_engine_name, "mmap");
		td->io_engine = FIO_MMAPIO;
		return 0;
	} else if (!strncmp(str, "sgio", 4)) {
		strcpy(td->io_engine_name, "sgio");
		td->io_engine = FIO_SGIO;
		return 0;
	} else if (!strncmp(str, "splice", 6)) {
		strcpy(td->io_engine_name, "splice");
		td->io_engine = FIO_SPLICEIO;
		return 0;
	}

	log_err("fio: ioengine: { linuxaio, aio, libaio }, posixaio, sync, mmap, sgio, splice\n");
	return 1;
}

/*
 * This is our [ini] type file parser.
 */
int parse_jobs_ini(char *file, int stonewall_flag)
{
	unsigned int prioclass, prio, cpu, global, il;
	unsigned long long ull;
	unsigned long ul1, ul2;
	struct thread_data *td;
	char *string, *name, *tmpbuf;
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
	tmpbuf = malloc(4096);

	stonewall = stonewall_flag;
	while ((p = fgets(string, 4096, f)) != NULL) {
		if (ret)
			break;
		if (is_empty_or_comment(p))
			continue;
		if (sscanf(p, "[%s]", name) != 1)
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
			td->stonewall = stonewall;
			stonewall = 0;
		}

		fgetpos(f, &off);
		while ((p = fgets(string, 4096, f)) != NULL) {
			if (is_empty_or_comment(p))
				continue;
			if (strstr(p, "["))
				break;
			strip_blank_front(&p);
			strip_blank_end(p);

			if (!check_int(p, "prio", &prio)) {
#ifndef FIO_HAVE_IOPRIO
				log_err("io priorities not available\n");
				ret = 1;
				break;
#endif
				td->ioprio |= prio;
				fgetpos(f, &off);
				continue;
			}
			if (!check_int(p, "prioclass", &prioclass)) {
#ifndef FIO_HAVE_IOPRIO
				log_err("io priorities not available\n");
				ret = 1;
				break;
#else
				td->ioprio |= prioclass << IOPRIO_CLASS_SHIFT;
				fgetpos(f, &off);
				continue;
#endif
			}
			if (!check_int(p, "direct", &il)) {
				td->odirect = il;
				fgetpos(f, &off);
				continue;
			}
			if (!check_int(p, "rand_repeatable", &il)) {
				td->rand_repeatable = il;
				fgetpos(f, &off);
				continue;
			}
			if (!check_int(p, "rate", &td->rate)) {
				fgetpos(f, &off);
				continue;
			}
			if (!check_int(p, "ratemin", &td->ratemin)) {
				fgetpos(f, &off);
				continue;
			}
			if (!check_int(p, "ratecycle", &td->ratecycle)) {
				fgetpos(f, &off);
				continue;
			}
			if (!check_int(p, "thinktime", &td->thinktime)) {
				fgetpos(f, &off);
				continue;
			}
			if (!check_int(p, "cpumask", &cpu)) {
#ifndef FIO_HAVE_CPU_AFFINITY
				log_err("cpu affinity not available\n");
				ret = 1;
				break;
#endif
				fill_cpu_mask(td->cpumask, cpu);
				fgetpos(f, &off);
				continue;
			}
			if (!check_int(p, "fsync", &td->fsync_blocks)) {
				fgetpos(f, &off);
				td->end_fsync = 1;
				continue;
			}
			if (!check_int(p, "startdelay", &td->start_delay)) {
				fgetpos(f, &off);
				continue;
			}
			if (!check_str_time(p, "timeout", &ull)) {
				td->timeout = ull;
				fgetpos(f, &off);
				continue;
			}
			if (!check_int(p, "invalidate", &il)) {
				td->invalidate_cache = il;
				fgetpos(f, &off);
				continue;
			}
			if (!check_int(p, "iodepth", &td->iodepth)) {
				fgetpos(f, &off);
				continue;
			}
			if (!check_int(p, "sync", &il)) {
				td->sync_io = il;
				fgetpos(f, &off);
				continue;
			}
			if (!check_int(p, "bwavgtime", &td->bw_avg_time)) {
				fgetpos(f, &off);
				continue;
			}
			if (!check_int(p, "create_serialize", &il)) {
				td->create_serialize = il;
				fgetpos(f, &off);
				continue;
			}
			if (!check_int(p, "create_fsync", &il)) {
				td->create_fsync = il;
				fgetpos(f, &off);
				continue;
			}
			if (!check_int(p, "end_fsync", &il)) {
				td->end_fsync = il;
				fgetpos(f, &off);
				continue;
			}
			if (!check_int(p, "loops", &td->loops)) {
				fgetpos(f, &off);
				continue;
			}
			if (!check_int(p, "numjobs", &td->numjobs)) {
				fgetpos(f, &off);
				continue;
			}
			if (!check_int(p, "overwrite", &il)) {
				td->overwrite = il;
				fgetpos(f, &off);
				continue;
			}
			if (!check_int(p, "rwmixcycle", &td->rwmixcycle)) {
				fgetpos(f, &off);
				continue;
			}
			if (!check_int(p, "rwmixread", &il)) {
				if (il > 100)
					il = 100;
				td->rwmixread = il;
				fgetpos(f, &off);
				continue;
			}
			if (!check_int(p, "rwmixwrite", &il)) {
				if (il > 100)
					il = 100;
				td->rwmixread = 100 - il;
				fgetpos(f, &off);
				continue;
			}
			if (!check_int(p, "nice", &td->nice)) {
				fgetpos(f, &off);
				continue;
			}
			if (!check_range_bytes(p, "bsrange", &ul1, &ul2)) {
				if (ul1 > ul2) {
					td->max_bs = ul1;
					td->min_bs = ul2;
				} else {
					td->max_bs = ul2;
					td->min_bs = ul1;
				}
				fgetpos(f, &off);
				continue;
			}
			if (!check_str_bytes(p, "bs", &ull)) {
				td->bs = ull;
				fgetpos(f, &off);
				continue;
			}
			if (!check_str_bytes(p, "size", &td->file_size)) {
				fgetpos(f, &off);
				continue;
			}
			if (!check_str_bytes(p, "offset", &td->file_offset)) {
				fgetpos(f, &off);
				continue;
			}
			if (!check_str_bytes(p, "zonesize", &td->zone_size)) {
				fgetpos(f, &off);
				continue;
			}
			if (!check_str_bytes(p, "zoneskip", &td->zone_skip)) {
				fgetpos(f, &off);
				continue;
			}
			if (!check_str_bytes(p, "lockmem", &mlock_size)) {
				fgetpos(f, &off);
				continue;
			}
			if (!check_strstore(p, "directory", tmpbuf)) {
				td->directory = strdup(tmpbuf);
				fgetpos(f, &off);
				continue;
			}
			if (!check_strstore(p, "name", tmpbuf)) {
				snprintf(td->name, sizeof(td->name)-1, "%s%d", tmpbuf, td->thread_number);
				fgetpos(f, &off);
				continue;
			}
			if (!check_str(p, "mem", str_mem_cb, td)) {
				fgetpos(f, &off);
				continue;
			}
			if (!check_str(p, "verify", str_verify_cb, td)) {
				fgetpos(f, &off);
				continue;
			}
			if (!check_str(p, "rw", str_rw_cb, td)) {
				fgetpos(f, &off);
				continue;
			}
			if (!check_str(p, "ioengine", str_ioengine_cb, td)) {
				fgetpos(f, &off);
				continue;
			}
			if (!check_strset(p, "create")) {
				td->create_file = 1;
				fgetpos(f, &off);
				continue;
			}
			if (!check_strset(p, "exitall")) {
				exitall_on_terminate = 1;
				fgetpos(f, &off);
				continue;
			}
			if (!check_strset(p, "stonewall")) {
				td->stonewall = 1;
				fgetpos(f, &off);
				continue;
			}
			if (!check_strset(p, "thread")) {
				td->use_thread = 1;
				fgetpos(f, &off);
				continue;
			}
			if (!check_strstore(p, "iolog", tmpbuf)) {
				if (td->write_iolog) {
					log_err("fio: read iolog overrides given write_iolog\n");
					free(td->iolog_file);
					td->write_iolog = 0;
				}
				td->iolog_file = strdup(tmpbuf);
				td->read_iolog = 1;
				fgetpos(f, &off);
				continue;
			}
			if (!check_strstore(p, "write_iolog", tmpbuf)) {
				if (!td->read_iolog) {
					td->iolog_file = strdup(tmpbuf);
					td->write_iolog = 1;
				} else
					log_err("fio: read iolog overrides given write_iolog\n");
				fgetpos(f, &off);
				continue;
			}
			if (!check_strstore(p, "exec_prerun", tmpbuf)) {
				td->exec_prerun = strdup(tmpbuf);
				fgetpos(f, &off);
				continue;
			}
			if (!check_strstore(p, "exec_postrun", tmpbuf)) {
				td->exec_postrun = strdup(tmpbuf);
				fgetpos(f, &off);
				continue;
			}
			if (!check_strstore(p, "ioscheduler", tmpbuf)) {
#ifndef FIO_HAVE_IOSCHED_SWITCH
				log_err("io scheduler switching not available\n");
				ret = 1;
				break;
#else
				td->ioscheduler = strdup(tmpbuf);
				fgetpos(f, &off);
				continue;
#endif
			}

			/*
			 * Don't break here, continue parsing options so we
			 * dump all the bad ones. Makes trial/error fixups
			 * easier on the user.
			 */
			printf("Client%d: bad option %s\n",td->thread_number,p);
			ret = 1;
		}

		if (!ret) {
			fsetpos(f, &off);
			ret = add_job(td, name, 0);
		}
		if (ret)
			break;
	}

	free(string);
	free(name);
	free(tmpbuf);
	fclose(f);
	return ret;
}

static int fill_def_thread(void)
{
	memset(&def_thread, 0, sizeof(def_thread));

	if (fio_getaffinity(getpid(), &def_thread.cpumask) == -1) {
		perror("sched_getaffinity");
		return 1;
	}

	/*
	 * fill globals
	 */
	def_thread.ddir = DDIR_READ;
	def_thread.iomix = 0;
	def_thread.bs = DEF_BS;
	def_thread.min_bs = -1;
	def_thread.max_bs = -1;
	def_thread.io_engine = DEF_IO_ENGINE;
	strcpy(def_thread.io_engine_name, DEF_IO_ENGINE_NAME);
	def_thread.odirect = DEF_ODIRECT;
	def_thread.ratecycle = DEF_RATE_CYCLE;
	def_thread.sequential = DEF_SEQUENTIAL;
	def_thread.timeout = def_timeout;
	def_thread.create_file = DEF_CREATE;
	def_thread.overwrite = DEF_OVERWRITE;
	def_thread.invalidate_cache = DEF_INVALIDATE;
	def_thread.sync_io = DEF_SYNCIO;
	def_thread.mem_type = MEM_MALLOC;
	def_thread.bw_avg_time = DEF_BWAVGTIME;
	def_thread.create_serialize = DEF_CREATE_SER;
	def_thread.create_fsync = DEF_CREATE_FSYNC;
	def_thread.loops = DEF_LOOPS;
	def_thread.verify = DEF_VERIFY;
	def_thread.stonewall = DEF_STONEWALL;
	def_thread.numjobs = DEF_NUMJOBS;
	def_thread.use_thread = DEF_USE_THREAD;
	def_thread.rwmixcycle = DEF_RWMIX_CYCLE;
	def_thread.rwmixread = DEF_RWMIX_READ;
	def_thread.nice = DEF_NICE;
	def_thread.rand_repeatable = DEF_RAND_REPEAT;
#ifdef FIO_HAVE_DISK_UTIL
	def_thread.do_disk_util = 1;
#endif

	return 0;
}

static void usage(char *name)
{
	printf("%s\n", fio_version_string);
	printf("\t-o Write output to file\n");
	printf("\t-t Runtime in seconds\n");
	printf("\t-l Generate per-job latency logs\n");
	printf("\t-w Generate per-job bandwidth logs\n");
	printf("\t-m Minimal (terse) output\n");
	printf("\t-v Print version info and exit\n");
}

static int parse_cmd_line(int argc, char *argv[])
{
	int c, idx = 1, ini_idx = 0;

	while ((c = getopt(argc, argv, "t:o:lwvhm")) != EOF) {
		switch (c) {
			case 't':
				def_timeout = atoi(optarg);
				idx = optind;
				break;
			case 'l':
				write_lat_log = 1;
				idx = optind;
				break;
			case 'w':
				write_bw_log = 1;
				idx = optind;
				break;
			case 'o':
				f_out = fopen(optarg, "w+");
				if (!f_out) {
					perror("fopen output");
					exit(1);
				}
				f_err = f_out;
				idx = optind;
				break;
			case 'm':
				terse_output = 1;
				idx = optind;
				break;
			case 'h':
				usage(argv[0]);
				exit(0);
			case 'v':
				printf("%s\n", fio_version_string);
				exit(0);
		}
	}

	while (idx < argc) {
		ini_idx++;
		ini_file = realloc(ini_file, ini_idx * sizeof(char *));
		ini_file[ini_idx - 1] = strdup(argv[idx]);
		idx++;
	}

	if (!f_out) {
		f_out = stdout;
		f_err = stderr;
	}

	return ini_idx;
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

int parse_options(int argc, char *argv[])
{
	int job_files, i;

	if (setup_thread_area())
		return 1;
	if (fill_def_thread())
		return 1;

	job_files = parse_cmd_line(argc, argv);
	if (!job_files) {
		log_err("Need job file(s)\n");
		usage(argv[0]);
		return 1;
	}

	for (i = 0; i < job_files; i++) {
		if (fill_def_thread())
			return 1;
		if (parse_jobs_ini(ini_file[i], i))
			return 1;
		free(ini_file[i]);
	}

	free(ini_file);
	return 0;
}
