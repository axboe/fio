#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>
#include <libgen.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "fio.h"
#include "verify.h"
#include "parse.h"
#include "lib/fls.h"
#include "options.h"

#include "crc/crc32c.h"

/*
 * Check if mmap/mmaphuge has a :/foo/bar/file at the end. If so, return that.
 */
static char *get_opt_postfix(const char *str)
{
	char *p = strstr(str, ":");

	if (!p)
		return NULL;

	p++;
	strip_blank_front(&p);
	strip_blank_end(p);
	return strdup(p);
}

static int converthexchartoint(char a)
{
	int base;

	switch (a) {
	case '0'...'9':
		base = '0';
		break;
	case 'A'...'F':
		base = 'A' - 10;
		break;
	case 'a'...'f':
		base = 'a' - 10;
		break;
	default:
		base = 0;
	}
	return a - base;
}

static int bs_cmp(const void *p1, const void *p2)
{
	const struct bssplit *bsp1 = p1;
	const struct bssplit *bsp2 = p2;

	return bsp1->perc < bsp2->perc;
}

static int bssplit_ddir(struct thread_options *o, int ddir, char *str)
{
	struct bssplit *bssplit;
	unsigned int i, perc, perc_missing;
	unsigned int max_bs, min_bs;
	long long val;
	char *fname;

	o->bssplit_nr[ddir] = 4;
	bssplit = malloc(4 * sizeof(struct bssplit));

	i = 0;
	max_bs = 0;
	min_bs = -1;
	while ((fname = strsep(&str, ":")) != NULL) {
		char *perc_str;

		if (!strlen(fname))
			break;

		/*
		 * grow struct buffer, if needed
		 */
		if (i == o->bssplit_nr[ddir]) {
			o->bssplit_nr[ddir] <<= 1;
			bssplit = realloc(bssplit, o->bssplit_nr[ddir]
						  * sizeof(struct bssplit));
		}

		perc_str = strstr(fname, "/");
		if (perc_str) {
			*perc_str = '\0';
			perc_str++;
			perc = atoi(perc_str);
			if (perc > 100)
				perc = 100;
			else if (!perc)
				perc = -1;
		} else
			perc = -1;

		if (str_to_decimal(fname, &val, 1, o, 0)) {
			log_err("fio: bssplit conversion failed\n");
			free(bssplit);
			return 1;
		}

		if (val > max_bs)
			max_bs = val;
		if (val < min_bs)
			min_bs = val;

		bssplit[i].bs = val;
		bssplit[i].perc = perc;
		i++;
	}

	o->bssplit_nr[ddir] = i;

	/*
	 * Now check if the percentages add up, and how much is missing
	 */
	perc = perc_missing = 0;
	for (i = 0; i < o->bssplit_nr[ddir]; i++) {
		struct bssplit *bsp = &bssplit[i];

		if (bsp->perc == (unsigned char) -1)
			perc_missing++;
		else
			perc += bsp->perc;
	}

	if (perc > 100) {
		log_err("fio: bssplit percentages add to more than 100%%\n");
		free(bssplit);
		return 1;
	}
	/*
	 * If values didn't have a percentage set, divide the remains between
	 * them.
	 */
	if (perc_missing) {
		for (i = 0; i < o->bssplit_nr[ddir]; i++) {
			struct bssplit *bsp = &bssplit[i];

			if (bsp->perc == (unsigned char) -1)
				bsp->perc = (100 - perc) / perc_missing;
		}
	}

	o->min_bs[ddir] = min_bs;
	o->max_bs[ddir] = max_bs;

	/*
	 * now sort based on percentages, for ease of lookup
	 */
	qsort(bssplit, o->bssplit_nr[ddir], sizeof(struct bssplit), bs_cmp);
	o->bssplit[ddir] = bssplit;
	return 0;
}

static int str_bssplit_cb(void *data, const char *input)
{
	struct thread_data *td = data;
	char *str, *p, *odir, *ddir;
	int ret = 0;

	if (parse_dryrun())
		return 0;

	p = str = strdup(input);

	strip_blank_front(&str);
	strip_blank_end(str);

	odir = strchr(str, ',');
	if (odir) {
		ddir = strchr(odir + 1, ',');
		if (ddir) {
			ret = bssplit_ddir(&td->o, DDIR_TRIM, ddir + 1);
			if (!ret)
				*ddir = '\0';
		} else {
			char *op;

			op = strdup(odir + 1);
			ret = bssplit_ddir(&td->o, DDIR_TRIM, op);

			free(op);
		}
		if (!ret)
			ret = bssplit_ddir(&td->o, DDIR_WRITE, odir + 1);
		if (!ret) {
			*odir = '\0';
			ret = bssplit_ddir(&td->o, DDIR_READ, str);
		}
	} else {
		char *op;

		op = strdup(str);
		ret = bssplit_ddir(&td->o, DDIR_WRITE, op);
		free(op);

		if (!ret) {
			op = strdup(str);
			ret = bssplit_ddir(&td->o, DDIR_TRIM, op);
			free(op);
		}
		ret = bssplit_ddir(&td->o, DDIR_READ, str);
	}

	free(p);
	return ret;
}

static int str2error(char *str)
{
	const char *err[] = { "EPERM", "ENOENT", "ESRCH", "EINTR", "EIO",
			    "ENXIO", "E2BIG", "ENOEXEC", "EBADF",
			    "ECHILD", "EAGAIN", "ENOMEM", "EACCES",
			    "EFAULT", "ENOTBLK", "EBUSY", "EEXIST",
			    "EXDEV", "ENODEV", "ENOTDIR", "EISDIR",
			    "EINVAL", "ENFILE", "EMFILE", "ENOTTY",
			    "ETXTBSY","EFBIG", "ENOSPC", "ESPIPE",
			    "EROFS","EMLINK", "EPIPE", "EDOM", "ERANGE" };
	int i = 0, num = sizeof(err) / sizeof(void *);

	while (i < num) {
		if (!strcmp(err[i], str))
			return i + 1;
		i++;
	}
	return 0;
}

static int ignore_error_type(struct thread_data *td, int etype, char *str)
{
	unsigned int i;
	int *error;
	char *fname;

	if (etype >= ERROR_TYPE_CNT) {
		log_err("Illegal error type\n");
		return 1;
	}

	td->o.ignore_error_nr[etype] = 4;
	error = malloc(4 * sizeof(struct bssplit));

	i = 0;
	while ((fname = strsep(&str, ":")) != NULL) {

		if (!strlen(fname))
			break;

		/*
		 * grow struct buffer, if needed
		 */
		if (i == td->o.ignore_error_nr[etype]) {
			td->o.ignore_error_nr[etype] <<= 1;
			error = realloc(error, td->o.ignore_error_nr[etype]
						  * sizeof(int));
		}
		if (fname[0] == 'E') {
			error[i] = str2error(fname);
		} else {
			error[i] = atoi(fname);
			if (error[i] < 0)
				error[i] = -error[i];
		}
		if (!error[i]) {
			log_err("Unknown error %s, please use number value \n",
				  fname);
			free(error);
			return 1;
		}
		i++;
	}
	if (i) {
		td->o.continue_on_error |= 1 << etype;
		td->o.ignore_error_nr[etype] = i;
		td->o.ignore_error[etype] = error;
	} else
		free(error);

	return 0;

}

static int str_ignore_error_cb(void *data, const char *input)
{
	struct thread_data *td = data;
	char *str, *p, *n;
	int type = 0, ret = 1;

	if (parse_dryrun())
		return 0;

	p = str = strdup(input);

	strip_blank_front(&str);
	strip_blank_end(str);

	while (p) {
		n = strchr(p, ',');
		if (n)
			*n++ = '\0';
		ret = ignore_error_type(td, type, p);
		if (ret)
			break;
		p = n;
		type++;
	}
	free(str);
	return ret;
}

static int str_rw_cb(void *data, const char *str)
{
	struct thread_data *td = data;
	struct thread_options *o = &td->o;
	char *nr;

	if (parse_dryrun())
		return 0;

	o->ddir_seq_nr = 1;
	o->ddir_seq_add = 0;

	nr = get_opt_postfix(str);
	if (!nr)
		return 0;

	if (td_random(td))
		o->ddir_seq_nr = atoi(nr);
	else {
		long long val;

		if (str_to_decimal(nr, &val, 1, o, 0)) {
			log_err("fio: rw postfix parsing failed\n");
			free(nr);
			return 1;
		}

		o->ddir_seq_add = val;
	}

	free(nr);
	return 0;
}

static int str_mem_cb(void *data, const char *mem)
{
	struct thread_data *td = data;

	if (td->o.mem_type == MEM_MMAPHUGE || td->o.mem_type == MEM_MMAP)
		td->o.mmapfile = get_opt_postfix(mem);

	return 0;
}

static int fio_clock_source_cb(void *data, const char *str)
{
	struct thread_data *td = data;

	fio_clock_source = td->o.clocksource;
	fio_clock_source_set = 1;
	fio_clock_init();
	return 0;
}

static int str_rwmix_read_cb(void *data, unsigned long long *val)
{
	struct thread_data *td = data;

	td->o.rwmix[DDIR_READ] = *val;
	td->o.rwmix[DDIR_WRITE] = 100 - *val;
	return 0;
}

static int str_rwmix_write_cb(void *data, unsigned long long *val)
{
	struct thread_data *td = data;

	td->o.rwmix[DDIR_WRITE] = *val;
	td->o.rwmix[DDIR_READ] = 100 - *val;
	return 0;
}

static int str_exitall_cb(void)
{
	exitall_on_terminate = 1;
	return 0;
}

#ifdef FIO_HAVE_CPU_AFFINITY
int fio_cpus_split(os_cpu_mask_t *mask, unsigned int cpu_index)
{
	unsigned int i, index, cpus_in_mask;
	const long max_cpu = cpus_online();

	cpus_in_mask = fio_cpu_count(mask);
	cpu_index = cpu_index % cpus_in_mask;

	index = 0;
	for (i = 0; i < max_cpu; i++) {
		if (!fio_cpu_isset(mask, i))
			continue;

		if (cpu_index != index)
			fio_cpu_clear(mask, i);

		index++;
	}

	return fio_cpu_count(mask);
}

static int str_cpumask_cb(void *data, unsigned long long *val)
{
	struct thread_data *td = data;
	unsigned int i;
	long max_cpu;
	int ret;

	if (parse_dryrun())
		return 0;

	ret = fio_cpuset_init(&td->o.cpumask);
	if (ret < 0) {
		log_err("fio: cpuset_init failed\n");
		td_verror(td, ret, "fio_cpuset_init");
		return 1;
	}

	max_cpu = cpus_online();

	for (i = 0; i < sizeof(int) * 8; i++) {
		if ((1 << i) & *val) {
			if (i > max_cpu) {
				log_err("fio: CPU %d too large (max=%ld)\n", i,
								max_cpu);
				return 1;
			}
			dprint(FD_PARSE, "set cpu allowed %d\n", i);
			fio_cpu_set(&td->o.cpumask, i);
		}
	}

	td->o.cpumask_set = 1;
	return 0;
}

static int set_cpus_allowed(struct thread_data *td, os_cpu_mask_t *mask,
			    const char *input)
{
	char *cpu, *str, *p;
	long max_cpu;
	int ret = 0;

	ret = fio_cpuset_init(mask);
	if (ret < 0) {
		log_err("fio: cpuset_init failed\n");
		td_verror(td, ret, "fio_cpuset_init");
		return 1;
	}

	p = str = strdup(input);

	strip_blank_front(&str);
	strip_blank_end(str);

	max_cpu = cpus_online();

	while ((cpu = strsep(&str, ",")) != NULL) {
		char *str2, *cpu2;
		int icpu, icpu2;

		if (!strlen(cpu))
			break;

		str2 = cpu;
		icpu2 = -1;
		while ((cpu2 = strsep(&str2, "-")) != NULL) {
			if (!strlen(cpu2))
				break;

			icpu2 = atoi(cpu2);
		}

		icpu = atoi(cpu);
		if (icpu2 == -1)
			icpu2 = icpu;
		while (icpu <= icpu2) {
			if (icpu >= FIO_MAX_CPUS) {
				log_err("fio: your OS only supports up to"
					" %d CPUs\n", (int) FIO_MAX_CPUS);
				ret = 1;
				break;
			}
			if (icpu > max_cpu) {
				log_err("fio: CPU %d too large (max=%ld)\n",
							icpu, max_cpu);
				ret = 1;
				break;
			}

			dprint(FD_PARSE, "set cpu allowed %d\n", icpu);
			fio_cpu_set(mask, icpu);
			icpu++;
		}
		if (ret)
			break;
	}

	free(p);
	if (!ret)
		td->o.cpumask_set = 1;
	return ret;
}

static int str_cpus_allowed_cb(void *data, const char *input)
{
	struct thread_data *td = data;
	int ret;

	if (parse_dryrun())
		return 0;

	ret = set_cpus_allowed(td, &td->o.cpumask, input);
	if (!ret)
		td->o.cpumask_set = 1;

	return ret;
}

static int str_verify_cpus_allowed_cb(void *data, const char *input)
{
	struct thread_data *td = data;
	int ret;

	ret = set_cpus_allowed(td, &td->o.verify_cpumask, input);
	if (!ret)
		td->o.verify_cpumask_set = 1;

	return ret;
}
#endif

#ifdef CONFIG_LIBNUMA
static int str_numa_cpunodes_cb(void *data, char *input)
{
	struct thread_data *td = data;
	struct bitmask *verify_bitmask;

	if (parse_dryrun())
		return 0;

	/* numa_parse_nodestring() parses a character string list
	 * of nodes into a bit mask. The bit mask is allocated by
	 * numa_allocate_nodemask(), so it should be freed by
	 * numa_free_nodemask().
	 */
	verify_bitmask = numa_parse_nodestring(input);
	if (verify_bitmask == NULL) {
		log_err("fio: numa_parse_nodestring failed\n");
		td_verror(td, 1, "str_numa_cpunodes_cb");
		return 1;
	}
	numa_free_nodemask(verify_bitmask);

	td->o.numa_cpunodes = strdup(input);
	td->o.numa_cpumask_set = 1;
	return 0;
}

static int str_numa_mpol_cb(void *data, char *input)
{
	struct thread_data *td = data;
	const char * const policy_types[] =
		{ "default", "prefer", "bind", "interleave", "local", NULL };
	int i;
	char *nodelist;
	struct bitmask *verify_bitmask;

	if (parse_dryrun())
		return 0;

	nodelist = strchr(input, ':');
	if (nodelist) {
		/* NUL-terminate mode */
		*nodelist++ = '\0';
	}

	for (i = 0; i <= MPOL_LOCAL; i++) {
		if (!strcmp(input, policy_types[i])) {
			td->o.numa_mem_mode = i;
			break;
		}
	}
	if (i > MPOL_LOCAL) {
		log_err("fio: memory policy should be: default, prefer, bind, interleave, local\n");
		goto out;
	}

	switch (td->o.numa_mem_mode) {
	case MPOL_PREFERRED:
		/*
		 * Insist on a nodelist of one node only
		 */
		if (nodelist) {
			char *rest = nodelist;
			while (isdigit(*rest))
				rest++;
			if (*rest) {
				log_err("fio: one node only for \'prefer\'\n");
				goto out;
			}
		} else {
			log_err("fio: one node is needed for \'prefer\'\n");
			goto out;
		}
		break;
	case MPOL_INTERLEAVE:
		/*
		 * Default to online nodes with memory if no nodelist
		 */
		if (!nodelist)
			nodelist = strdup("all");
		break;
	case MPOL_LOCAL:
	case MPOL_DEFAULT:
		/*
		 * Don't allow a nodelist
		 */
		if (nodelist) {
			log_err("fio: NO nodelist for \'local\'\n");
			goto out;
		}
		break;
	case MPOL_BIND:
		/*
		 * Insist on a nodelist
		 */
		if (!nodelist) {
			log_err("fio: a nodelist is needed for \'bind\'\n");
			goto out;
		}
		break;
	}


	/* numa_parse_nodestring() parses a character string list
	 * of nodes into a bit mask. The bit mask is allocated by
	 * numa_allocate_nodemask(), so it should be freed by
	 * numa_free_nodemask().
	 */
	switch (td->o.numa_mem_mode) {
	case MPOL_PREFERRED:
		td->o.numa_mem_prefer_node = atoi(nodelist);
		break;
	case MPOL_INTERLEAVE:
	case MPOL_BIND:
		verify_bitmask = numa_parse_nodestring(nodelist);
		if (verify_bitmask == NULL) {
			log_err("fio: numa_parse_nodestring failed\n");
			td_verror(td, 1, "str_numa_memnodes_cb");
			return 1;
		}
		td->o.numa_memnodes = strdup(nodelist);
		numa_free_nodemask(verify_bitmask);
                
		break;
	case MPOL_LOCAL:
	case MPOL_DEFAULT:
	default:
		break;
	}

	td->o.numa_memmask_set = 1;
	return 0;

out:
	return 1;
}
#endif

static int str_fst_cb(void *data, const char *str)
{
	struct thread_data *td = data;
	char *nr = get_opt_postfix(str);

	td->file_service_nr = 1;
	if (nr) {
		td->file_service_nr = atoi(nr);
		free(nr);
	}

	return 0;
}

#ifdef CONFIG_SYNC_FILE_RANGE
static int str_sfr_cb(void *data, const char *str)
{
	struct thread_data *td = data;
	char *nr = get_opt_postfix(str);

	td->sync_file_range_nr = 1;
	if (nr) {
		td->sync_file_range_nr = atoi(nr);
		free(nr);
	}

	return 0;
}
#endif

static int str_random_distribution_cb(void *data, const char *str)
{
	struct thread_data *td = data;
	double val;
	char *nr;

	if (parse_dryrun())
		return 0;

	if (td->o.random_distribution == FIO_RAND_DIST_ZIPF)
		val = 1.1;
	else if (td->o.random_distribution == FIO_RAND_DIST_PARETO)
		val = 0.2;
	else
		return 0;

	nr = get_opt_postfix(str);
	if (nr && !str_to_float(nr, &val)) {
		log_err("fio: random postfix parsing failed\n");
		free(nr);
		return 1;
	}

	free(nr);

	if (td->o.random_distribution == FIO_RAND_DIST_ZIPF) {
		if (val == 1.00) {
			log_err("fio: zipf theta must different than 1.0\n");
			return 1;
		}
		td->o.zipf_theta.u.f = val;
	} else {
		if (val <= 0.00 || val >= 1.00) {
			log_err("fio: pareto input out of range (0 < input < 1.0)\n");
			return 1;
		}
		td->o.pareto_h.u.f = val;
	}

	return 0;
}

/*
 * Return next name in the string. Files are separated with ':'. If the ':'
 * is escaped with a '\', then that ':' is part of the filename and does not
 * indicate a new file.
 */
static char *get_next_name(char **ptr)
{
	char *str = *ptr;
	char *p, *start;

	if (!str || !strlen(str))
		return NULL;

	start = str;
	do {
		/*
		 * No colon, we are done
		 */
		p = strchr(str, ':');
		if (!p) {
			*ptr = NULL;
			break;
		}

		/*
		 * We got a colon, but it's the first character. Skip and
		 * continue
		 */
		if (p == start) {
			str = ++start;
			continue;
		}

		if (*(p - 1) != '\\') {
			*p = '\0';
			*ptr = p + 1;
			break;
		}

		memmove(p - 1, p, strlen(p) + 1);
		str = p;
	} while (1);

	return start;
}


static int get_max_name_idx(char *input)
{
	unsigned int cur_idx;
	char *str, *p;

	p = str = strdup(input);
	for (cur_idx = 0; ; cur_idx++)
		if (get_next_name(&str) == NULL)
			break;

	free(p);
	return cur_idx;
}

/*
 * Returns the directory at the index, indexes > entires will be
 * assigned via modulo division of the index
 */
int set_name_idx(char *target, char *input, int index)
{
	unsigned int cur_idx;
	int len;
	char *fname, *str, *p;

	p = str = strdup(input);

	index %= get_max_name_idx(input);
	for (cur_idx = 0; cur_idx <= index; cur_idx++)
		fname = get_next_name(&str);

	len = sprintf(target, "%s/", fname);
	free(p);

	return len;
}

static int str_filename_cb(void *data, const char *input)
{
	struct thread_data *td = data;
	char *fname, *str, *p;

	p = str = strdup(input);

	strip_blank_front(&str);
	strip_blank_end(str);

	if (!td->files_index)
		td->o.nr_files = 0;

	while ((fname = get_next_name(&str)) != NULL) {
		if (!strlen(fname))
			break;
		add_file(td, fname, 0, 1);
	}

	free(p);
	return 0;
}

static int str_directory_cb(void *data, const char fio_unused *unused)
{
	struct thread_data *td = data;
	struct stat sb;
	char *dirname, *str, *p;
	int ret = 0;

	if (parse_dryrun())
		return 0;

	p = str = strdup(td->o.directory);
	while ((dirname = get_next_name(&str)) != NULL) {
		if (lstat(dirname, &sb) < 0) {
			ret = errno;

			log_err("fio: %s is not a directory\n", dirname);
			td_verror(td, ret, "lstat");
			goto out;
		}
		if (!S_ISDIR(sb.st_mode)) {
			log_err("fio: %s is not a directory\n", dirname);
			ret = 1;
			goto out;
		}
	}

out:
	free(p);
	return ret;
}

static int str_lockfile_cb(void *data, const char fio_unused *str)
{
	struct thread_data *td = data;

	if (td->files_index) {
		log_err("fio: lockfile= option must precede filename=\n");
		return 1;
	}

	return 0;
}

static int str_opendir_cb(void *data, const char fio_unused *str)
{
	struct thread_data *td = data;

	if (parse_dryrun())
		return 0;

	if (!td->files_index)
		td->o.nr_files = 0;

	return add_dir_files(td, td->o.opendir);
}

static int pattern_cb(char *pattern, unsigned int max_size,
		      const char *input, unsigned int *pattern_bytes)
{
	long off;
	int i = 0, j = 0, len, k, base = 10;
	uint32_t pattern_length;
	char *loc1, *loc2;

	loc1 = strstr(input, "0x");
	loc2 = strstr(input, "0X");
	if (loc1 || loc2)
		base = 16;
	off = strtol(input, NULL, base);
	if (off != LONG_MAX || errno != ERANGE) {
		while (off) {
			pattern[i] = off & 0xff;
			off >>= 8;
			i++;
		}
	} else {
		len = strlen(input);
		k = len - 1;
		if (base == 16) {
			if (loc1)
				j = loc1 - input + 2;
			else
				j = loc2 - input + 2;
		} else
			return 1;
		if (len - j < max_size * 2) {
			while (k >= j) {
				off = converthexchartoint(input[k--]);
				if (k >= j)
					off += (converthexchartoint(input[k--])
						* 16);
				pattern[i++] = (char) off;
			}
		}
	}

	/*
	 * Fill the pattern all the way to the end. This greatly reduces
	 * the number of memcpy's we have to do when verifying the IO.
	 */
	pattern_length = i;
	while (i > 1 && i * 2 <= max_size) {
		memcpy(&pattern[i], &pattern[0], i);
		i *= 2;
	}

	/*
	 * Fill remainder, if the pattern multiple ends up not being
	 * max_size.
	 */
	while (i > 1 && i < max_size) {
		unsigned int b = min(pattern_length, max_size - i);

		memcpy(&pattern[i], &pattern[0], b);
		i += b;
	}

	if (i == 1) {
		/*
		 * The code in verify_io_u_pattern assumes a single byte pattern
		 * fills the whole verify pattern buffer.
		 */
		memset(pattern, pattern[0], max_size);
	}

	*pattern_bytes = i;
	return 0;
}

static int str_buffer_pattern_cb(void *data, const char *input)
{
	struct thread_data *td = data;
	int ret;

	ret = pattern_cb(td->o.buffer_pattern, MAX_PATTERN_SIZE, input,
				&td->o.buffer_pattern_bytes);

	if (!ret) {
		td->o.refill_buffers = 0;
		td->o.scramble_buffers = 0;
		td->o.zero_buffers = 0;
	}

	return ret;
}

static int str_buffer_compress_cb(void *data, unsigned long long *il)
{
	struct thread_data *td = data;

	td->flags |= TD_F_COMPRESS;
	td->o.compress_percentage = *il;
	return 0;
}

static int str_verify_pattern_cb(void *data, const char *input)
{
	struct thread_data *td = data;
	int ret;

	ret = pattern_cb(td->o.verify_pattern, MAX_PATTERN_SIZE, input,
				&td->o.verify_pattern_bytes);

	/*
	 * VERIFY_META could already be set
	 */
	if (!ret && td->o.verify == VERIFY_NONE)
		td->o.verify = VERIFY_PATTERN;

	return ret;
}

static int str_gtod_reduce_cb(void *data, int *il)
{
	struct thread_data *td = data;
	int val = *il;

	td->o.disable_lat = !!val;
	td->o.disable_clat = !!val;
	td->o.disable_slat = !!val;
	td->o.disable_bw = !!val;
	td->o.clat_percentiles = !val;
	if (val)
		td->tv_cache_mask = 63;

	return 0;
}

static int str_gtod_cpu_cb(void *data, long long *il)
{
	struct thread_data *td = data;
	int val = *il;

	td->o.gtod_cpu = val;
	td->o.gtod_offload = 1;
	return 0;
}

static int str_size_cb(void *data, unsigned long long *__val)
{
	struct thread_data *td = data;
	unsigned long long v = *__val;

	if (parse_is_percent(v)) {
		td->o.size = 0;
		td->o.size_percent = -1ULL - v;
	} else
		td->o.size = v;

	return 0;
}

static int rw_verify(struct fio_option *o, void *data)
{
	struct thread_data *td = data;

	if (read_only && td_write(td)) {
		log_err("fio: job <%s> has write bit set, but fio is in"
			" read-only mode\n", td->o.name);
		return 1;
	}

	return 0;
}

static int gtod_cpu_verify(struct fio_option *o, void *data)
{
#ifndef FIO_HAVE_CPU_AFFINITY
	struct thread_data *td = data;

	if (td->o.gtod_cpu) {
		log_err("fio: platform must support CPU affinity for"
			"gettimeofday() offloading\n");
		return 1;
	}
#endif

	return 0;
}

/*
 * Option grouping
 */
static struct opt_group fio_opt_groups[] = {
	{
		.name	= "General",
		.mask	= FIO_OPT_C_GENERAL,
	},
	{
		.name	= "I/O",
		.mask	= FIO_OPT_C_IO,
	},
	{
		.name	= "File",
		.mask	= FIO_OPT_C_FILE,
	},
	{
		.name	= "Statistics",
		.mask	= FIO_OPT_C_STAT,
	},
	{
		.name	= "Logging",
		.mask	= FIO_OPT_C_LOG,
	},
	{
		.name	= "Profiles",
		.mask	= FIO_OPT_C_PROFILE,
	},
	{
		.name	= NULL,
	},
};

static struct opt_group *__opt_group_from_mask(struct opt_group *ogs, unsigned int *mask,
					       unsigned int inv_mask)
{
	struct opt_group *og;
	int i;

	if (*mask == inv_mask || !*mask)
		return NULL;

	for (i = 0; ogs[i].name; i++) {
		og = &ogs[i];

		if (*mask & og->mask) {
			*mask &= ~(og->mask);
			return og;
		}
	}

	return NULL;
}

struct opt_group *opt_group_from_mask(unsigned int *mask)
{
	return __opt_group_from_mask(fio_opt_groups, mask, FIO_OPT_C_INVALID);
}

static struct opt_group fio_opt_cat_groups[] = {
	{
		.name	= "Latency profiling",
		.mask	= FIO_OPT_G_LATPROF,
	},
	{
		.name	= "Rate",
		.mask	= FIO_OPT_G_RATE,
	},
	{
		.name	= "Zone",
		.mask	= FIO_OPT_G_ZONE,
	},
	{
		.name	= "Read/write mix",
		.mask	= FIO_OPT_G_RWMIX,
	},
	{
		.name	= "Verify",
		.mask	= FIO_OPT_G_VERIFY,
	},
	{
		.name	= "Trim",
		.mask	= FIO_OPT_G_TRIM,
	},
	{
		.name	= "I/O Logging",
		.mask	= FIO_OPT_G_IOLOG,
	},
	{
		.name	= "I/O Depth",
		.mask	= FIO_OPT_G_IO_DEPTH,
	},
	{
		.name	= "I/O Flow",
		.mask	= FIO_OPT_G_IO_FLOW,
	},
	{
		.name	= "Description",
		.mask	= FIO_OPT_G_DESC,
	},
	{
		.name	= "Filename",
		.mask	= FIO_OPT_G_FILENAME,
	},
	{
		.name	= "General I/O",
		.mask	= FIO_OPT_G_IO_BASIC,
	},
	{
		.name	= "Cgroups",
		.mask	= FIO_OPT_G_CGROUP,
	},
	{
		.name	= "Runtime",
		.mask	= FIO_OPT_G_RUNTIME,
	},
	{
		.name	= "Process",
		.mask	= FIO_OPT_G_PROCESS,
	},
	{
		.name	= "Job credentials / priority",
		.mask	= FIO_OPT_G_CRED,
	},
	{
		.name	= "Clock settings",
		.mask	= FIO_OPT_G_CLOCK,
	},
	{
		.name	= "I/O Type",
		.mask	= FIO_OPT_G_IO_TYPE,
	},
	{
		.name	= "I/O Thinktime",
		.mask	= FIO_OPT_G_THINKTIME,
	},
	{
		.name	= "Randomizations",
		.mask	= FIO_OPT_G_RANDOM,
	},
	{
		.name	= "I/O buffers",
		.mask	= FIO_OPT_G_IO_BUF,
	},
	{
		.name	= "Tiobench profile",
		.mask	= FIO_OPT_G_TIOBENCH,
	},

	{
		.name	= NULL,
	}
};

struct opt_group *opt_group_cat_from_mask(unsigned int *mask)
{
	return __opt_group_from_mask(fio_opt_cat_groups, mask, FIO_OPT_G_INVALID);
}

/*
 * Map of job/command line options
 */
struct fio_option fio_options[FIO_MAX_OPTS] = {
	{
		.name	= "description",
		.lname	= "Description of job",
		.type	= FIO_OPT_STR_STORE,
		.off1	= td_var_offset(description),
		.help	= "Text job description",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_DESC,
	},
	{
		.name	= "name",
		.lname	= "Job name",
		.type	= FIO_OPT_STR_STORE,
		.off1	= td_var_offset(name),
		.help	= "Name of this job",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_DESC,
	},
	{
		.name	= "filename",
		.lname	= "Filename(s)",
		.type	= FIO_OPT_STR_STORE,
		.off1	= td_var_offset(filename),
		.cb	= str_filename_cb,
		.prio	= -1, /* must come after "directory" */
		.help	= "File(s) to use for the workload",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_FILENAME,
	},
	{
		.name	= "directory",
		.lname	= "Directory",
		.type	= FIO_OPT_STR_STORE,
		.off1	= td_var_offset(directory),
		.cb	= str_directory_cb,
		.help	= "Directory to store files in",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_FILENAME,
	},
	{
		.name	= "filename_format",
		.type	= FIO_OPT_STR_STORE,
		.off1	= td_var_offset(filename_format),
		.prio	= -1, /* must come after "directory" */
		.help	= "Override default $jobname.$jobnum.$filenum naming",
		.def	= "$jobname.$jobnum.$filenum",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_FILENAME,
	},
	{
		.name	= "lockfile",
		.lname	= "Lockfile",
		.type	= FIO_OPT_STR,
		.off1	= td_var_offset(file_lock_mode),
		.help	= "Lock file when doing IO to it",
		.prio	= 1,
		.parent	= "filename",
		.hide	= 0,
		.def	= "none",
		.cb	= str_lockfile_cb,
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_FILENAME,
		.posval = {
			  { .ival = "none",
			    .oval = FILE_LOCK_NONE,
			    .help = "No file locking",
			  },
			  { .ival = "exclusive",
			    .oval = FILE_LOCK_EXCLUSIVE,
			    .help = "Exclusive file lock",
			  },
			  {
			    .ival = "readwrite",
			    .oval = FILE_LOCK_READWRITE,
			    .help = "Read vs write lock",
			  },
		},
	},
	{
		.name	= "opendir",
		.lname	= "Open directory",
		.type	= FIO_OPT_STR_STORE,
		.off1	= td_var_offset(opendir),
		.cb	= str_opendir_cb,
		.help	= "Recursively add files from this directory and down",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_FILENAME,
	},
	{
		.name	= "rw",
		.lname	= "Read/write",
		.alias	= "readwrite",
		.type	= FIO_OPT_STR,
		.cb	= str_rw_cb,
		.off1	= td_var_offset(td_ddir),
		.help	= "IO direction",
		.def	= "read",
		.verify	= rw_verify,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_BASIC,
		.posval = {
			  { .ival = "read",
			    .oval = TD_DDIR_READ,
			    .help = "Sequential read",
			  },
			  { .ival = "write",
			    .oval = TD_DDIR_WRITE,
			    .help = "Sequential write",
			  },
			  { .ival = "trim",
			    .oval = TD_DDIR_TRIM,
			    .help = "Sequential trim",
			  },
			  { .ival = "randread",
			    .oval = TD_DDIR_RANDREAD,
			    .help = "Random read",
			  },
			  { .ival = "randwrite",
			    .oval = TD_DDIR_RANDWRITE,
			    .help = "Random write",
			  },
			  { .ival = "randtrim",
			    .oval = TD_DDIR_RANDTRIM,
			    .help = "Random trim",
			  },
			  { .ival = "rw",
			    .oval = TD_DDIR_RW,
			    .help = "Sequential read and write mix",
			  },
			  { .ival = "readwrite",
			    .oval = TD_DDIR_RW,
			    .help = "Sequential read and write mix",
			  },
			  { .ival = "randrw",
			    .oval = TD_DDIR_RANDRW,
			    .help = "Random read and write mix"
			  },
		},
	},
	{
		.name	= "rw_sequencer",
		.lname	= "RW Sequencer",
		.type	= FIO_OPT_STR,
		.off1	= td_var_offset(rw_seq),
		.help	= "IO offset generator modifier",
		.def	= "sequential",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_BASIC,
		.posval = {
			  { .ival = "sequential",
			    .oval = RW_SEQ_SEQ,
			    .help = "Generate sequential offsets",
			  },
			  { .ival = "identical",
			    .oval = RW_SEQ_IDENT,
			    .help = "Generate identical offsets",
			  },
		},
	},

	{
		.name	= "ioengine",
		.lname	= "IO Engine",
		.type	= FIO_OPT_STR_STORE,
		.off1	= td_var_offset(ioengine),
		.help	= "IO engine to use",
		.def	= FIO_PREFERRED_ENGINE,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_BASIC,
		.posval	= {
			  { .ival = "sync",
			    .help = "Use read/write",
			  },
			  { .ival = "psync",
			    .help = "Use pread/pwrite",
			  },
			  { .ival = "vsync",
			    .help = "Use readv/writev",
			  },
#ifdef CONFIG_PWRITEV
			  { .ival = "pvsync",
			    .help = "Use preadv/pwritev",
			  },
#endif
#ifdef CONFIG_LIBAIO
			  { .ival = "libaio",
			    .help = "Linux native asynchronous IO",
			  },
#endif
#ifdef CONFIG_POSIXAIO
			  { .ival = "posixaio",
			    .help = "POSIX asynchronous IO",
			  },
#endif
#ifdef CONFIG_SOLARISAIO
			  { .ival = "solarisaio",
			    .help = "Solaris native asynchronous IO",
			  },
#endif
#ifdef CONFIG_WINDOWSAIO
			  { .ival = "windowsaio",
			    .help = "Windows native asynchronous IO"
			  },
#endif
#ifdef CONFIG_RBD
			  { .ival = "rbd",
			    .help = "Rados Block Device asynchronous IO"
			  },
#endif
			  { .ival = "mmap",
			    .help = "Memory mapped IO"
			  },
#ifdef CONFIG_LINUX_SPLICE
			  { .ival = "splice",
			    .help = "splice/vmsplice based IO",
			  },
			  { .ival = "netsplice",
			    .help = "splice/vmsplice to/from the network",
			  },
#endif
#ifdef FIO_HAVE_SGIO
			  { .ival = "sg",
			    .help = "SCSI generic v3 IO",
			  },
#endif
			  { .ival = "null",
			    .help = "Testing engine (no data transfer)",
			  },
			  { .ival = "net",
			    .help = "Network IO",
			  },
			  { .ival = "cpuio",
			    .help = "CPU cycle burner engine",
			  },
#ifdef CONFIG_GUASI
			  { .ival = "guasi",
			    .help = "GUASI IO engine",
			  },
#endif
#ifdef FIO_HAVE_BINJECT
			  { .ival = "binject",
			    .help = "binject direct inject block engine",
			  },
#endif
#ifdef CONFIG_RDMA
			  { .ival = "rdma",
			    .help = "RDMA IO engine",
			  },
#endif
#ifdef CONFIG_FUSION_AW
			  { .ival = "fusion-aw-sync",
			    .help = "Fusion-io atomic write engine",
			  },
#endif
#ifdef CONFIG_LINUX_EXT4_MOVE_EXTENT
			  { .ival = "e4defrag",
			    .help = "ext4 defrag engine",
			  },
#endif
#ifdef CONFIG_LINUX_FALLOCATE
			  { .ival = "falloc",
			    .help = "fallocate() file based engine",
			  },
#endif
			  { .ival = "external",
			    .help = "Load external engine (append name)",
			  },
		},
	},
	{
		.name	= "iodepth",
		.lname	= "IO Depth",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(iodepth),
		.help	= "Number of IO buffers to keep in flight",
		.minval = 1,
		.interval = 1,
		.def	= "1",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_BASIC,
	},
	{
		.name	= "iodepth_batch",
		.lname	= "IO Depth batch",
		.alias	= "iodepth_batch_submit",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(iodepth_batch),
		.help	= "Number of IO buffers to submit in one go",
		.parent	= "iodepth",
		.hide	= 1,
		.minval	= 1,
		.interval = 1,
		.def	= "1",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_BASIC,
	},
	{
		.name	= "iodepth_batch_complete",
		.lname	= "IO Depth batch complete",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(iodepth_batch_complete),
		.help	= "Number of IO buffers to retrieve in one go",
		.parent	= "iodepth",
		.hide	= 1,
		.minval	= 0,
		.interval = 1,
		.def	= "1",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_BASIC,
	},
	{
		.name	= "iodepth_low",
		.lname	= "IO Depth batch low",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(iodepth_low),
		.help	= "Low water mark for queuing depth",
		.parent	= "iodepth",
		.hide	= 1,
		.interval = 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_BASIC,
	},
	{
		.name	= "size",
		.lname	= "Size",
		.type	= FIO_OPT_STR_VAL,
		.cb	= str_size_cb,
		.help	= "Total size of device or files",
		.interval = 1024 * 1024,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "io_limit",
		.lname	= "IO Limit",
		.type	= FIO_OPT_STR_VAL,
		.off1	= td_var_offset(io_limit),
		.interval = 1024 * 1024,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "fill_device",
		.lname	= "Fill device",
		.alias	= "fill_fs",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(fill_device),
		.help	= "Write until an ENOSPC error occurs",
		.def	= "0",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "filesize",
		.lname	= "File size",
		.type	= FIO_OPT_STR_VAL,
		.off1	= td_var_offset(file_size_low),
		.off2	= td_var_offset(file_size_high),
		.minval = 1,
		.help	= "Size of individual files",
		.interval = 1024 * 1024,
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "file_append",
		.lname	= "File append",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(file_append),
		.help	= "IO will start at the end of the file(s)",
		.def	= "0",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "offset",
		.lname	= "IO offset",
		.alias	= "fileoffset",
		.type	= FIO_OPT_STR_VAL,
		.off1	= td_var_offset(start_offset),
		.help	= "Start IO from this offset",
		.def	= "0",
		.interval = 1024 * 1024,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "offset_increment",
		.lname	= "IO offset increment",
		.type	= FIO_OPT_STR_VAL,
		.off1	= td_var_offset(offset_increment),
		.help	= "What is the increment from one offset to the next",
		.parent = "offset",
		.hide	= 1,
		.def	= "0",
		.interval = 1024 * 1024,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "number_ios",
		.lname	= "Number of IOs to perform",
		.type	= FIO_OPT_STR_VAL,
		.off1	= td_var_offset(number_ios),
		.help	= "Force job completion of this number of IOs",
		.def	= "0",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "bs",
		.lname	= "Block size",
		.alias	= "blocksize",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(bs[DDIR_READ]),
		.off2	= td_var_offset(bs[DDIR_WRITE]),
		.off3	= td_var_offset(bs[DDIR_TRIM]),
		.minval = 1,
		.help	= "Block size unit",
		.def	= "4k",
		.parent = "rw",
		.hide	= 1,
		.interval = 512,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "ba",
		.lname	= "Block size align",
		.alias	= "blockalign",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(ba[DDIR_READ]),
		.off2	= td_var_offset(ba[DDIR_WRITE]),
		.off3	= td_var_offset(ba[DDIR_TRIM]),
		.minval	= 1,
		.help	= "IO block offset alignment",
		.parent	= "rw",
		.hide	= 1,
		.interval = 512,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "bsrange",
		.lname	= "Block size range",
		.alias	= "blocksize_range",
		.type	= FIO_OPT_RANGE,
		.off1	= td_var_offset(min_bs[DDIR_READ]),
		.off2	= td_var_offset(max_bs[DDIR_READ]),
		.off3	= td_var_offset(min_bs[DDIR_WRITE]),
		.off4	= td_var_offset(max_bs[DDIR_WRITE]),
		.off5	= td_var_offset(min_bs[DDIR_TRIM]),
		.off6	= td_var_offset(max_bs[DDIR_TRIM]),
		.minval = 1,
		.help	= "Set block size range (in more detail than bs)",
		.parent = "rw",
		.hide	= 1,
		.interval = 4096,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "bssplit",
		.lname	= "Block size split",
		.type	= FIO_OPT_STR,
		.cb	= str_bssplit_cb,
		.help	= "Set a specific mix of block sizes",
		.parent	= "rw",
		.hide	= 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "bs_unaligned",
		.lname	= "Block size unaligned",
		.alias	= "blocksize_unaligned",
		.type	= FIO_OPT_STR_SET,
		.off1	= td_var_offset(bs_unaligned),
		.help	= "Don't sector align IO buffer sizes",
		.parent = "rw",
		.hide	= 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "bs_is_seq_rand",
		.lname	= "Block size division is seq/random (not read/write)",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(bs_is_seq_rand),
		.help	= "Consider any blocksize setting to be sequential,ramdom",
		.def	= "0",
		.parent = "blocksize",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "randrepeat",
		.lname	= "Random repeatable",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(rand_repeatable),
		.help	= "Use repeatable random IO pattern",
		.def	= "1",
		.parent = "rw",
		.hide	= 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_RANDOM,
	},
	{
		.name	= "randseed",
		.lname	= "The random generator seed",
		.type	= FIO_OPT_STR_VAL,
		.off1	= td_var_offset(rand_seed),
		.help	= "Set the random generator seed value",
		.parent = "rw",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_RANDOM,
	},
	{
		.name	= "use_os_rand",
		.lname	= "Use OS random",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(use_os_rand),
		.help	= "Set to use OS random generator",
		.def	= "0",
		.parent = "rw",
		.hide	= 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_RANDOM,
	},
	{
		.name	= "norandommap",
		.lname	= "No randommap",
		.type	= FIO_OPT_STR_SET,
		.off1	= td_var_offset(norandommap),
		.help	= "Accept potential duplicate random blocks",
		.parent = "rw",
		.hide	= 1,
		.hide_on_set = 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_RANDOM,
	},
	{
		.name	= "softrandommap",
		.lname	= "Soft randommap",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(softrandommap),
		.help	= "Set norandommap if randommap allocation fails",
		.parent	= "norandommap",
		.hide	= 1,
		.def	= "0",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_RANDOM,
	},
	{
		.name	= "random_generator",
		.type	= FIO_OPT_STR,
		.off1	= td_var_offset(random_generator),
		.help	= "Type of random number generator to use",
		.def	= "tausworthe",
		.posval	= {
			  { .ival = "tausworthe",
			    .oval = FIO_RAND_GEN_TAUSWORTHE,
			    .help = "Strong Tausworthe generator",
			  },
			  { .ival = "lfsr",
			    .oval = FIO_RAND_GEN_LFSR,
			    .help = "Variable length LFSR",
			  },
		},
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_RANDOM,
	},
	{
		.name	= "random_distribution",
		.type	= FIO_OPT_STR,
		.off1	= td_var_offset(random_distribution),
		.cb	= str_random_distribution_cb,
		.help	= "Random offset distribution generator",
		.def	= "random",
		.posval	= {
			  { .ival = "random",
			    .oval = FIO_RAND_DIST_RANDOM,
			    .help = "Completely random",
			  },
			  { .ival = "zipf",
			    .oval = FIO_RAND_DIST_ZIPF,
			    .help = "Zipf distribution",
			  },
			  { .ival = "pareto",
			    .oval = FIO_RAND_DIST_PARETO,
			    .help = "Pareto distribution",
			  },
		},
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_RANDOM,
	},
	{
		.name	= "percentage_random",
		.lname	= "Percentage Random",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(perc_rand[DDIR_READ]),
		.off2	= td_var_offset(perc_rand[DDIR_WRITE]),
		.off3	= td_var_offset(perc_rand[DDIR_TRIM]),
		.maxval	= 100,
		.help	= "Percentage of seq/random mix that should be random",
		.def	= "100,100,100",
		.interval = 5,
		.inverse = "percentage_sequential",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_RANDOM,
	},
	{
		.name	= "percentage_sequential",
		.lname	= "Percentage Sequential",
		.type	= FIO_OPT_DEPRECATED,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_RANDOM,
	},
	{
		.name	= "allrandrepeat",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(allrand_repeatable),
		.help	= "Use repeatable random numbers for everything",
		.def	= "0",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_RANDOM,
	},
	{
		.name	= "nrfiles",
		.lname	= "Number of files",
		.alias	= "nr_files",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(nr_files),
		.help	= "Split job workload between this number of files",
		.def	= "1",
		.interval = 1,
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "openfiles",
		.lname	= "Number of open files",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(open_files),
		.help	= "Number of files to keep open at the same time",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "file_service_type",
		.lname	= "File service type",
		.type	= FIO_OPT_STR,
		.cb	= str_fst_cb,
		.off1	= td_var_offset(file_service_type),
		.help	= "How to select which file to service next",
		.def	= "roundrobin",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
		.posval	= {
			  { .ival = "random",
			    .oval = FIO_FSERVICE_RANDOM,
			    .help = "Choose a file at random",
			  },
			  { .ival = "roundrobin",
			    .oval = FIO_FSERVICE_RR,
			    .help = "Round robin select files",
			  },
			  { .ival = "sequential",
			    .oval = FIO_FSERVICE_SEQ,
			    .help = "Finish one file before moving to the next",
			  },
		},
		.parent = "nrfiles",
		.hide	= 1,
	},
#ifdef CONFIG_POSIX_FALLOCATE
	{
		.name	= "fallocate",
		.lname	= "Fallocate",
		.type	= FIO_OPT_STR,
		.off1	= td_var_offset(fallocate_mode),
		.help	= "Whether pre-allocation is performed when laying out files",
		.def	= "posix",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
		.posval	= {
			  { .ival = "none",
			    .oval = FIO_FALLOCATE_NONE,
			    .help = "Do not pre-allocate space",
			  },
			  { .ival = "posix",
			    .oval = FIO_FALLOCATE_POSIX,
			    .help = "Use posix_fallocate()",
			  },
#ifdef CONFIG_LINUX_FALLOCATE
			  { .ival = "keep",
			    .oval = FIO_FALLOCATE_KEEP_SIZE,
			    .help = "Use fallocate(..., FALLOC_FL_KEEP_SIZE, ...)",
			  },
#endif
			  /* Compatibility with former boolean values */
			  { .ival = "0",
			    .oval = FIO_FALLOCATE_NONE,
			    .help = "Alias for 'none'",
			  },
			  { .ival = "1",
			    .oval = FIO_FALLOCATE_POSIX,
			    .help = "Alias for 'posix'",
			  },
		},
	},
#endif	/* CONFIG_POSIX_FALLOCATE */
	{
		.name	= "fadvise_hint",
		.lname	= "Fadvise hint",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(fadvise_hint),
		.help	= "Use fadvise() to advise the kernel on IO pattern",
		.def	= "1",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "fsync",
		.lname	= "Fsync",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(fsync_blocks),
		.help	= "Issue fsync for writes every given number of blocks",
		.def	= "0",
		.interval = 1,
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "fdatasync",
		.lname	= "Fdatasync",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(fdatasync_blocks),
		.help	= "Issue fdatasync for writes every given number of blocks",
		.def	= "0",
		.interval = 1,
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "write_barrier",
		.lname	= "Write barrier",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(barrier_blocks),
		.help	= "Make every Nth write a barrier write",
		.def	= "0",
		.interval = 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_INVALID,
	},
#ifdef CONFIG_SYNC_FILE_RANGE
	{
		.name	= "sync_file_range",
		.lname	= "Sync file range",
		.posval	= {
			  { .ival = "wait_before",
			    .oval = SYNC_FILE_RANGE_WAIT_BEFORE,
			    .help = "SYNC_FILE_RANGE_WAIT_BEFORE",
			    .orval  = 1,
			  },
			  { .ival = "write",
			    .oval = SYNC_FILE_RANGE_WRITE,
			    .help = "SYNC_FILE_RANGE_WRITE",
			    .orval  = 1,
			  },
			  {
			    .ival = "wait_after",
			    .oval = SYNC_FILE_RANGE_WAIT_AFTER,
			    .help = "SYNC_FILE_RANGE_WAIT_AFTER",
			    .orval  = 1,
			  },
		},
		.type	= FIO_OPT_STR_MULTI,
		.cb	= str_sfr_cb,
		.off1	= td_var_offset(sync_file_range),
		.help	= "Use sync_file_range()",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
	},
#endif
	{
		.name	= "direct",
		.lname	= "Direct I/O",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(odirect),
		.help	= "Use O_DIRECT IO (negates buffered)",
		.def	= "0",
		.inverse = "buffered",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_TYPE,
	},
	{
		.name	= "atomic",
		.lname	= "Atomic I/O",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(oatomic),
		.help	= "Use Atomic IO with O_DIRECT (implies O_DIRECT)",
		.def	= "0",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_TYPE,
	},
	{
		.name	= "buffered",
		.lname	= "Buffered I/O",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(odirect),
		.neg	= 1,
		.help	= "Use buffered IO (negates direct)",
		.def	= "1",
		.inverse = "direct",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_TYPE,
	},
	{
		.name	= "overwrite",
		.lname	= "Overwrite",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(overwrite),
		.help	= "When writing, set whether to overwrite current data",
		.def	= "0",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "loops",
		.lname	= "Loops",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(loops),
		.help	= "Number of times to run the job",
		.def	= "1",
		.interval = 1,
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_RUNTIME,
	},
	{
		.name	= "numjobs",
		.lname	= "Number of jobs",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(numjobs),
		.help	= "Duplicate this job this many times",
		.def	= "1",
		.interval = 1,
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_RUNTIME,
	},
	{
		.name	= "startdelay",
		.lname	= "Start delay",
		.type	= FIO_OPT_STR_VAL_TIME,
		.off1	= td_var_offset(start_delay),
		.off2	= td_var_offset(start_delay_high),
		.help	= "Only start job when this period has passed",
		.def	= "0",
		.is_seconds = 1,
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_RUNTIME,
	},
	{
		.name	= "runtime",
		.lname	= "Runtime",
		.alias	= "timeout",
		.type	= FIO_OPT_STR_VAL_TIME,
		.off1	= td_var_offset(timeout),
		.help	= "Stop workload when this amount of time has passed",
		.def	= "0",
		.is_seconds = 1,
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_RUNTIME,
	},
	{
		.name	= "time_based",
		.lname	= "Time based",
		.type	= FIO_OPT_STR_SET,
		.off1	= td_var_offset(time_based),
		.help	= "Keep running until runtime/timeout is met",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_RUNTIME,
	},
	{
		.name	= "verify_only",
		.lname	= "Verify only",
		.type	= FIO_OPT_STR_SET,
		.off1	= td_var_offset(verify_only),
		.help	= "Verifies previously written data is still valid",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_RUNTIME,
	},
	{
		.name	= "ramp_time",
		.lname	= "Ramp time",
		.type	= FIO_OPT_STR_VAL_TIME,
		.off1	= td_var_offset(ramp_time),
		.help	= "Ramp up time before measuring performance",
		.is_seconds = 1,
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_RUNTIME,
	},
	{
		.name	= "clocksource",
		.lname	= "Clock source",
		.type	= FIO_OPT_STR,
		.cb	= fio_clock_source_cb,
		.off1	= td_var_offset(clocksource),
		.help	= "What type of timing source to use",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_CLOCK,
		.posval	= {
#ifdef CONFIG_GETTIMEOFDAY
			  { .ival = "gettimeofday",
			    .oval = CS_GTOD,
			    .help = "Use gettimeofday(2) for timing",
			  },
#endif
#ifdef CONFIG_CLOCK_GETTIME
			  { .ival = "clock_gettime",
			    .oval = CS_CGETTIME,
			    .help = "Use clock_gettime(2) for timing",
			  },
#endif
#ifdef ARCH_HAVE_CPU_CLOCK
			  { .ival = "cpu",
			    .oval = CS_CPUCLOCK,
			    .help = "Use CPU private clock",
			  },
#endif
		},
	},
	{
		.name	= "mem",
		.alias	= "iomem",
		.lname	= "I/O Memory",
		.type	= FIO_OPT_STR,
		.cb	= str_mem_cb,
		.off1	= td_var_offset(mem_type),
		.help	= "Backing type for IO buffers",
		.def	= "malloc",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_INVALID,
		.posval	= {
			  { .ival = "malloc",
			    .oval = MEM_MALLOC,
			    .help = "Use malloc(3) for IO buffers",
			  },
			  { .ival = "shm",
			    .oval = MEM_SHM,
			    .help = "Use shared memory segments for IO buffers",
			  },
#ifdef FIO_HAVE_HUGETLB
			  { .ival = "shmhuge",
			    .oval = MEM_SHMHUGE,
			    .help = "Like shm, but use huge pages",
			  },
#endif
			  { .ival = "mmap",
			    .oval = MEM_MMAP,
			    .help = "Use mmap(2) (file or anon) for IO buffers",
			  },
#ifdef FIO_HAVE_HUGETLB
			  { .ival = "mmaphuge",
			    .oval = MEM_MMAPHUGE,
			    .help = "Like mmap, but use huge pages",
			  },
#endif
		  },
	},
	{
		.name	= "iomem_align",
		.alias	= "mem_align",
		.lname	= "I/O memory alignment",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(mem_align),
		.minval	= 0,
		.help	= "IO memory buffer offset alignment",
		.def	= "0",
		.parent	= "iomem",
		.hide	= 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "verify",
		.lname	= "Verify",
		.type	= FIO_OPT_STR,
		.off1	= td_var_offset(verify),
		.help	= "Verify data written",
		.def	= "0",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_VERIFY,
		.posval = {
			  { .ival = "0",
			    .oval = VERIFY_NONE,
			    .help = "Don't do IO verification",
			  },
			  { .ival = "md5",
			    .oval = VERIFY_MD5,
			    .help = "Use md5 checksums for verification",
			  },
			  { .ival = "crc64",
			    .oval = VERIFY_CRC64,
			    .help = "Use crc64 checksums for verification",
			  },
			  { .ival = "crc32",
			    .oval = VERIFY_CRC32,
			    .help = "Use crc32 checksums for verification",
			  },
			  { .ival = "crc32c-intel",
			    .oval = VERIFY_CRC32C,
			    .help = "Use crc32c checksums for verification (hw assisted, if available)",
			  },
			  { .ival = "crc32c",
			    .oval = VERIFY_CRC32C,
			    .help = "Use crc32c checksums for verification (hw assisted, if available)",
			  },
			  { .ival = "crc16",
			    .oval = VERIFY_CRC16,
			    .help = "Use crc16 checksums for verification",
			  },
			  { .ival = "crc7",
			    .oval = VERIFY_CRC7,
			    .help = "Use crc7 checksums for verification",
			  },
			  { .ival = "sha1",
			    .oval = VERIFY_SHA1,
			    .help = "Use sha1 checksums for verification",
			  },
			  { .ival = "sha256",
			    .oval = VERIFY_SHA256,
			    .help = "Use sha256 checksums for verification",
			  },
			  { .ival = "sha512",
			    .oval = VERIFY_SHA512,
			    .help = "Use sha512 checksums for verification",
			  },
			  { .ival = "xxhash",
			    .oval = VERIFY_XXHASH,
			    .help = "Use xxhash checksums for verification",
			  },
			  { .ival = "meta",
			    .oval = VERIFY_META,
			    .help = "Use io information",
			  },
			  {
			    .ival = "null",
			    .oval = VERIFY_NULL,
			    .help = "Pretend to verify",
			  },
		},
	},
	{
		.name	= "do_verify",
		.lname	= "Perform verify step",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(do_verify),
		.help	= "Run verification stage after write",
		.def	= "1",
		.parent = "verify",
		.hide	= 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_VERIFY,
	},
	{
		.name	= "verifysort",
		.lname	= "Verify sort",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(verifysort),
		.help	= "Sort written verify blocks for read back",
		.def	= "1",
		.parent = "verify",
		.hide	= 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_VERIFY,
	},
	{
		.name	= "verifysort_nr",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(verifysort_nr),
		.help	= "Pre-load and sort verify blocks for a read workload",
		.minval	= 0,
		.maxval	= 131072,
		.def	= "1024",
		.parent = "verify",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_VERIFY,
	},
	{
		.name   = "verify_interval",
		.lname	= "Verify interval",
		.type   = FIO_OPT_INT,
		.off1   = td_var_offset(verify_interval),
		.minval	= 2 * sizeof(struct verify_header),
		.help   = "Store verify buffer header every N bytes",
		.parent	= "verify",
		.hide	= 1,
		.interval = 2 * sizeof(struct verify_header),
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_VERIFY,
	},
	{
		.name	= "verify_offset",
		.lname	= "Verify offset",
		.type	= FIO_OPT_INT,
		.help	= "Offset verify header location by N bytes",
		.off1	= td_var_offset(verify_offset),
		.minval	= sizeof(struct verify_header),
		.parent	= "verify",
		.hide	= 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_VERIFY,
	},
	{
		.name	= "verify_pattern",
		.lname	= "Verify pattern",
		.type	= FIO_OPT_STR,
		.cb	= str_verify_pattern_cb,
		.help	= "Fill pattern for IO buffers",
		.parent	= "verify",
		.hide	= 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_VERIFY,
	},
	{
		.name	= "verify_fatal",
		.lname	= "Verify fatal",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(verify_fatal),
		.def	= "0",
		.help	= "Exit on a single verify failure, don't continue",
		.parent = "verify",
		.hide	= 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_VERIFY,
	},
	{
		.name	= "verify_dump",
		.lname	= "Verify dump",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(verify_dump),
		.def	= "0",
		.help	= "Dump contents of good and bad blocks on failure",
		.parent = "verify",
		.hide	= 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_VERIFY,
	},
	{
		.name	= "verify_async",
		.lname	= "Verify asynchronously",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(verify_async),
		.def	= "0",
		.help	= "Number of async verifier threads to use",
		.parent	= "verify",
		.hide	= 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_VERIFY,
	},
	{
		.name	= "verify_backlog",
		.lname	= "Verify backlog",
		.type	= FIO_OPT_STR_VAL,
		.off1	= td_var_offset(verify_backlog),
		.help	= "Verify after this number of blocks are written",
		.parent	= "verify",
		.hide	= 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_VERIFY,
	},
	{
		.name	= "verify_backlog_batch",
		.lname	= "Verify backlog batch",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(verify_batch),
		.help	= "Verify this number of IO blocks",
		.parent	= "verify",
		.hide	= 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_VERIFY,
	},
#ifdef FIO_HAVE_CPU_AFFINITY
	{
		.name	= "verify_async_cpus",
		.lname	= "Async verify CPUs",
		.type	= FIO_OPT_STR,
		.cb	= str_verify_cpus_allowed_cb,
		.help	= "Set CPUs allowed for async verify threads",
		.parent	= "verify_async",
		.hide	= 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_VERIFY,
	},
#endif
	{
		.name	= "experimental_verify",
		.off1	= td_var_offset(experimental_verify),
		.type	= FIO_OPT_BOOL,
		.help	= "Enable experimental verification",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_VERIFY,
	},
#ifdef FIO_HAVE_TRIM
	{
		.name	= "trim_percentage",
		.lname	= "Trim percentage",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(trim_percentage),
		.minval = 0,
		.maxval = 100,
		.help	= "Number of verify blocks to discard/trim",
		.parent	= "verify",
		.def	= "0",
		.interval = 1,
		.hide	= 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_TRIM,
	},
	{
		.name	= "trim_verify_zero",
		.lname	= "Verify trim zero",
		.type	= FIO_OPT_BOOL,
		.help	= "Verify that trim/discarded blocks are returned as zeroes",
		.off1	= td_var_offset(trim_zero),
		.parent	= "trim_percentage",
		.hide	= 1,
		.def	= "1",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_TRIM,
	},
	{
		.name	= "trim_backlog",
		.lname	= "Trim backlog",
		.type	= FIO_OPT_STR_VAL,
		.off1	= td_var_offset(trim_backlog),
		.help	= "Trim after this number of blocks are written",
		.parent	= "trim_percentage",
		.hide	= 1,
		.interval = 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_TRIM,
	},
	{
		.name	= "trim_backlog_batch",
		.lname	= "Trim backlog batch",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(trim_batch),
		.help	= "Trim this number of IO blocks",
		.parent	= "trim_percentage",
		.hide	= 1,
		.interval = 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_TRIM,
	},
#endif
	{
		.name	= "write_iolog",
		.lname	= "Write I/O log",
		.type	= FIO_OPT_STR_STORE,
		.off1	= td_var_offset(write_iolog_file),
		.help	= "Store IO pattern to file",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IOLOG,
	},
	{
		.name	= "read_iolog",
		.lname	= "Read I/O log",
		.type	= FIO_OPT_STR_STORE,
		.off1	= td_var_offset(read_iolog_file),
		.help	= "Playback IO pattern from file",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IOLOG,
	},
	{
		.name	= "replay_no_stall",
		.lname	= "Don't stall on replay",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(no_stall),
		.def	= "0",
		.parent	= "read_iolog",
		.hide	= 1,
		.help	= "Playback IO pattern file as fast as possible without stalls",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IOLOG,
	},
	{
		.name	= "replay_redirect",
		.lname	= "Redirect device for replay",
		.type	= FIO_OPT_STR_STORE,
		.off1	= td_var_offset(replay_redirect),
		.parent	= "read_iolog",
		.hide	= 1,
		.help	= "Replay all I/O onto this device, regardless of trace device",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IOLOG,
	},
	{
		.name	= "exec_prerun",
		.lname	= "Pre-execute runnable",
		.type	= FIO_OPT_STR_STORE,
		.off1	= td_var_offset(exec_prerun),
		.help	= "Execute this file prior to running job",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "exec_postrun",
		.lname	= "Post-execute runnable",
		.type	= FIO_OPT_STR_STORE,
		.off1	= td_var_offset(exec_postrun),
		.help	= "Execute this file after running job",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_INVALID,
	},
#ifdef FIO_HAVE_IOSCHED_SWITCH
	{
		.name	= "ioscheduler",
		.lname	= "I/O scheduler",
		.type	= FIO_OPT_STR_STORE,
		.off1	= td_var_offset(ioscheduler),
		.help	= "Use this IO scheduler on the backing device",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
	},
#endif
	{
		.name	= "zonesize",
		.lname	= "Zone size",
		.type	= FIO_OPT_STR_VAL,
		.off1	= td_var_offset(zone_size),
		.help	= "Amount of data to read per zone",
		.def	= "0",
		.interval = 1024 * 1024,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_ZONE,
	},
	{
		.name	= "zonerange",
		.lname	= "Zone range",
		.type	= FIO_OPT_STR_VAL,
		.off1	= td_var_offset(zone_range),
		.help	= "Give size of an IO zone",
		.def	= "0",
		.interval = 1024 * 1024,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_ZONE,
	},
	{
		.name	= "zoneskip",
		.lname	= "Zone skip",
		.type	= FIO_OPT_STR_VAL,
		.off1	= td_var_offset(zone_skip),
		.help	= "Space between IO zones",
		.def	= "0",
		.interval = 1024 * 1024,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_ZONE,
	},
	{
		.name	= "lockmem",
		.lname	= "Lock memory",
		.type	= FIO_OPT_STR_VAL,
		.off1	= td_var_offset(lockmem),
		.help	= "Lock down this amount of memory (per worker)",
		.def	= "0",
		.interval = 1024 * 1024,
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "rwmixread",
		.lname	= "Read/write mix read",
		.type	= FIO_OPT_INT,
		.cb	= str_rwmix_read_cb,
		.maxval	= 100,
		.help	= "Percentage of mixed workload that is reads",
		.def	= "50",
		.interval = 5,
		.inverse = "rwmixwrite",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_RWMIX,
	},
	{
		.name	= "rwmixwrite",
		.lname	= "Read/write mix write",
		.type	= FIO_OPT_INT,
		.cb	= str_rwmix_write_cb,
		.maxval	= 100,
		.help	= "Percentage of mixed workload that is writes",
		.def	= "50",
		.interval = 5,
		.inverse = "rwmixread",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_RWMIX,
	},
	{
		.name	= "rwmixcycle",
		.lname	= "Read/write mix cycle",
		.type	= FIO_OPT_DEPRECATED,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_RWMIX,
	},
	{
		.name	= "nice",
		.lname	= "Nice",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(nice),
		.help	= "Set job CPU nice value",
		.minval	= -19,
		.maxval	= 20,
		.def	= "0",
		.interval = 1,
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_CRED,
	},
#ifdef FIO_HAVE_IOPRIO
	{
		.name	= "prio",
		.lname	= "I/O nice priority",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(ioprio),
		.help	= "Set job IO priority value",
		.minval	= 0,
		.maxval	= 7,
		.interval = 1,
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_CRED,
	},
	{
		.name	= "prioclass",
		.lname	= "I/O nice priority class",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(ioprio_class),
		.help	= "Set job IO priority class",
		.minval	= 0,
		.maxval	= 3,
		.interval = 1,
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_CRED,
	},
#endif
	{
		.name	= "thinktime",
		.lname	= "Thinktime",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(thinktime),
		.help	= "Idle time between IO buffers (usec)",
		.def	= "0",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_THINKTIME,
	},
	{
		.name	= "thinktime_spin",
		.lname	= "Thinktime spin",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(thinktime_spin),
		.help	= "Start think time by spinning this amount (usec)",
		.def	= "0",
		.parent	= "thinktime",
		.hide	= 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_THINKTIME,
	},
	{
		.name	= "thinktime_blocks",
		.lname	= "Thinktime blocks",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(thinktime_blocks),
		.help	= "IO buffer period between 'thinktime'",
		.def	= "1",
		.parent	= "thinktime",
		.hide	= 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_THINKTIME,
	},
	{
		.name	= "rate",
		.lname	= "I/O rate",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(rate[DDIR_READ]),
		.off2	= td_var_offset(rate[DDIR_WRITE]),
		.off3	= td_var_offset(rate[DDIR_TRIM]),
		.help	= "Set bandwidth rate",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_RATE,
	},
	{
		.name	= "ratemin",
		.lname	= "I/O min rate",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(ratemin[DDIR_READ]),
		.off2	= td_var_offset(ratemin[DDIR_WRITE]),
		.off3	= td_var_offset(ratemin[DDIR_TRIM]),
		.help	= "Job must meet this rate or it will be shutdown",
		.parent	= "rate",
		.hide	= 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_RATE,
	},
	{
		.name	= "rate_iops",
		.lname	= "I/O rate IOPS",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(rate_iops[DDIR_READ]),
		.off2	= td_var_offset(rate_iops[DDIR_WRITE]),
		.off3	= td_var_offset(rate_iops[DDIR_TRIM]),
		.help	= "Limit IO used to this number of IO operations/sec",
		.hide	= 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_RATE,
	},
	{
		.name	= "rate_iops_min",
		.lname	= "I/O min rate IOPS",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(rate_iops_min[DDIR_READ]),
		.off2	= td_var_offset(rate_iops_min[DDIR_WRITE]),
		.off3	= td_var_offset(rate_iops_min[DDIR_TRIM]),
		.help	= "Job must meet this rate or it will be shut down",
		.parent	= "rate_iops",
		.hide	= 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_RATE,
	},
	{
		.name	= "ratecycle",
		.lname	= "I/O rate cycle",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(ratecycle),
		.help	= "Window average for rate limits (msec)",
		.def	= "1000",
		.parent = "rate",
		.hide	= 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_RATE,
	},
	{
		.name	= "max_latency",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(max_latency),
		.help	= "Maximum tolerated IO latency (usec)",
		.category = FIO_OPT_C_IO,
		.group = FIO_OPT_G_LATPROF,
	},
	{
		.name	= "latency_target",
		.lname	= "Latency Target (usec)",
		.type	= FIO_OPT_STR_VAL_TIME,
		.off1	= td_var_offset(latency_target),
		.help	= "Ramp to max queue depth supporting this latency",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_LATPROF,
	},
	{
		.name	= "latency_window",
		.lname	= "Latency Window (usec)",
		.type	= FIO_OPT_STR_VAL_TIME,
		.off1	= td_var_offset(latency_window),
		.help	= "Time to sustain latency_target",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_LATPROF,
	},
	{
		.name	= "latency_percentile",
		.lname	= "Latency Percentile",
		.type	= FIO_OPT_FLOAT_LIST,
		.off1	= td_var_offset(latency_percentile),
		.help	= "Percentile of IOs must be below latency_target",
		.def	= "100",
		.maxlen	= 1,
		.minfp	= 0.0,
		.maxfp	= 100.0,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_LATPROF,
	},
	{
		.name	= "invalidate",
		.lname	= "Cache invalidate",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(invalidate_cache),
		.help	= "Invalidate buffer/page cache prior to running job",
		.def	= "1",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_TYPE,
	},
	{
		.name	= "sync",
		.lname	= "Synchronous I/O",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(sync_io),
		.help	= "Use O_SYNC for buffered writes",
		.def	= "0",
		.parent = "buffered",
		.hide	= 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_TYPE,
	},
	{
		.name	= "create_serialize",
		.lname	= "Create serialize",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(create_serialize),
		.help	= "Serialize creating of job files",
		.def	= "1",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "create_fsync",
		.lname	= "Create fsync",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(create_fsync),
		.help	= "fsync file after creation",
		.def	= "1",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "create_on_open",
		.lname	= "Create on open",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(create_on_open),
		.help	= "Create files when they are opened for IO",
		.def	= "0",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "create_only",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(create_only),
		.help	= "Only perform file creation phase",
		.category = FIO_OPT_C_FILE,
		.def	= "0",
	},
	{
		.name	= "pre_read",
		.lname	= "Pre-read files",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(pre_read),
		.help	= "Pre-read files before starting official testing",
		.def	= "0",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
	},
#ifdef FIO_HAVE_CPU_AFFINITY
	{
		.name	= "cpumask",
		.lname	= "CPU mask",
		.type	= FIO_OPT_INT,
		.cb	= str_cpumask_cb,
		.help	= "CPU affinity mask",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_CRED,
	},
	{
		.name	= "cpus_allowed",
		.lname	= "CPUs allowed",
		.type	= FIO_OPT_STR,
		.cb	= str_cpus_allowed_cb,
		.help	= "Set CPUs allowed",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_CRED,
	},
	{
		.name	= "cpus_allowed_policy",
		.lname	= "CPUs allowed distribution policy",
		.type	= FIO_OPT_STR,
		.off1	= td_var_offset(cpus_allowed_policy),
		.help	= "Distribution policy for cpus_allowed",
		.parent = "cpus_allowed",
		.prio	= 1,
		.posval = {
			  { .ival = "shared",
			    .oval = FIO_CPUS_SHARED,
			    .help = "Mask shared between threads",
			  },
			  { .ival = "split",
			    .oval = FIO_CPUS_SPLIT,
			    .help = "Mask split between threads",
			  },
		},
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_CRED,
	},
#endif
#ifdef CONFIG_LIBNUMA
	{
		.name	= "numa_cpu_nodes",
		.type	= FIO_OPT_STR,
		.cb	= str_numa_cpunodes_cb,
		.help	= "NUMA CPU nodes bind",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "numa_mem_policy",
		.type	= FIO_OPT_STR,
		.cb	= str_numa_mpol_cb,
		.help	= "NUMA memory policy setup",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_INVALID,
	},
#endif
	{
		.name	= "end_fsync",
		.lname	= "End fsync",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(end_fsync),
		.help	= "Include fsync at the end of job",
		.def	= "0",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "fsync_on_close",
		.lname	= "Fsync on close",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(fsync_on_close),
		.help	= "fsync files on close",
		.def	= "0",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "unlink",
		.lname	= "Unlink file",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(unlink),
		.help	= "Unlink created files after job has completed",
		.def	= "0",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "exitall",
		.lname	= "Exit-all on terminate",
		.type	= FIO_OPT_STR_SET,
		.cb	= str_exitall_cb,
		.help	= "Terminate all jobs when one exits",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_PROCESS,
	},
	{
		.name	= "stonewall",
		.lname	= "Wait for previous",
		.alias	= "wait_for_previous",
		.type	= FIO_OPT_STR_SET,
		.off1	= td_var_offset(stonewall),
		.help	= "Insert a hard barrier between this job and previous",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_PROCESS,
	},
	{
		.name	= "new_group",
		.lname	= "New group",
		.type	= FIO_OPT_STR_SET,
		.off1	= td_var_offset(new_group),
		.help	= "Mark the start of a new group (for reporting)",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_PROCESS,
	},
	{
		.name	= "thread",
		.lname	= "Thread",
		.type	= FIO_OPT_STR_SET,
		.off1	= td_var_offset(use_thread),
		.help	= "Use threads instead of processes",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_PROCESS,
	},
	{
		.name	= "write_bw_log",
		.lname	= "Write bandwidth log",
		.type	= FIO_OPT_STR_STORE,
		.off1	= td_var_offset(bw_log_file),
		.help	= "Write log of bandwidth during run",
		.category = FIO_OPT_C_LOG,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "write_lat_log",
		.lname	= "Write latency log",
		.type	= FIO_OPT_STR_STORE,
		.off1	= td_var_offset(lat_log_file),
		.help	= "Write log of latency during run",
		.category = FIO_OPT_C_LOG,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "write_iops_log",
		.lname	= "Write IOPS log",
		.type	= FIO_OPT_STR_STORE,
		.off1	= td_var_offset(iops_log_file),
		.help	= "Write log of IOPS during run",
		.category = FIO_OPT_C_LOG,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "log_avg_msec",
		.lname	= "Log averaging (msec)",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(log_avg_msec),
		.help	= "Average bw/iops/lat logs over this period of time",
		.def	= "0",
		.category = FIO_OPT_C_LOG,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "bwavgtime",
		.lname	= "Bandwidth average time",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(bw_avg_time),
		.help	= "Time window over which to calculate bandwidth"
			  " (msec)",
		.def	= "500",
		.parent	= "write_bw_log",
		.hide	= 1,
		.interval = 100,
		.category = FIO_OPT_C_LOG,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "iopsavgtime",
		.lname	= "IOPS average time",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(iops_avg_time),
		.help	= "Time window over which to calculate IOPS (msec)",
		.def	= "500",
		.parent	= "write_iops_log",
		.hide	= 1,
		.interval = 100,
		.category = FIO_OPT_C_LOG,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "group_reporting",
		.lname	= "Group reporting",
		.type	= FIO_OPT_STR_SET,
		.off1	= td_var_offset(group_reporting),
		.help	= "Do reporting on a per-group basis",
		.category = FIO_OPT_C_STAT,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "zero_buffers",
		.lname	= "Zero I/O buffers",
		.type	= FIO_OPT_STR_SET,
		.off1	= td_var_offset(zero_buffers),
		.help	= "Init IO buffers to all zeroes",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_BUF,
	},
	{
		.name	= "refill_buffers",
		.lname	= "Refill I/O buffers",
		.type	= FIO_OPT_STR_SET,
		.off1	= td_var_offset(refill_buffers),
		.help	= "Refill IO buffers on every IO submit",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_BUF,
	},
	{
		.name	= "scramble_buffers",
		.lname	= "Scramble I/O buffers",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(scramble_buffers),
		.help	= "Slightly scramble buffers on every IO submit",
		.def	= "1",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_BUF,
	},
	{
		.name	= "buffer_pattern",
		.lname	= "Buffer pattern",
		.type	= FIO_OPT_STR,
		.cb	= str_buffer_pattern_cb,
		.help	= "Fill pattern for IO buffers",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_BUF,
	},
	{
		.name	= "buffer_compress_percentage",
		.lname	= "Buffer compression percentage",
		.type	= FIO_OPT_INT,
		.cb	= str_buffer_compress_cb,
		.maxval	= 100,
		.minval	= 0,
		.help	= "How compressible the buffer is (approximately)",
		.interval = 5,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_BUF,
	},
	{
		.name	= "buffer_compress_chunk",
		.lname	= "Buffer compression chunk size",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(compress_chunk),
		.parent	= "buffer_compress_percentage",
		.hide	= 1,
		.help	= "Size of compressible region in buffer",
		.interval = 256,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_BUF,
	},
	{
		.name	= "clat_percentiles",
		.lname	= "Completion latency percentiles",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(clat_percentiles),
		.help	= "Enable the reporting of completion latency percentiles",
		.def	= "1",
		.category = FIO_OPT_C_STAT,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "percentile_list",
		.lname	= "Completion latency percentile list",
		.type	= FIO_OPT_FLOAT_LIST,
		.off1	= td_var_offset(percentile_list),
		.off2	= td_var_offset(percentile_precision),
		.help	= "Specify a custom list of percentiles to report",
		.def    = "1:5:10:20:30:40:50:60:70:80:90:95:99:99.5:99.9:99.95:99.99",
		.maxlen	= FIO_IO_U_LIST_MAX_LEN,
		.minfp	= 0.0,
		.maxfp	= 100.0,
		.category = FIO_OPT_C_STAT,
		.group	= FIO_OPT_G_INVALID,
	},

#ifdef FIO_HAVE_DISK_UTIL
	{
		.name	= "disk_util",
		.lname	= "Disk utilization",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(do_disk_util),
		.help	= "Log disk utilization statistics",
		.def	= "1",
		.category = FIO_OPT_C_STAT,
		.group	= FIO_OPT_G_INVALID,
	},
#endif
	{
		.name	= "gtod_reduce",
		.lname	= "Reduce gettimeofday() calls",
		.type	= FIO_OPT_BOOL,
		.help	= "Greatly reduce number of gettimeofday() calls",
		.cb	= str_gtod_reduce_cb,
		.def	= "0",
		.hide_on_set = 1,
		.category = FIO_OPT_C_STAT,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "disable_lat",
		.lname	= "Disable all latency stats",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(disable_lat),
		.help	= "Disable latency numbers",
		.parent	= "gtod_reduce",
		.hide	= 1,
		.def	= "0",
		.category = FIO_OPT_C_STAT,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "disable_clat",
		.lname	= "Disable completion latency stats",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(disable_clat),
		.help	= "Disable completion latency numbers",
		.parent	= "gtod_reduce",
		.hide	= 1,
		.def	= "0",
		.category = FIO_OPT_C_STAT,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "disable_slat",
		.lname	= "Disable submission latency stats",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(disable_slat),
		.help	= "Disable submission latency numbers",
		.parent	= "gtod_reduce",
		.hide	= 1,
		.def	= "0",
		.category = FIO_OPT_C_STAT,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "disable_bw_measurement",
		.lname	= "Disable bandwidth stats",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(disable_bw),
		.help	= "Disable bandwidth logging",
		.parent	= "gtod_reduce",
		.hide	= 1,
		.def	= "0",
		.category = FIO_OPT_C_STAT,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "gtod_cpu",
		.lname	= "Dedicated gettimeofday() CPU",
		.type	= FIO_OPT_INT,
		.cb	= str_gtod_cpu_cb,
		.help	= "Set up dedicated gettimeofday() thread on this CPU",
		.verify	= gtod_cpu_verify,
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_CLOCK,
	},
	{
		.name	= "unified_rw_reporting",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(unified_rw_rep),
		.help	= "Unify reporting across data direction",
		.def	= "0",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "continue_on_error",
		.lname	= "Continue on error",
		.type	= FIO_OPT_STR,
		.off1	= td_var_offset(continue_on_error),
		.help	= "Continue on non-fatal errors during IO",
		.def	= "none",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_ERR,
		.posval = {
			  { .ival = "none",
			    .oval = ERROR_TYPE_NONE,
			    .help = "Exit when an error is encountered",
			  },
			  { .ival = "read",
			    .oval = ERROR_TYPE_READ,
			    .help = "Continue on read errors only",
			  },
			  { .ival = "write",
			    .oval = ERROR_TYPE_WRITE,
			    .help = "Continue on write errors only",
			  },
			  { .ival = "io",
			    .oval = ERROR_TYPE_READ | ERROR_TYPE_WRITE,
			    .help = "Continue on any IO errors",
			  },
			  { .ival = "verify",
			    .oval = ERROR_TYPE_VERIFY,
			    .help = "Continue on verify errors only",
			  },
			  { .ival = "all",
			    .oval = ERROR_TYPE_ANY,
			    .help = "Continue on all io and verify errors",
			  },
			  { .ival = "0",
			    .oval = ERROR_TYPE_NONE,
			    .help = "Alias for 'none'",
			  },
			  { .ival = "1",
			    .oval = ERROR_TYPE_ANY,
			    .help = "Alias for 'all'",
			  },
		},
	},
	{
		.name	= "ignore_error",
		.type	= FIO_OPT_STR,
		.cb	= str_ignore_error_cb,
		.help	= "Set a specific list of errors to ignore",
		.parent	= "rw",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_ERR,
	},
	{
		.name	= "error_dump",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(error_dump),
		.def	= "0",
		.help	= "Dump info on each error",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_ERR,
	},
	{
		.name	= "profile",
		.lname	= "Profile",
		.type	= FIO_OPT_STR_STORE,
		.off1	= td_var_offset(profile),
		.help	= "Select a specific builtin performance test",
		.category = FIO_OPT_C_PROFILE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "cgroup",
		.lname	= "Cgroup",
		.type	= FIO_OPT_STR_STORE,
		.off1	= td_var_offset(cgroup),
		.help	= "Add job to cgroup of this name",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_CGROUP,
	},
	{
		.name	= "cgroup_nodelete",
		.lname	= "Cgroup no-delete",
		.type	= FIO_OPT_BOOL,
		.off1	= td_var_offset(cgroup_nodelete),
		.help	= "Do not delete cgroups after job completion",
		.def	= "0",
		.parent	= "cgroup",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_CGROUP,
	},
	{
		.name	= "cgroup_weight",
		.lname	= "Cgroup weight",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(cgroup_weight),
		.help	= "Use given weight for cgroup",
		.minval = 100,
		.maxval	= 1000,
		.parent	= "cgroup",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_CGROUP,
	},
	{
		.name	= "uid",
		.lname	= "User ID",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(uid),
		.help	= "Run job with this user ID",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_CRED,
	},
	{
		.name	= "gid",
		.lname	= "Group ID",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(gid),
		.help	= "Run job with this group ID",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_CRED,
	},
	{
		.name	= "kb_base",
		.lname	= "KB Base",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(kb_base),
		.prio	= 1,
		.def	= "1024",
		.posval = {
			  { .ival = "1024",
			    .oval = 1024,
			    .help = "Use 1024 as the K base",
			  },
			  { .ival = "1000",
			    .oval = 1000,
			    .help = "Use 1000 as the K base",
			  },
		},
		.help	= "How many bytes per KB for reporting (1000 or 1024)",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "unit_base",
		.lname	= "Base unit for reporting (Bits or Bytes)",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(unit_base),
		.prio	= 1,
		.posval = {
			  { .ival = "0",
			    .oval = 0,
			    .help = "Auto-detect",
			  },
			  { .ival = "8",
			    .oval = 8,
			    .help = "Normal (byte based)",
			  },
			  { .ival = "1",
			    .oval = 1,
			    .help = "Bit based",
			  },
		},
		.help	= "Bit multiple of result summary data (8 for byte, 1 for bit)",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "hugepage-size",
		.lname	= "Hugepage size",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(hugepage_size),
		.help	= "When using hugepages, specify size of each page",
		.def	= __fio_stringify(FIO_HUGE_PAGE),
		.interval = 1024 * 1024,
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "flow_id",
		.lname	= "I/O flow ID",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(flow_id),
		.help	= "The flow index ID to use",
		.def	= "0",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_FLOW,
	},
	{
		.name	= "flow",
		.lname	= "I/O flow weight",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(flow),
		.help	= "Weight for flow control of this job",
		.parent	= "flow_id",
		.hide	= 1,
		.def	= "0",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_FLOW,
	},
	{
		.name	= "flow_watermark",
		.lname	= "I/O flow watermark",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(flow_watermark),
		.help	= "High watermark for flow control. This option"
			" should be set to the same value for all threads"
			" with non-zero flow.",
		.parent	= "flow_id",
		.hide	= 1,
		.def	= "1024",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_FLOW,
	},
	{
		.name	= "flow_sleep",
		.lname	= "I/O flow sleep",
		.type	= FIO_OPT_INT,
		.off1	= td_var_offset(flow_sleep),
		.help	= "How many microseconds to sleep after being held"
			" back by the flow control mechanism",
		.parent	= "flow_id",
		.hide	= 1,
		.def	= "0",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_FLOW,
	},
	{
		.name = NULL,
	},
};

static void add_to_lopt(struct option *lopt, struct fio_option *o,
			const char *name, int val)
{
	lopt->name = (char *) name;
	lopt->val = val;
	if (o->type == FIO_OPT_STR_SET)
		lopt->has_arg = optional_argument;
	else
		lopt->has_arg = required_argument;
}

static void options_to_lopts(struct fio_option *opts,
			      struct option *long_options,
			      int i, int option_type)
{
	struct fio_option *o = &opts[0];
	while (o->name) {
		add_to_lopt(&long_options[i], o, o->name, option_type);
		if (o->alias) {
			i++;
			add_to_lopt(&long_options[i], o, o->alias, option_type);
		}

		i++;
		o++;
		assert(i < FIO_NR_OPTIONS);
	}
}

void fio_options_set_ioengine_opts(struct option *long_options,
				   struct thread_data *td)
{
	unsigned int i;

	i = 0;
	while (long_options[i].name) {
		if (long_options[i].val == FIO_GETOPT_IOENGINE) {
			memset(&long_options[i], 0, sizeof(*long_options));
			break;
		}
		i++;
	}

	/*
	 * Just clear out the prior ioengine options.
	 */
	if (!td || !td->eo)
		return;

	options_to_lopts(td->io_ops->options, long_options, i,
			 FIO_GETOPT_IOENGINE);
}

void fio_options_dup_and_init(struct option *long_options)
{
	unsigned int i;

	options_init(fio_options);

	i = 0;
	while (long_options[i].name)
		i++;

	options_to_lopts(fio_options, long_options, i, FIO_GETOPT_JOB);
}

struct fio_keyword {
	const char *word;
	const char *desc;
	char *replace;
};

static struct fio_keyword fio_keywords[] = {
	{
		.word	= "$pagesize",
		.desc	= "Page size in the system",
	},
	{
		.word	= "$mb_memory",
		.desc	= "Megabytes of memory online",
	},
	{
		.word	= "$ncpus",
		.desc	= "Number of CPUs online in the system",
	},
	{
		.word	= NULL,
	},
};

void fio_keywords_init(void)
{
	unsigned long long mb_memory;
	char buf[128];
	long l;

	sprintf(buf, "%lu", (unsigned long) page_size);
	fio_keywords[0].replace = strdup(buf);

	mb_memory = os_phys_mem() / (1024 * 1024);
	sprintf(buf, "%llu", mb_memory);
	fio_keywords[1].replace = strdup(buf);

	l = cpus_online();
	sprintf(buf, "%lu", l);
	fio_keywords[2].replace = strdup(buf);
}

#define BC_APP		"bc"

static char *bc_calc(char *str)
{
	char buf[128], *tmp;
	FILE *f;
	int ret;

	/*
	 * No math, just return string
	 */
	if ((!strchr(str, '+') && !strchr(str, '-') && !strchr(str, '*') &&
	     !strchr(str, '/')) || strchr(str, '\''))
		return str;

	/*
	 * Split option from value, we only need to calculate the value
	 */
	tmp = strchr(str, '=');
	if (!tmp)
		return str;

	tmp++;

	/*
	 * Prevent buffer overflows; such a case isn't reasonable anyway
	 */
	if (strlen(str) >= 128 || strlen(tmp) > 100)
		return str;

	sprintf(buf, "which %s > /dev/null", BC_APP);
	if (system(buf)) {
		log_err("fio: bc is needed for performing math\n");
		return NULL;
	}

	sprintf(buf, "echo '%s' | %s", tmp, BC_APP);
	f = popen(buf, "r");
	if (!f)
		return NULL;

	ret = fread(&buf[tmp - str], 1, 128 - (tmp - str), f);
	if (ret <= 0) {
		pclose(f);
		return NULL;
	}

	pclose(f);
	buf[(tmp - str) + ret - 1] = '\0';
	memcpy(buf, str, tmp - str);
	free(str);
	return strdup(buf);
}

/*
 * Return a copy of the input string with substrings of the form ${VARNAME}
 * substituted with the value of the environment variable VARNAME.  The
 * substitution always occurs, even if VARNAME is empty or the corresponding
 * environment variable undefined.
 */
static char *option_dup_subs(const char *opt)
{
	char out[OPT_LEN_MAX+1];
	char in[OPT_LEN_MAX+1];
	char *outptr = out;
	char *inptr = in;
	char *ch1, *ch2, *env;
	ssize_t nchr = OPT_LEN_MAX;
	size_t envlen;

	if (strlen(opt) + 1 > OPT_LEN_MAX) {
		log_err("OPT_LEN_MAX (%d) is too small\n", OPT_LEN_MAX);
		return NULL;
	}

	in[OPT_LEN_MAX] = '\0';
	strncpy(in, opt, OPT_LEN_MAX);

	while (*inptr && nchr > 0) {
		if (inptr[0] == '$' && inptr[1] == '{') {
			ch2 = strchr(inptr, '}');
			if (ch2 && inptr+1 < ch2) {
				ch1 = inptr+2;
				inptr = ch2+1;
				*ch2 = '\0';

				env = getenv(ch1);
				if (env) {
					envlen = strlen(env);
					if (envlen <= nchr) {
						memcpy(outptr, env, envlen);
						outptr += envlen;
						nchr -= envlen;
					}
				}

				continue;
			}
		}

		*outptr++ = *inptr++;
		--nchr;
	}

	*outptr = '\0';
	return strdup(out);
}

/*
 * Look for reserved variable names and replace them with real values
 */
static char *fio_keyword_replace(char *opt)
{
	char *s;
	int i;
	int docalc = 0;

	for (i = 0; fio_keywords[i].word != NULL; i++) {
		struct fio_keyword *kw = &fio_keywords[i];

		while ((s = strstr(opt, kw->word)) != NULL) {
			char *new = malloc(strlen(opt) + 1);
			char *o_org = opt;
			int olen = s - opt;
			int len;

			/*
			 * Copy part of the string before the keyword and
			 * sprintf() the replacement after it.
			 */
			memcpy(new, opt, olen);
			len = sprintf(new + olen, "%s", kw->replace);

			/*
			 * If there's more in the original string, copy that
			 * in too
			 */
			opt += strlen(kw->word) + olen;
			if (strlen(opt))
				memcpy(new + olen + len, opt, opt - o_org - 1);

			/*
			 * replace opt and free the old opt
			 */
			opt = new;
			free(o_org);

			docalc = 1;
		}
	}

	/*
	 * Check for potential math and invoke bc, if possible
	 */
	if (docalc)
		opt = bc_calc(opt);

	return opt;
}

static char **dup_and_sub_options(char **opts, int num_opts)
{
	int i;
	char **opts_copy = malloc(num_opts * sizeof(*opts));
	for (i = 0; i < num_opts; i++) {
		opts_copy[i] = option_dup_subs(opts[i]);
		if (!opts_copy[i])
			continue;
		opts_copy[i] = fio_keyword_replace(opts_copy[i]);
	}
	return opts_copy;
}

int fio_options_parse(struct thread_data *td, char **opts, int num_opts,
			int dump_cmdline)
{
	int i, ret, unknown;
	char **opts_copy;

	sort_options(opts, fio_options, num_opts);
	opts_copy = dup_and_sub_options(opts, num_opts);

	for (ret = 0, i = 0, unknown = 0; i < num_opts; i++) {
		struct fio_option *o;
		int newret = parse_option(opts_copy[i], opts[i], fio_options,
						&o, td, dump_cmdline);

		if (opts_copy[i]) {
			if (newret && !o) {
				unknown++;
				continue;
			}
			free(opts_copy[i]);
			opts_copy[i] = NULL;
		}

		ret |= newret;
	}

	if (unknown) {
		ret |= ioengine_load(td);
		if (td->eo) {
			sort_options(opts_copy, td->io_ops->options, num_opts);
			opts = opts_copy;
		}
		for (i = 0; i < num_opts; i++) {
			struct fio_option *o = NULL;
			int newret = 1;
			if (!opts_copy[i])
				continue;

			if (td->eo)
				newret = parse_option(opts_copy[i], opts[i],
						      td->io_ops->options, &o,
						      td->eo, dump_cmdline);

			ret |= newret;
			if (!o)
				log_err("Bad option <%s>\n", opts[i]);

			free(opts_copy[i]);
			opts_copy[i] = NULL;
		}
	}

	free(opts_copy);
	return ret;
}

int fio_cmd_option_parse(struct thread_data *td, const char *opt, char *val)
{
	return parse_cmd_option(opt, val, fio_options, td);
}

int fio_cmd_ioengine_option_parse(struct thread_data *td, const char *opt,
				char *val)
{
	return parse_cmd_option(opt, val, td->io_ops->options, td->eo);
}

void fio_fill_default_options(struct thread_data *td)
{
	td->o.magic = OPT_MAGIC;
	fill_default_options(td, fio_options);
}

int fio_show_option_help(const char *opt)
{
	return show_cmd_help(fio_options, opt);
}

void options_mem_dupe(void *data, struct fio_option *options)
{
	struct fio_option *o;
	char **ptr;

	for (o = &options[0]; o->name; o++) {
		if (o->type != FIO_OPT_STR_STORE)
			continue;

		ptr = td_var(data, o, o->off1);
		if (*ptr)
			*ptr = strdup(*ptr);
	}
}

/*
 * dupe FIO_OPT_STR_STORE options
 */
void fio_options_mem_dupe(struct thread_data *td)
{
	options_mem_dupe(&td->o, fio_options);

	if (td->eo && td->io_ops) {
		void *oldeo = td->eo;

		td->eo = malloc(td->io_ops->option_struct_size);
		memcpy(td->eo, oldeo, td->io_ops->option_struct_size);
		options_mem_dupe(td->eo, td->io_ops->options);
	}
}

unsigned int fio_get_kb_base(void *data)
{
	struct thread_options *o = data;
	unsigned int kb_base = 0;

	/*
	 * This is a hack... For private options, *data is not holding
	 * a pointer to the thread_options, but to private data. This means
	 * we can't safely dereference it, but magic is first so mem wise
	 * it is valid. But this also means that if the job first sets
	 * kb_base and expects that to be honored by private options,
	 * it will be disappointed. We will return the global default
	 * for this.
	 */
	if (o && o->magic == OPT_MAGIC)
		kb_base = o->kb_base;
	if (!kb_base)
		kb_base = 1024;

	return kb_base;
}

int add_option(struct fio_option *o)
{
	struct fio_option *__o;
	int opt_index = 0;

	__o = fio_options;
	while (__o->name) {
		opt_index++;
		__o++;
	}

	if (opt_index + 1 == FIO_MAX_OPTS) {
		log_err("fio: FIO_MAX_OPTS is too small\n");
		return 1;
	}

	memcpy(&fio_options[opt_index], o, sizeof(*o));
	fio_options[opt_index + 1].name = NULL;
	return 0;
}

void invalidate_profile_options(const char *prof_name)
{
	struct fio_option *o;

	o = fio_options;
	while (o->name) {
		if (o->prof_name && !strcmp(o->prof_name, prof_name)) {
			o->type = FIO_OPT_INVALID;
			o->prof_name = NULL;
		}
		o++;
	}
}

void add_opt_posval(const char *optname, const char *ival, const char *help)
{
	struct fio_option *o;
	unsigned int i;

	o = find_option(fio_options, optname);
	if (!o)
		return;

	for (i = 0; i < PARSE_MAX_VP; i++) {
		if (o->posval[i].ival)
			continue;

		o->posval[i].ival = ival;
		o->posval[i].help = help;
		break;
	}
}

void del_opt_posval(const char *optname, const char *ival)
{
	struct fio_option *o;
	unsigned int i;

	o = find_option(fio_options, optname);
	if (!o)
		return;

	for (i = 0; i < PARSE_MAX_VP; i++) {
		if (!o->posval[i].ival)
			continue;
		if (strcmp(o->posval[i].ival, ival))
			continue;

		o->posval[i].ival = NULL;
		o->posval[i].help = NULL;
	}
}

void fio_options_free(struct thread_data *td)
{
	options_free(fio_options, td);
	if (td->eo && td->io_ops && td->io_ops->options) {
		options_free(td->io_ops->options, td->eo);
		free(td->eo);
		td->eo = NULL;
	}
}

struct fio_option *fio_option_find(const char *name)
{
	return find_option(fio_options, name);
}

