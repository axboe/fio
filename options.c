#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>
#include <netinet/in.h>

#include "fio.h"
#include "verify.h"
#include "parse.h"
#include "lib/pattern.h"
#include "options.h"
#include "optgroup.h"

char client_sockaddr_str[INET6_ADDRSTRLEN] = { 0 };

#define cb_data_to_td(data)	container_of(data, struct thread_data, o)

static struct pattern_fmt_desc fmt_desc[] = {
	{
		.fmt   = "%o",
		.len   = FIELD_SIZE(struct io_u *, offset),
		.paste = paste_blockoff
	}
};

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

static int bs_cmp(const void *p1, const void *p2)
{
	const struct bssplit *bsp1 = p1;
	const struct bssplit *bsp2 = p2;

	return (int) bsp1->perc - (int) bsp2->perc;
}

struct split {
	unsigned int nr;
	unsigned long long val1[ZONESPLIT_MAX];
	unsigned long long val2[ZONESPLIT_MAX];
};

static int split_parse_ddir(struct thread_options *o, struct split *split,
			    char *str, bool absolute, unsigned int max_splits)
{
	unsigned long long perc;
	unsigned int i;
	long long val;
	char *fname;

	split->nr = 0;

	i = 0;
	while ((fname = strsep(&str, ":")) != NULL) {
		char *perc_str;

		if (!strlen(fname))
			break;

		perc_str = strstr(fname, "/");
		if (perc_str) {
			*perc_str = '\0';
			perc_str++;
			if (absolute) {
				if (str_to_decimal(perc_str, &val, 1, o, 0, 0)) {
					log_err("fio: split conversion failed\n");
					return 1;
				}
				perc = val;
			} else {
				perc = atoi(perc_str);
				if (perc > 100)
					perc = 100;
				else if (!perc)
					perc = -1U;
			}
		} else {
			if (absolute)
				perc = 0;
			else
				perc = -1U;
		}

		if (str_to_decimal(fname, &val, 1, o, 0, 0)) {
			log_err("fio: split conversion failed\n");
			return 1;
		}

		split->val1[i] = val;
		split->val2[i] = perc;
		i++;
		if (i == max_splits) {
			log_err("fio: hit max of %d split entries\n", i);
			break;
		}
	}

	split->nr = i;
	return 0;
}

static int bssplit_ddir(struct thread_options *o, enum fio_ddir ddir, char *str,
			bool data)
{
	unsigned int i, perc, perc_missing;
	unsigned long long max_bs, min_bs;
	struct split split;

	memset(&split, 0, sizeof(split));

	if (split_parse_ddir(o, &split, str, data, BSSPLIT_MAX))
		return 1;
	if (!split.nr)
		return 0;

	max_bs = 0;
	min_bs = -1;
	o->bssplit[ddir] = malloc(split.nr * sizeof(struct bssplit));
	o->bssplit_nr[ddir] = split.nr;
	for (i = 0; i < split.nr; i++) {
		if (split.val1[i] > max_bs)
			max_bs = split.val1[i];
		if (split.val1[i] < min_bs)
			min_bs = split.val1[i];

		o->bssplit[ddir][i].bs = split.val1[i];
		o->bssplit[ddir][i].perc =split.val2[i];
	}

	/*
	 * Now check if the percentages add up, and how much is missing
	 */
	perc = perc_missing = 0;
	for (i = 0; i < o->bssplit_nr[ddir]; i++) {
		struct bssplit *bsp = &o->bssplit[ddir][i];

		if (bsp->perc == -1U)
			perc_missing++;
		else
			perc += bsp->perc;
	}

	if (perc > 100 && perc_missing > 1) {
		log_err("fio: bssplit percentages add to more than 100%%\n");
		free(o->bssplit[ddir]);
		o->bssplit[ddir] = NULL;
		return 1;
	}

	/*
	 * If values didn't have a percentage set, divide the remains between
	 * them.
	 */
	if (perc_missing) {
		if (perc_missing == 1 && o->bssplit_nr[ddir] == 1)
			perc = 100;
		for (i = 0; i < o->bssplit_nr[ddir]; i++) {
			struct bssplit *bsp = &o->bssplit[ddir][i];

			if (bsp->perc == -1U)
				bsp->perc = (100 - perc) / perc_missing;
		}
	}

	o->min_bs[ddir] = min_bs;
	o->max_bs[ddir] = max_bs;

	/*
	 * now sort based on percentages, for ease of lookup
	 */
	qsort(o->bssplit[ddir], o->bssplit_nr[ddir], sizeof(struct bssplit), bs_cmp);
	return 0;
}

typedef int (split_parse_fn)(struct thread_options *, enum fio_ddir, char *, bool);

static int str_split_parse(struct thread_data *td, char *str,
			   split_parse_fn *fn, bool data)
{
	char *odir, *ddir;
	int ret = 0;

	odir = strchr(str, ',');
	if (odir) {
		ddir = strchr(odir + 1, ',');
		if (ddir) {
			ret = fn(&td->o, DDIR_TRIM, ddir + 1, data);
			if (!ret)
				*ddir = '\0';
		} else {
			char *op;

			op = strdup(odir + 1);
			ret = fn(&td->o, DDIR_TRIM, op, data);

			free(op);
		}
		if (!ret)
			ret = fn(&td->o, DDIR_WRITE, odir + 1, data);
		if (!ret) {
			*odir = '\0';
			ret = fn(&td->o, DDIR_READ, str, data);
		}
	} else {
		char *op;

		op = strdup(str);
		ret = fn(&td->o, DDIR_WRITE, op, data);
		free(op);

		if (!ret) {
			op = strdup(str);
			ret = fn(&td->o, DDIR_TRIM, op, data);
			free(op);
		}
		if (!ret)
			ret = fn(&td->o, DDIR_READ, str, data);
	}

	return ret;
}

static int str_bssplit_cb(void *data, const char *input)
{
	struct thread_data *td = cb_data_to_td(data);
	char *str, *p;
	int ret = 0;

	p = str = strdup(input);

	strip_blank_front(&str);
	strip_blank_end(str);

	ret = str_split_parse(td, str, bssplit_ddir, false);

	if (parse_dryrun()) {
		int i;

		for (i = 0; i < DDIR_RWDIR_CNT; i++) {
			free(td->o.bssplit[i]);
			td->o.bssplit[i] = NULL;
			td->o.bssplit_nr[i] = 0;
		}
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
	int i = 0, num = sizeof(err) / sizeof(char *);

	while (i < num) {
		if (!strcmp(err[i], str))
			return i + 1;
		i++;
	}
	return 0;
}

static int ignore_error_type(struct thread_data *td, enum error_type_bit etype,
				char *str)
{
	unsigned int i;
	int *error;
	char *fname;

	if (etype >= ERROR_TYPE_CNT) {
		log_err("Illegal error type\n");
		return 1;
	}

	td->o.ignore_error_nr[etype] = 4;
	error = calloc(4, sizeof(int));

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
			log_err("Unknown error %s, please use number value\n",
				  fname);
			td->o.ignore_error_nr[etype] = 0;
			free(error);
			return 1;
		}
		i++;
	}
	if (i) {
		td->o.continue_on_error |= 1 << etype;
		td->o.ignore_error_nr[etype] = i;
		td->o.ignore_error[etype] = error;
	} else {
		td->o.ignore_error_nr[etype] = 0;
		free(error);
	}

	return 0;

}

static int str_replay_skip_cb(void *data, const char *input)
{
	struct thread_data *td = cb_data_to_td(data);
	char *str, *p, *n;
	int ret = 0;

	if (parse_dryrun())
		return 0;

	p = str = strdup(input);

	strip_blank_front(&str);
	strip_blank_end(str);

	while (p) {
		n = strchr(p, ',');
		if (n)
			*n++ = '\0';
		if (!strcmp(p, "read"))
			td->o.replay_skip |= 1u << DDIR_READ;
		else if (!strcmp(p, "write"))
			td->o.replay_skip |= 1u << DDIR_WRITE;
		else if (!strcmp(p, "trim"))
			td->o.replay_skip |= 1u << DDIR_TRIM;
		else if (!strcmp(p, "sync"))
			td->o.replay_skip |= 1u << DDIR_SYNC;
		else {
			log_err("Unknown skip type: %s\n", p);
			ret = 1;
			break;
		}
		p = n;
	}
	free(str);
	return ret;
}

static int str_ignore_error_cb(void *data, const char *input)
{
	struct thread_data *td = cb_data_to_td(data);
	char *str, *p, *n;
	int ret = 1;
	enum error_type_bit type = 0;

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
	struct thread_data *td = cb_data_to_td(data);
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

		if (str_to_decimal(nr, &val, 1, o, 0, 0)) {
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
	struct thread_data *td = cb_data_to_td(data);

	if (td->o.mem_type == MEM_MMAPHUGE || td->o.mem_type == MEM_MMAP ||
	    td->o.mem_type == MEM_MMAPSHARED)
		td->o.mmapfile = get_opt_postfix(mem);

	return 0;
}

static int fio_clock_source_cb(void *data, const char *str)
{
	struct thread_data *td = cb_data_to_td(data);

	fio_clock_source = td->o.clocksource;
	fio_clock_source_set = 1;
	fio_clock_init();
	return 0;
}

static int str_rwmix_read_cb(void *data, unsigned long long *val)
{
	struct thread_data *td = cb_data_to_td(data);

	td->o.rwmix[DDIR_READ] = *val;
	td->o.rwmix[DDIR_WRITE] = 100 - *val;
	return 0;
}

static int str_rwmix_write_cb(void *data, unsigned long long *val)
{
	struct thread_data *td = cb_data_to_td(data);

	td->o.rwmix[DDIR_WRITE] = *val;
	td->o.rwmix[DDIR_READ] = 100 - *val;
	return 0;
}

static int str_exitall_cb(void)
{
	exitall_on_terminate = true;
	return 0;
}

#ifdef FIO_HAVE_CPU_AFFINITY
int fio_cpus_split(os_cpu_mask_t *mask, unsigned int cpu_index)
{
	unsigned int i, index, cpus_in_mask;
	const long max_cpu = cpus_online();

	cpus_in_mask = fio_cpu_count(mask);
	if (!cpus_in_mask)
		return 0;

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
	struct thread_data *td = cb_data_to_td(data);
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
			if (i >= max_cpu) {
				log_err("fio: CPU %d too large (max=%ld)\n", i,
								max_cpu - 1);
				return 1;
			}
			dprint(FD_PARSE, "set cpu allowed %d\n", i);
			fio_cpu_set(&td->o.cpumask, i);
		}
	}

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
			if (icpu >= max_cpu) {
				log_err("fio: CPU %d too large (max=%ld)\n",
							icpu, max_cpu - 1);
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
	return ret;
}

static int str_cpus_allowed_cb(void *data, const char *input)
{
	struct thread_data *td = cb_data_to_td(data);

	if (parse_dryrun())
		return 0;

	return set_cpus_allowed(td, &td->o.cpumask, input);
}

static int str_verify_cpus_allowed_cb(void *data, const char *input)
{
	struct thread_data *td = cb_data_to_td(data);

	if (parse_dryrun())
		return 0;

	return set_cpus_allowed(td, &td->o.verify_cpumask, input);
}

#ifdef CONFIG_ZLIB
static int str_log_cpus_allowed_cb(void *data, const char *input)
{
	struct thread_data *td = cb_data_to_td(data);

	if (parse_dryrun())
		return 0;

	return set_cpus_allowed(td, &td->o.log_gz_cpumask, input);
}
#endif /* CONFIG_ZLIB */

#endif /* FIO_HAVE_CPU_AFFINITY */

#ifdef CONFIG_LIBNUMA
static int str_numa_cpunodes_cb(void *data, char *input)
{
	struct thread_data *td = cb_data_to_td(data);
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
	return 0;
}

static int str_numa_mpol_cb(void *data, char *input)
{
	struct thread_data *td = cb_data_to_td(data);
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

	return 0;
out:
	return 1;
}
#endif

static int str_fst_cb(void *data, const char *str)
{
	struct thread_data *td = cb_data_to_td(data);
	double val;
	bool done = false;
	char *nr;

	td->file_service_nr = 1;

	switch (td->o.file_service_type) {
	case FIO_FSERVICE_RANDOM:
	case FIO_FSERVICE_RR:
	case FIO_FSERVICE_SEQ:
		nr = get_opt_postfix(str);
		if (nr) {
			td->file_service_nr = atoi(nr);
			free(nr);
		}
		done = true;
		break;
	case FIO_FSERVICE_ZIPF:
		val = FIO_DEF_ZIPF;
		break;
	case FIO_FSERVICE_PARETO:
		val = FIO_DEF_PARETO;
		break;
	case FIO_FSERVICE_GAUSS:
		val = 0.0;
		break;
	default:
		log_err("fio: bad file service type: %d\n", td->o.file_service_type);
		return 1;
	}

	if (done)
		return 0;

	nr = get_opt_postfix(str);
	if (nr && !str_to_float(nr, &val, 0)) {
		log_err("fio: file service type random postfix parsing failed\n");
		free(nr);
		return 1;
	}

	free(nr);

	switch (td->o.file_service_type) {
	case FIO_FSERVICE_ZIPF:
		if (val == 1.00) {
			log_err("fio: zipf theta must be different than 1.0\n");
			return 1;
		}
		if (parse_dryrun())
			return 0;
		td->zipf_theta = val;
		break;
	case FIO_FSERVICE_PARETO:
		if (val <= 0.00 || val >= 1.00) {
                          log_err("fio: pareto input out of range (0 < input < 1.0)\n");
                          return 1;
		}
		if (parse_dryrun())
			return 0;
		td->pareto_h = val;
		break;
	case FIO_FSERVICE_GAUSS:
		if (val < 0.00 || val >= 100.00) {
                          log_err("fio: normal deviation out of range (0 <= input < 100.0)\n");
                          return 1;
		}
		if (parse_dryrun())
			return 0;
		td->gauss_dev = val;
		break;
	}

	return 0;
}

#ifdef CONFIG_SYNC_FILE_RANGE
static int str_sfr_cb(void *data, const char *str)
{
	struct thread_data *td = cb_data_to_td(data);
	char *nr = get_opt_postfix(str);

	td->sync_file_range_nr = 1;
	if (nr) {
		td->sync_file_range_nr = atoi(nr);
		free(nr);
	}

	return 0;
}
#endif

static int zone_split_ddir(struct thread_options *o, enum fio_ddir ddir,
			   char *str, bool absolute)
{
	unsigned int i, perc, perc_missing, sperc, sperc_missing;
	struct split split;

	memset(&split, 0, sizeof(split));

	if (split_parse_ddir(o, &split, str, absolute, ZONESPLIT_MAX))
		return 1;
	if (!split.nr)
		return 0;

	o->zone_split[ddir] = malloc(split.nr * sizeof(struct zone_split));
	o->zone_split_nr[ddir] = split.nr;
	for (i = 0; i < split.nr; i++) {
		o->zone_split[ddir][i].access_perc = split.val1[i];
		if (absolute)
			o->zone_split[ddir][i].size = split.val2[i];
		else
			o->zone_split[ddir][i].size_perc = split.val2[i];
	}

	/*
	 * Now check if the percentages add up, and how much is missing
	 */
	perc = perc_missing = 0;
	sperc = sperc_missing = 0;
	for (i = 0; i < o->zone_split_nr[ddir]; i++) {
		struct zone_split *zsp = &o->zone_split[ddir][i];

		if (zsp->access_perc == (uint8_t) -1U)
			perc_missing++;
		else
			perc += zsp->access_perc;

		if (!absolute) {
			if (zsp->size_perc == (uint8_t) -1U)
				sperc_missing++;
			else
				sperc += zsp->size_perc;
		}
	}

	if (perc > 100 || sperc > 100) {
		log_err("fio: zone_split percentages add to more than 100%%\n");
		free(o->zone_split[ddir]);
		o->zone_split[ddir] = NULL;
		return 1;
	}
	if (perc < 100) {
		log_err("fio: access percentage don't add up to 100 for zoned "
			"random distribution (got=%u)\n", perc);
		free(o->zone_split[ddir]);
		o->zone_split[ddir] = NULL;
		return 1;
	}

	/*
	 * If values didn't have a percentage set, divide the remains between
	 * them.
	 */
	if (perc_missing) {
		if (perc_missing == 1 && o->zone_split_nr[ddir] == 1)
			perc = 100;
		for (i = 0; i < o->zone_split_nr[ddir]; i++) {
			struct zone_split *zsp = &o->zone_split[ddir][i];

			if (zsp->access_perc == (uint8_t) -1U)
				zsp->access_perc = (100 - perc) / perc_missing;
		}
	}
	if (sperc_missing) {
		if (sperc_missing == 1 && o->zone_split_nr[ddir] == 1)
			sperc = 100;
		for (i = 0; i < o->zone_split_nr[ddir]; i++) {
			struct zone_split *zsp = &o->zone_split[ddir][i];

			if (zsp->size_perc == (uint8_t) -1U)
				zsp->size_perc = (100 - sperc) / sperc_missing;
		}
	}

	return 0;
}

static int parse_zoned_distribution(struct thread_data *td, const char *input,
				    bool absolute)
{
	const char *pre = absolute ? "zoned_abs:" : "zoned:";
	char *str, *p;
	int i, ret = 0;

	p = str = strdup(input);

	strip_blank_front(&str);
	strip_blank_end(str);

	/* We expect it to start like that, bail if not */
	if (strncmp(str, pre, strlen(pre))) {
		log_err("fio: mismatch in zoned input <%s>\n", str);
		free(p);
		return 1;
	}
	str += strlen(pre);

	ret = str_split_parse(td, str, zone_split_ddir, absolute);

	free(p);

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		int j;

		dprint(FD_PARSE, "zone ddir %d (nr=%u): \n", i, td->o.zone_split_nr[i]);

		for (j = 0; j < td->o.zone_split_nr[i]; j++) {
			struct zone_split *zsp = &td->o.zone_split[i][j];

			if (absolute) {
				dprint(FD_PARSE, "\t%d: %u/%llu\n", j,
						zsp->access_perc,
						(unsigned long long) zsp->size);
			} else {
				dprint(FD_PARSE, "\t%d: %u/%u\n", j,
						zsp->access_perc,
						zsp->size_perc);
			}
		}
	}

	if (parse_dryrun()) {
		for (i = 0; i < DDIR_RWDIR_CNT; i++) {
			free(td->o.zone_split[i]);
			td->o.zone_split[i] = NULL;
			td->o.zone_split_nr[i] = 0;
		}

		return ret;
	}

	if (ret) {
		for (i = 0; i < DDIR_RWDIR_CNT; i++)
			td->o.zone_split_nr[i] = 0;
	}

	return ret;
}

static int str_random_distribution_cb(void *data, const char *str)
{
	struct thread_data *td = cb_data_to_td(data);
	double val;
	char *nr;

	if (td->o.random_distribution == FIO_RAND_DIST_ZIPF)
		val = FIO_DEF_ZIPF;
	else if (td->o.random_distribution == FIO_RAND_DIST_PARETO)
		val = FIO_DEF_PARETO;
	else if (td->o.random_distribution == FIO_RAND_DIST_GAUSS)
		val = 0.0;
	else if (td->o.random_distribution == FIO_RAND_DIST_ZONED)
		return parse_zoned_distribution(td, str, false);
	else if (td->o.random_distribution == FIO_RAND_DIST_ZONED_ABS)
		return parse_zoned_distribution(td, str, true);
	else
		return 0;

	nr = get_opt_postfix(str);
	if (nr && !str_to_float(nr, &val, 0)) {
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
		if (parse_dryrun())
			return 0;
		td->o.zipf_theta.u.f = val;
	} else if (td->o.random_distribution == FIO_RAND_DIST_PARETO) {
		if (val <= 0.00 || val >= 1.00) {
			log_err("fio: pareto input out of range (0 < input < 1.0)\n");
			return 1;
		}
		if (parse_dryrun())
			return 0;
		td->o.pareto_h.u.f = val;
	} else {
		if (val < 0.00 || val >= 100.0) {
			log_err("fio: normal deviation out of range (0 <= input < 100.0)\n");
			return 1;
		}
		if (parse_dryrun())
			return 0;
		td->o.gauss_dev.u.f = val;
	}

	return 0;
}

static int str_steadystate_cb(void *data, const char *str)
{
	struct thread_data *td = cb_data_to_td(data);
	double val;
	char *nr;
	char *pct;
	long long ll;

	if (td->o.ss_state != FIO_SS_IOPS && td->o.ss_state != FIO_SS_IOPS_SLOPE &&
	    td->o.ss_state != FIO_SS_BW && td->o.ss_state != FIO_SS_BW_SLOPE) {
		/* should be impossible to get here */
		log_err("fio: unknown steady state criterion\n");
		return 1;
	}

	nr = get_opt_postfix(str);
	if (!nr) {
		log_err("fio: steadystate threshold must be specified in addition to criterion\n");
		free(nr);
		return 1;
	}

	/* ENHANCEMENT Allow fio to understand size=10.2% and use here */
	pct = strstr(nr, "%");
	if (pct) {
		*pct = '\0';
		strip_blank_end(nr);
		if (!str_to_float(nr, &val, 0))	{
			log_err("fio: could not parse steadystate threshold percentage\n");
			free(nr);
			return 1;
		}

		dprint(FD_PARSE, "set steady state threshold to %f%%\n", val);
		free(nr);
		if (parse_dryrun())
			return 0;

		td->o.ss_state |= FIO_SS_PCT;
		td->o.ss_limit.u.f = val;
	} else if (td->o.ss_state & FIO_SS_IOPS) {
		if (!str_to_float(nr, &val, 0)) {
			log_err("fio: steadystate IOPS threshold postfix parsing failed\n");
			free(nr);
			return 1;
		}

		dprint(FD_PARSE, "set steady state IOPS threshold to %f\n", val);
		free(nr);
		if (parse_dryrun())
			return 0;

		td->o.ss_limit.u.f = val;
	} else {	/* bandwidth criterion */
		if (str_to_decimal(nr, &ll, 1, td, 0, 0)) {
			log_err("fio: steadystate BW threshold postfix parsing failed\n");
			free(nr);
			return 1;
		}

		dprint(FD_PARSE, "set steady state BW threshold to %lld\n", ll);
		free(nr);
		if (parse_dryrun())
			return 0;

		td->o.ss_limit.u.f = (double) ll;
	}

	td->ss.state = td->o.ss_state;
	return 0;
}

/*
 * Return next name in the string. Files are separated with ':'. If the ':'
 * is escaped with a '\', then that ':' is part of the filename and does not
 * indicate a new file.
 */
char *get_next_str(char **ptr)
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


int get_max_str_idx(char *input)
{
	unsigned int cur_idx;
	char *str, *p;

	p = str = strdup(input);
	for (cur_idx = 0; ; cur_idx++)
		if (get_next_str(&str) == NULL)
			break;

	free(p);
	return cur_idx;
}

/*
 * Returns the directory at the index, indexes > entires will be
 * assigned via modulo division of the index
 */
int set_name_idx(char *target, size_t tlen, char *input, int index,
		 bool unique_filename)
{
	unsigned int cur_idx;
	int len;
	char *fname, *str, *p;

	p = str = strdup(input);

	index %= get_max_str_idx(input);
	for (cur_idx = 0; cur_idx <= index; cur_idx++)
		fname = get_next_str(&str);

	if (client_sockaddr_str[0] && unique_filename) {
		len = snprintf(target, tlen, "%s/%s.", fname,
				client_sockaddr_str);
	} else
		len = snprintf(target, tlen, "%s%c", fname,
				FIO_OS_PATH_SEPARATOR);

	target[tlen - 1] = '\0';
	free(p);

	return len;
}

char* get_name_by_idx(char *input, int index)
{
	unsigned int cur_idx;
	char *fname, *str, *p;

	p = str = strdup(input);

	index %= get_max_str_idx(input);
	for (cur_idx = 0; cur_idx <= index; cur_idx++)
		fname = get_next_str(&str);

	fname = strdup(fname);
	free(p);

	return fname;
}

static int str_filename_cb(void *data, const char *input)
{
	struct thread_data *td = cb_data_to_td(data);
	char *fname, *str, *p;

	p = str = strdup(input);

	strip_blank_front(&str);
	strip_blank_end(str);

	/*
	 * Ignore what we may already have from nrfiles option.
	 */
	if (!td->files_index)
		td->o.nr_files = 0;

	while ((fname = get_next_str(&str)) != NULL) {
		if (!strlen(fname))
			break;
		add_file(td, fname, 0, 1);
	}

	free(p);
	return 0;
}

static int str_directory_cb(void *data, const char fio_unused *unused)
{
	struct thread_data *td = cb_data_to_td(data);
	struct stat sb;
	char *dirname, *str, *p;
	int ret = 0;

	if (parse_dryrun())
		return 0;

	p = str = strdup(td->o.directory);
	while ((dirname = get_next_str(&str)) != NULL) {
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

static int str_opendir_cb(void *data, const char fio_unused *str)
{
	struct thread_data *td = cb_data_to_td(data);

	if (parse_dryrun())
		return 0;

	if (!td->files_index)
		td->o.nr_files = 0;

	return add_dir_files(td, td->o.opendir);
}

static int str_buffer_pattern_cb(void *data, const char *input)
{
	struct thread_data *td = cb_data_to_td(data);
	int ret;

	/* FIXME: for now buffer pattern does not support formats */
	ret = parse_and_fill_pattern(input, strlen(input), td->o.buffer_pattern,
				     MAX_PATTERN_SIZE, NULL, 0, NULL, NULL);
	if (ret < 0)
		return 1;

	assert(ret != 0);
	td->o.buffer_pattern_bytes = ret;

	/*
	 * If this job is doing any reading or has compression set,
	 * ensure that we refill buffers for writes or we could be
	 * invalidating the pattern through reads.
	 */
	if (!td->o.compress_percentage && !td_read(td))
		td->o.refill_buffers = 0;
	else
		td->o.refill_buffers = 1;

	td->o.scramble_buffers = 0;
	td->o.zero_buffers = 0;

	return 0;
}

static int str_buffer_compress_cb(void *data, unsigned long long *il)
{
	struct thread_data *td = cb_data_to_td(data);

	td->flags |= TD_F_COMPRESS;
	td->o.compress_percentage = *il;
	return 0;
}

static int str_dedupe_cb(void *data, unsigned long long *il)
{
	struct thread_data *td = cb_data_to_td(data);

	td->flags |= TD_F_COMPRESS;
	td->o.dedupe_percentage = *il;
	td->o.refill_buffers = 1;
	return 0;
}

static int str_verify_pattern_cb(void *data, const char *input)
{
	struct thread_data *td = cb_data_to_td(data);
	int ret;

	td->o.verify_fmt_sz = ARRAY_SIZE(td->o.verify_fmt);
	ret = parse_and_fill_pattern(input, strlen(input), td->o.verify_pattern,
				     MAX_PATTERN_SIZE, fmt_desc, sizeof(fmt_desc),
				     td->o.verify_fmt, &td->o.verify_fmt_sz);
	if (ret < 0)
		return 1;

	assert(ret != 0);
	td->o.verify_pattern_bytes = ret;
	/*
	 * VERIFY_* could already be set
	 */
	if (!fio_option_is_set(&td->o, verify))
		td->o.verify = VERIFY_PATTERN;

	return 0;
}

static int str_gtod_reduce_cb(void *data, int *il)
{
	struct thread_data *td = cb_data_to_td(data);
	int val = *il;

	/*
	 * Only modfiy options if gtod_reduce==1
	 * Otherwise leave settings alone.
	 */
	if (val) {
		td->o.disable_lat = 1;
		td->o.disable_clat = 1;
		td->o.disable_slat = 1;
		td->o.disable_bw = 1;
		td->o.clat_percentiles = 0;
		td->o.lat_percentiles = 0;
		td->o.slat_percentiles = 0;
		td->ts_cache_mask = 63;
	}

	return 0;
}

static int str_offset_cb(void *data, unsigned long long *__val)
{
	struct thread_data *td = cb_data_to_td(data);
	unsigned long long v = *__val;

	if (parse_is_percent(v)) {
		td->o.start_offset = 0;
		td->o.start_offset_percent = -1ULL - v;
		dprint(FD_PARSE, "SET start_offset_percent %d\n",
					td->o.start_offset_percent);
	} else
		td->o.start_offset = v;

	return 0;
}

static int str_offset_increment_cb(void *data, unsigned long long *__val)
{
	struct thread_data *td = cb_data_to_td(data);
	unsigned long long v = *__val;

	if (parse_is_percent(v)) {
		td->o.offset_increment = 0;
		td->o.offset_increment_percent = -1ULL - v;
		dprint(FD_PARSE, "SET offset_increment_percent %d\n",
					td->o.offset_increment_percent);
	} else
		td->o.offset_increment = v;

	return 0;
}

static int str_size_cb(void *data, unsigned long long *__val)
{
	struct thread_data *td = cb_data_to_td(data);
	unsigned long long v = *__val;

	if (parse_is_percent(v)) {
		td->o.size = 0;
		td->o.size_percent = -1ULL - v;
		dprint(FD_PARSE, "SET size_percent %d\n",
					td->o.size_percent);
	} else
		td->o.size = v;

	return 0;
}

static int str_write_bw_log_cb(void *data, const char *str)
{
	struct thread_data *td = cb_data_to_td(data);

	if (str)
		td->o.bw_log_file = strdup(str);

	td->o.write_bw_log = 1;
	return 0;
}

static int str_write_lat_log_cb(void *data, const char *str)
{
	struct thread_data *td = cb_data_to_td(data);

	if (str)
		td->o.lat_log_file = strdup(str);

	td->o.write_lat_log = 1;
	return 0;
}

static int str_write_iops_log_cb(void *data, const char *str)
{
	struct thread_data *td = cb_data_to_td(data);

	if (str)
		td->o.iops_log_file = strdup(str);

	td->o.write_iops_log = 1;
	return 0;
}

static int str_write_hist_log_cb(void *data, const char *str)
{
	struct thread_data *td = cb_data_to_td(data);

	if (str)
		td->o.hist_log_file = strdup(str);

	td->o.write_hist_log = 1;
	return 0;
}

/*
 * str is supposed to be a substring of the strdup'd original string,
 * and is valid only if it's a regular file path.
 * This function keeps the pointer to the path as needed later.
 *
 * "external:/path/to/so\0" <- original pointer updated with strdup'd
 * "external\0"             <- above pointer after parsed, i.e. ->ioengine
 *          "/path/to/so\0" <- str argument, i.e. ->ioengine_so_path
 */
static int str_ioengine_external_cb(void *data, const char *str)
{
	struct thread_data *td = cb_data_to_td(data);
	struct stat sb;
	char *p;

	if (!str) {
		log_err("fio: null external ioengine path\n");
		return 1;
	}

	p = (char *)str; /* str is mutable */
	strip_blank_front(&p);
	strip_blank_end(p);

	if (stat(p, &sb) || !S_ISREG(sb.st_mode)) {
		log_err("fio: invalid external ioengine path \"%s\"\n", p);
		return 1;
	}

	td->o.ioengine_so_path = p;
	return 0;
}

static int rw_verify(const struct fio_option *o, void *data)
{
	struct thread_data *td = cb_data_to_td(data);

	if (read_only && (td_write(td) || td_trim(td))) {
		log_err("fio: job <%s> has write or trim bit set, but"
			" fio is in read-only mode\n", td->o.name);
		return 1;
	}

	return 0;
}

static int gtod_cpu_verify(const struct fio_option *o, void *data)
{
#ifndef FIO_HAVE_CPU_AFFINITY
	struct thread_data *td = cb_data_to_td(data);

	if (td->o.gtod_cpu) {
		log_err("fio: platform must support CPU affinity for"
			"gettimeofday() offloading\n");
		return 1;
	}
#endif

	return 0;
}

/*
 * Map of job/command line options
 */
struct fio_option fio_options[FIO_MAX_OPTS] = {
	{
		.name	= "description",
		.lname	= "Description of job",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct thread_options, description),
		.help	= "Text job description",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_DESC,
	},
	{
		.name	= "name",
		.lname	= "Job name",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct thread_options, name),
		.help	= "Name of this job",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_DESC,
	},
	{
		.name	= "wait_for",
		.lname	= "Waitee name",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct thread_options, wait_for),
		.help	= "Name of the job this one wants to wait for before starting",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_DESC,
	},
	{
		.name	= "filename",
		.lname	= "Filename(s)",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct thread_options, filename),
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
		.off1	= offsetof(struct thread_options, directory),
		.cb	= str_directory_cb,
		.help	= "Directory to store files in",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_FILENAME,
	},
	{
		.name	= "filename_format",
		.lname	= "Filename Format",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct thread_options, filename_format),
		.prio	= -1, /* must come after "directory" */
		.help	= "Override default $jobname.$jobnum.$filenum naming",
		.def	= "$jobname.$jobnum.$filenum",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_FILENAME,
	},
	{
		.name	= "unique_filename",
		.lname	= "Unique Filename",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, unique_filename),
		.help	= "For network clients, prefix file with source IP",
		.def	= "1",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_FILENAME,
	},
	{
		.name	= "lockfile",
		.lname	= "Lockfile",
		.type	= FIO_OPT_STR,
		.off1	= offsetof(struct thread_options, file_lock_mode),
		.help	= "Lock file when doing IO to it",
		.prio	= 1,
		.parent	= "filename",
		.hide	= 0,
		.def	= "none",
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
		.off1	= offsetof(struct thread_options, opendir),
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
		.off1	= offsetof(struct thread_options, td_ddir),
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
			  { .ival = "trimwrite",
			    .oval = TD_DDIR_TRIMWRITE,
			    .help = "Trim and write mix, trims preceding writes"
			  },
		},
	},
	{
		.name	= "rw_sequencer",
		.lname	= "RW Sequencer",
		.type	= FIO_OPT_STR,
		.off1	= offsetof(struct thread_options, rw_seq),
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
		.off1	= offsetof(struct thread_options, ioengine),
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
#ifdef FIO_HAVE_PWRITEV2
			  { .ival = "pvsync2",
			    .help = "Use preadv2/pwritev2",
			  },
#endif
#ifdef CONFIG_LIBAIO
			  { .ival = "libaio",
			    .help = "Linux native asynchronous IO",
			  },
#endif
#ifdef ARCH_HAVE_IOURING
			  { .ival = "io_uring",
			    .help = "Fast Linux native aio",
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
#ifdef CONFIG_RDMA
			  { .ival = "rdma",
			    .help = "RDMA IO engine",
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
#ifdef CONFIG_GFAPI
			  { .ival = "gfapi",
			    .help = "Glusterfs libgfapi(sync) based engine"
			  },
			  { .ival = "gfapi_async",
			    .help = "Glusterfs libgfapi(async) based engine"
			  },
#endif
#ifdef CONFIG_LIBHDFS
			  { .ival = "libhdfs",
			    .help = "Hadoop Distributed Filesystem (HDFS) engine"
			  },
#endif
#ifdef CONFIG_PMEMBLK
			  { .ival = "pmemblk",
			    .help = "PMDK libpmemblk based IO engine",
			  },

#endif
#ifdef CONFIG_IME
			  { .ival = "ime_psync",
			    .help = "DDN's IME synchronous IO engine",
			  },
			  { .ival = "ime_psyncv",
			    .help = "DDN's IME synchronous IO engine using iovecs",
			  },
			  { .ival = "ime_aio",
			    .help = "DDN's IME asynchronous IO engine",
			  },
#endif
#ifdef CONFIG_LINUX_DEVDAX
			  { .ival = "dev-dax",
			    .help = "DAX Device based IO engine",
			  },
#endif
			  {
			    .ival = "filecreate",
			    .help = "File creation engine",
			  },
			  { .ival = "external",
			    .help = "Load external engine (append name)",
			    .cb = str_ioengine_external_cb,
			  },
#ifdef CONFIG_LIBPMEM
			  { .ival = "libpmem",
			    .help = "PMDK libpmem based IO engine",
			  },
#endif
#ifdef CONFIG_HTTP
			  { .ival = "http",
			    .help = "HTTP (WebDAV/S3) IO engine",
			  },
#endif
			  { .ival = "nbd",
			    .help = "Network Block Device (NBD) IO engine"
			  },
		},
	},
	{
		.name	= "iodepth",
		.lname	= "IO Depth",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct thread_options, iodepth),
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
		.off1	= offsetof(struct thread_options, iodepth_batch),
		.help	= "Number of IO buffers to submit in one go",
		.parent	= "iodepth",
		.hide	= 1,
		.interval = 1,
		.def	= "1",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_BASIC,
	},
	{
		.name	= "iodepth_batch_complete_min",
		.lname	= "Min IO depth batch complete",
		.alias	= "iodepth_batch_complete",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct thread_options, iodepth_batch_complete_min),
		.help	= "Min number of IO buffers to retrieve in one go",
		.parent	= "iodepth",
		.hide	= 1,
		.minval	= 0,
		.interval = 1,
		.def	= "1",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_BASIC,
	},
	{
		.name	= "iodepth_batch_complete_max",
		.lname	= "Max IO depth batch complete",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct thread_options, iodepth_batch_complete_max),
		.help	= "Max number of IO buffers to retrieve in one go",
		.parent	= "iodepth",
		.hide	= 1,
		.minval	= 0,
		.interval = 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_BASIC,
	},
	{
		.name	= "iodepth_low",
		.lname	= "IO Depth batch low",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct thread_options, iodepth_low),
		.help	= "Low water mark for queuing depth",
		.parent	= "iodepth",
		.hide	= 1,
		.interval = 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_BASIC,
	},
	{
		.name	= "serialize_overlap",
		.lname	= "Serialize overlap",
		.off1	= offsetof(struct thread_options, serialize_overlap),
		.type	= FIO_OPT_BOOL,
		.help	= "Wait for in-flight IOs that collide to complete",
		.parent	= "iodepth",
		.def	= "0",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_BASIC,
	},
	{
		.name	= "io_submit_mode",
		.lname	= "IO submit mode",
		.type	= FIO_OPT_STR,
		.off1	= offsetof(struct thread_options, io_submit_mode),
		.help	= "How IO submissions and completions are done",
		.def	= "inline",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_BASIC,
		.posval = {
			  { .ival = "inline",
			    .oval = IO_MODE_INLINE,
			    .help = "Submit and complete IO inline",
			  },
			  { .ival = "offload",
			    .oval = IO_MODE_OFFLOAD,
			    .help = "Offload submit and complete to threads",
			  },
		},
	},
	{
		.name	= "size",
		.lname	= "Size",
		.type	= FIO_OPT_STR_VAL,
		.cb	= str_size_cb,
		.off1	= offsetof(struct thread_options, size),
		.help	= "Total size of device or files",
		.interval = 1024 * 1024,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "io_size",
		.alias	= "io_limit",
		.lname	= "IO Size",
		.type	= FIO_OPT_STR_VAL,
		.off1	= offsetof(struct thread_options, io_size),
		.help	= "Total size of I/O to be performed",
		.interval = 1024 * 1024,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "fill_device",
		.lname	= "Fill device",
		.alias	= "fill_fs",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, fill_device),
		.help	= "Write until an ENOSPC error occurs",
		.def	= "0",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "filesize",
		.lname	= "File size",
		.type	= FIO_OPT_STR_VAL,
		.off1	= offsetof(struct thread_options, file_size_low),
		.off2	= offsetof(struct thread_options, file_size_high),
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
		.off1	= offsetof(struct thread_options, file_append),
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
		.cb	= str_offset_cb,
		.off1	= offsetof(struct thread_options, start_offset),
		.help	= "Start IO from this offset",
		.def	= "0",
		.interval = 1024 * 1024,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "offset_align",
		.lname	= "IO offset alignment",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct thread_options, start_offset_align),
		.help	= "Start IO from this offset alignment",
		.def	= "0",
		.interval = 512,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "offset_increment",
		.lname	= "IO offset increment",
		.type	= FIO_OPT_STR_VAL,
		.cb	= str_offset_increment_cb,
		.off1	= offsetof(struct thread_options, offset_increment),
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
		.off1	= offsetof(struct thread_options, number_ios),
		.help	= "Force job completion after this number of IOs",
		.def	= "0",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "bs",
		.lname	= "Block size",
		.alias	= "blocksize",
		.type	= FIO_OPT_ULL,
		.off1	= offsetof(struct thread_options, bs[DDIR_READ]),
		.off2	= offsetof(struct thread_options, bs[DDIR_WRITE]),
		.off3	= offsetof(struct thread_options, bs[DDIR_TRIM]),
		.minval = 1,
		.help	= "Block size unit",
		.def	= "4096",
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
		.type	= FIO_OPT_ULL,
		.off1	= offsetof(struct thread_options, ba[DDIR_READ]),
		.off2	= offsetof(struct thread_options, ba[DDIR_WRITE]),
		.off3	= offsetof(struct thread_options, ba[DDIR_TRIM]),
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
		.off1	= offsetof(struct thread_options, min_bs[DDIR_READ]),
		.off2	= offsetof(struct thread_options, max_bs[DDIR_READ]),
		.off3	= offsetof(struct thread_options, min_bs[DDIR_WRITE]),
		.off4	= offsetof(struct thread_options, max_bs[DDIR_WRITE]),
		.off5	= offsetof(struct thread_options, min_bs[DDIR_TRIM]),
		.off6	= offsetof(struct thread_options, max_bs[DDIR_TRIM]),
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
		.type	= FIO_OPT_STR_ULL,
		.cb	= str_bssplit_cb,
		.off1	= offsetof(struct thread_options, bssplit),
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
		.off1	= offsetof(struct thread_options, bs_unaligned),
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
		.off1	= offsetof(struct thread_options, bs_is_seq_rand),
		.help	= "Consider any blocksize setting to be sequential,random",
		.def	= "0",
		.parent = "blocksize",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "randrepeat",
		.lname	= "Random repeatable",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, rand_repeatable),
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
		.off1	= offsetof(struct thread_options, rand_seed),
		.help	= "Set the random generator seed value",
		.def	= "0x89",
		.parent = "rw",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_RANDOM,
	},
	{
		.name	= "norandommap",
		.lname	= "No randommap",
		.type	= FIO_OPT_STR_SET,
		.off1	= offsetof(struct thread_options, norandommap),
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
		.off1	= offsetof(struct thread_options, softrandommap),
		.help	= "Set norandommap if randommap allocation fails",
		.parent	= "norandommap",
		.hide	= 1,
		.def	= "0",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_RANDOM,
	},
	{
		.name	= "random_generator",
		.lname	= "Random Generator",
		.type	= FIO_OPT_STR,
		.off1	= offsetof(struct thread_options, random_generator),
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
			  {
			    .ival = "tausworthe64",
			    .oval = FIO_RAND_GEN_TAUSWORTHE64,
			    .help = "64-bit Tausworthe variant",
			  },
		},
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_RANDOM,
	},
	{
		.name	= "random_distribution",
		.lname	= "Random Distribution",
		.type	= FIO_OPT_STR,
		.off1	= offsetof(struct thread_options, random_distribution),
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
			  { .ival = "normal",
			    .oval = FIO_RAND_DIST_GAUSS,
			    .help = "Normal (Gaussian) distribution",
			  },
			  { .ival = "zoned",
			    .oval = FIO_RAND_DIST_ZONED,
			    .help = "Zoned random distribution",
			  },
			  { .ival = "zoned_abs",
			    .oval = FIO_RAND_DIST_ZONED_ABS,
			    .help = "Zoned absolute random distribution",
			  },
		},
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_RANDOM,
	},
	{
		.name	= "percentage_random",
		.lname	= "Percentage Random",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct thread_options, perc_rand[DDIR_READ]),
		.off2	= offsetof(struct thread_options, perc_rand[DDIR_WRITE]),
		.off3	= offsetof(struct thread_options, perc_rand[DDIR_TRIM]),
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
		.lname	= "All Random Repeat",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, allrand_repeatable),
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
		.off1	= offsetof(struct thread_options, nr_files),
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
		.off1	= offsetof(struct thread_options, open_files),
		.help	= "Number of files to keep open at the same time",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "file_service_type",
		.lname	= "File service type",
		.type	= FIO_OPT_STR,
		.cb	= str_fst_cb,
		.off1	= offsetof(struct thread_options, file_service_type),
		.help	= "How to select which file to service next",
		.def	= "roundrobin",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
		.posval	= {
			  { .ival = "random",
			    .oval = FIO_FSERVICE_RANDOM,
			    .help = "Choose a file at random (uniform)",
			  },
			  { .ival = "zipf",
			    .oval = FIO_FSERVICE_ZIPF,
			    .help = "Zipf randomized",
			  },
			  { .ival = "pareto",
			    .oval = FIO_FSERVICE_PARETO,
			    .help = "Pareto randomized",
			  },
			  { .ival = "normal",
			    .oval = FIO_FSERVICE_GAUSS,
			    .help = "Normal (Gaussian) randomized",
			  },
			  { .ival = "gauss",
			    .oval = FIO_FSERVICE_GAUSS,
			    .help = "Alias for normal",
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
	{
		.name	= "fallocate",
		.lname	= "Fallocate",
		.type	= FIO_OPT_STR,
		.off1	= offsetof(struct thread_options, fallocate_mode),
		.help	= "Whether pre-allocation is performed when laying out files",
#ifdef FIO_HAVE_DEFAULT_FALLOCATE
		.def	= "native",
#else
		.def	= "none",
#endif
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
		.posval	= {
			  { .ival = "none",
			    .oval = FIO_FALLOCATE_NONE,
			    .help = "Do not pre-allocate space",
			  },
			  { .ival = "native",
			    .oval = FIO_FALLOCATE_NATIVE,
			    .help = "Use native pre-allocation if possible",
			  },
#ifdef CONFIG_POSIX_FALLOCATE
			  { .ival = "posix",
			    .oval = FIO_FALLOCATE_POSIX,
			    .help = "Use posix_fallocate()",
			  },
#endif
#ifdef CONFIG_LINUX_FALLOCATE
			  { .ival = "keep",
			    .oval = FIO_FALLOCATE_KEEP_SIZE,
			    .help = "Use fallocate(..., FALLOC_FL_KEEP_SIZE, ...)",
			  },
#endif
			  { .ival = "truncate",
			    .oval = FIO_FALLOCATE_TRUNCATE,
			    .help = "Truncate file to final size instead of allocating"
			  },
			  /* Compatibility with former boolean values */
			  { .ival = "0",
			    .oval = FIO_FALLOCATE_NONE,
			    .help = "Alias for 'none'",
			  },
#ifdef CONFIG_POSIX_FALLOCATE
			  { .ival = "1",
			    .oval = FIO_FALLOCATE_POSIX,
			    .help = "Alias for 'posix'",
			  },
#endif
		},
	},
	{
		.name	= "fadvise_hint",
		.lname	= "Fadvise hint",
		.type	= FIO_OPT_STR,
		.off1	= offsetof(struct thread_options, fadvise_hint),
		.posval	= {
			  { .ival = "0",
			    .oval = F_ADV_NONE,
			    .help = "Don't issue fadvise/madvise",
			  },
			  { .ival = "1",
			    .oval = F_ADV_TYPE,
			    .help = "Advise using fio IO pattern",
			  },
			  { .ival = "random",
			    .oval = F_ADV_RANDOM,
			    .help = "Advise using FADV_RANDOM",
			  },
			  { .ival = "sequential",
			    .oval = F_ADV_SEQUENTIAL,
			    .help = "Advise using FADV_SEQUENTIAL",
			  },
		},
		.help	= "Use fadvise() to advise the kernel on IO pattern",
		.def	= "1",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "fsync",
		.lname	= "Fsync",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct thread_options, fsync_blocks),
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
		.off1	= offsetof(struct thread_options, fdatasync_blocks),
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
		.off1	= offsetof(struct thread_options, barrier_blocks),
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
		.off1	= offsetof(struct thread_options, sync_file_range),
		.help	= "Use sync_file_range()",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
	},
#else
	{
		.name	= "sync_file_range",
		.lname	= "Sync file range",
		.type	= FIO_OPT_UNSUPPORTED,
		.help	= "Your platform does not support sync_file_range",
	},
#endif
	{
		.name	= "direct",
		.lname	= "Direct I/O",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, odirect),
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
		.off1	= offsetof(struct thread_options, oatomic),
		.help	= "Use Atomic IO with O_DIRECT (implies O_DIRECT)",
		.def	= "0",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_TYPE,
	},
	{
		.name	= "buffered",
		.lname	= "Buffered I/O",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, odirect),
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
		.off1	= offsetof(struct thread_options, overwrite),
		.help	= "When writing, set whether to overwrite current data",
		.def	= "0",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "loops",
		.lname	= "Loops",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct thread_options, loops),
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
		.off1	= offsetof(struct thread_options, numjobs),
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
		.off1	= offsetof(struct thread_options, start_delay),
		.off2	= offsetof(struct thread_options, start_delay_high),
		.help	= "Only start job when this period has passed",
		.def	= "0",
		.is_seconds = 1,
		.is_time = 1,
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_RUNTIME,
	},
	{
		.name	= "runtime",
		.lname	= "Runtime",
		.alias	= "timeout",
		.type	= FIO_OPT_STR_VAL_TIME,
		.off1	= offsetof(struct thread_options, timeout),
		.help	= "Stop workload when this amount of time has passed",
		.def	= "0",
		.is_seconds = 1,
		.is_time = 1,
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_RUNTIME,
	},
	{
		.name	= "time_based",
		.lname	= "Time based",
		.type	= FIO_OPT_STR_SET,
		.off1	= offsetof(struct thread_options, time_based),
		.help	= "Keep running until runtime/timeout is met",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_RUNTIME,
	},
	{
		.name	= "verify_only",
		.lname	= "Verify only",
		.type	= FIO_OPT_STR_SET,
		.off1	= offsetof(struct thread_options, verify_only),
		.help	= "Verifies previously written data is still valid",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_RUNTIME,
	},
	{
		.name	= "ramp_time",
		.lname	= "Ramp time",
		.type	= FIO_OPT_STR_VAL_TIME,
		.off1	= offsetof(struct thread_options, ramp_time),
		.help	= "Ramp up time before measuring performance",
		.is_seconds = 1,
		.is_time = 1,
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_RUNTIME,
	},
	{
		.name	= "clocksource",
		.lname	= "Clock source",
		.type	= FIO_OPT_STR,
		.cb	= fio_clock_source_cb,
		.off1	= offsetof(struct thread_options, clocksource),
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
		.off1	= offsetof(struct thread_options, mem_type),
		.help	= "Backing type for IO buffers",
		.def	= "malloc",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_INVALID,
		.posval	= {
			  { .ival = "malloc",
			    .oval = MEM_MALLOC,
			    .help = "Use malloc(3) for IO buffers",
			  },
#ifndef CONFIG_NO_SHM
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
#endif
			  { .ival = "mmap",
			    .oval = MEM_MMAP,
			    .help = "Use mmap(2) (file or anon) for IO buffers",
			  },
			  { .ival = "mmapshared",
			    .oval = MEM_MMAPSHARED,
			    .help = "Like mmap, but use the shared flag",
			  },
#ifdef FIO_HAVE_HUGETLB
			  { .ival = "mmaphuge",
			    .oval = MEM_MMAPHUGE,
			    .help = "Like mmap, but use huge pages",
			  },
#endif
#ifdef CONFIG_CUDA
			  { .ival = "cudamalloc",
			    .oval = MEM_CUDA_MALLOC,
			    .help = "Allocate GPU device memory for GPUDirect RDMA",
			  },
#endif
		  },
	},
	{
		.name	= "iomem_align",
		.alias	= "mem_align",
		.lname	= "I/O memory alignment",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct thread_options, mem_align),
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
		.off1	= offsetof(struct thread_options, verify),
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
			  { .ival = "sha3-224",
			    .oval = VERIFY_SHA3_224,
			    .help = "Use sha3-224 checksums for verification",
			  },
			  { .ival = "sha3-256",
			    .oval = VERIFY_SHA3_256,
			    .help = "Use sha3-256 checksums for verification",
			  },
			  { .ival = "sha3-384",
			    .oval = VERIFY_SHA3_384,
			    .help = "Use sha3-384 checksums for verification",
			  },
			  { .ival = "sha3-512",
			    .oval = VERIFY_SHA3_512,
			    .help = "Use sha3-512 checksums for verification",
			  },
			  { .ival = "xxhash",
			    .oval = VERIFY_XXHASH,
			    .help = "Use xxhash checksums for verification",
			  },
			  /* Meta information was included into verify_header,
			   * 'meta' verification is implied by default. */
			  { .ival = "meta",
			    .oval = VERIFY_HDR_ONLY,
			    .help = "Use io information for verification. "
				    "Now is implied by default, thus option is obsolete, "
				    "don't use it",
			  },
			  { .ival = "pattern",
			    .oval = VERIFY_PATTERN_NO_HDR,
			    .help = "Verify strict pattern",
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
		.off1	= offsetof(struct thread_options, do_verify),
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
		.type	= FIO_OPT_SOFT_DEPRECATED,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_VERIFY,
	},
	{
		.name	= "verifysort_nr",
		.lname	= "Verify Sort Nr",
		.type	= FIO_OPT_SOFT_DEPRECATED,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_VERIFY,
	},
	{
		.name   = "verify_interval",
		.lname	= "Verify interval",
		.type   = FIO_OPT_INT,
		.off1   = offsetof(struct thread_options, verify_interval),
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
		.off1	= offsetof(struct thread_options, verify_offset),
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
		.off1	= offsetof(struct thread_options, verify_pattern),
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
		.off1	= offsetof(struct thread_options, verify_fatal),
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
		.off1	= offsetof(struct thread_options, verify_dump),
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
		.off1	= offsetof(struct thread_options, verify_async),
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
		.off1	= offsetof(struct thread_options, verify_backlog),
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
		.off1	= offsetof(struct thread_options, verify_batch),
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
		.off1	= offsetof(struct thread_options, verify_cpumask),
		.help	= "Set CPUs allowed for async verify threads",
		.parent	= "verify_async",
		.hide	= 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_VERIFY,
	},
#else
	{
		.name	= "verify_async_cpus",
		.lname	= "Async verify CPUs",
		.type	= FIO_OPT_UNSUPPORTED,
		.help	= "Your platform does not support CPU affinities",
	},
#endif
	{
		.name	= "experimental_verify",
		.lname	= "Experimental Verify",
		.off1	= offsetof(struct thread_options, experimental_verify),
		.type	= FIO_OPT_BOOL,
		.help	= "Enable experimental verification",
		.parent	= "verify",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_VERIFY,
	},
	{
		.name	= "verify_state_load",
		.lname	= "Load verify state",
		.off1	= offsetof(struct thread_options, verify_state),
		.type	= FIO_OPT_BOOL,
		.help	= "Load verify termination state",
		.parent	= "verify",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_VERIFY,
	},
	{
		.name	= "verify_state_save",
		.lname	= "Save verify state",
		.off1	= offsetof(struct thread_options, verify_state_save),
		.type	= FIO_OPT_BOOL,
		.def	= "1",
		.help	= "Save verify state on termination",
		.parent	= "verify",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_VERIFY,
	},
#ifdef FIO_HAVE_TRIM
	{
		.name	= "trim_percentage",
		.lname	= "Trim percentage",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct thread_options, trim_percentage),
		.minval = 0,
		.maxval = 100,
		.help	= "Number of verify blocks to trim (i.e., discard)",
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
		.help	= "Verify that trimmed (i.e., discarded) blocks are returned as zeroes",
		.off1	= offsetof(struct thread_options, trim_zero),
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
		.off1	= offsetof(struct thread_options, trim_backlog),
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
		.off1	= offsetof(struct thread_options, trim_batch),
		.help	= "Trim this number of IO blocks",
		.parent	= "trim_percentage",
		.hide	= 1,
		.interval = 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_TRIM,
	},
#else
	{
		.name	= "trim_percentage",
		.lname	= "Trim percentage",
		.type	= FIO_OPT_UNSUPPORTED,
		.help	= "Fio does not support TRIM on your platform",
	},
	{
		.name	= "trim_verify_zero",
		.lname	= "Verify trim zero",
		.type	= FIO_OPT_UNSUPPORTED,
		.help	= "Fio does not support TRIM on your platform",
	},
	{
		.name	= "trim_backlog",
		.lname	= "Trim backlog",
		.type	= FIO_OPT_UNSUPPORTED,
		.help	= "Fio does not support TRIM on your platform",
	},
	{
		.name	= "trim_backlog_batch",
		.lname	= "Trim backlog batch",
		.type	= FIO_OPT_UNSUPPORTED,
		.help	= "Fio does not support TRIM on your platform",
	},
#endif
	{
		.name	= "write_iolog",
		.lname	= "Write I/O log",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct thread_options, write_iolog_file),
		.help	= "Store IO pattern to file",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IOLOG,
	},
	{
		.name	= "read_iolog",
		.lname	= "Read I/O log",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct thread_options, read_iolog_file),
		.help	= "Playback IO pattern from file",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IOLOG,
	},
	{
		.name	= "read_iolog_chunked",
		.lname	= "Read I/O log in parts",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, read_iolog_chunked),
		.def	= "0",
		.parent	= "read_iolog",
		.help	= "Parse IO pattern in chunks",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IOLOG,
	},
	{
		.name	= "replay_no_stall",
		.lname	= "Don't stall on replay",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, no_stall),
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
		.off1	= offsetof(struct thread_options, replay_redirect),
		.parent	= "read_iolog",
		.hide	= 1,
		.help	= "Replay all I/O onto this device, regardless of trace device",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IOLOG,
	},
	{
		.name	= "replay_scale",
		.lname	= "Replace offset scale factor",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct thread_options, replay_scale),
		.parent	= "read_iolog",
		.def	= "1",
		.help	= "Align offsets to this blocksize",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IOLOG,
	},
	{
		.name	= "replay_align",
		.lname	= "Replace alignment",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct thread_options, replay_align),
		.parent	= "read_iolog",
		.help	= "Scale offset down by this factor",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IOLOG,
		.pow2	= 1,
	},
	{
		.name	= "replay_time_scale",
		.lname	= "Replay Time Scale",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct thread_options, replay_time_scale),
		.def	= "100",
		.minval	= 1,
		.parent	= "read_iolog",
		.hide	= 1,
		.help	= "Scale time for replay events",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IOLOG,
	},
	{
		.name	= "replay_skip",
		.lname	= "Replay Skip",
		.type	= FIO_OPT_STR,
		.cb	= str_replay_skip_cb,
		.off1	= offsetof(struct thread_options, replay_skip),
		.parent	= "read_iolog",
		.help	= "Skip certain IO types (read,write,trim,flush)",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IOLOG,
	},
	{
		.name	= "merge_blktrace_file",
		.lname	= "Merged blktrace output filename",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct thread_options, merge_blktrace_file),
		.help	= "Merged blktrace output filename",
		.category = FIO_OPT_C_IO,
		.group = FIO_OPT_G_IOLOG,
	},
	{
		.name	= "merge_blktrace_scalars",
		.lname	= "Percentage to scale each trace",
		.type	= FIO_OPT_FLOAT_LIST,
		.off1	= offsetof(struct thread_options, merge_blktrace_scalars),
		.maxlen	= FIO_IO_U_LIST_MAX_LEN,
		.help	= "Percentage to scale each trace",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IOLOG,
	},
	{
		.name	= "merge_blktrace_iters",
		.lname	= "Number of iterations to run per trace",
		.type	= FIO_OPT_FLOAT_LIST,
		.off1	= offsetof(struct thread_options, merge_blktrace_iters),
		.maxlen	= FIO_IO_U_LIST_MAX_LEN,
		.help	= "Number of iterations to run per trace",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IOLOG,
	},
	{
		.name	= "exec_prerun",
		.lname	= "Pre-execute runnable",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct thread_options, exec_prerun),
		.help	= "Execute this file prior to running job",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "exec_postrun",
		.lname	= "Post-execute runnable",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct thread_options, exec_postrun),
		.help	= "Execute this file after running job",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_INVALID,
	},
#ifdef FIO_HAVE_IOSCHED_SWITCH
	{
		.name	= "ioscheduler",
		.lname	= "I/O scheduler",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct thread_options, ioscheduler),
		.help	= "Use this IO scheduler on the backing device",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
	},
#else
	{
		.name	= "ioscheduler",
		.lname	= "I/O scheduler",
		.type	= FIO_OPT_UNSUPPORTED,
		.help	= "Your platform does not support IO scheduler switching",
	},
#endif
	{
		.name	= "zonemode",
		.lname	= "Zone mode",
		.help	= "Mode for the zonesize, zonerange and zoneskip parameters",
		.type	= FIO_OPT_STR,
		.off1	= offsetof(struct thread_options, zone_mode),
		.def	= "none",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_ZONE,
		.posval	= {
			   { .ival = "none",
			     .oval = ZONE_MODE_NONE,
			     .help = "no zoning",
			   },
			   { .ival = "strided",
			     .oval = ZONE_MODE_STRIDED,
			     .help = "strided mode - random I/O is restricted to a single zone",
			   },
			   { .ival = "zbd",
			     .oval = ZONE_MODE_ZBD,
			     .help = "zoned block device mode - random I/O selects one of multiple zones randomly",
			   },
		},
	},
	{
		.name	= "zonesize",
		.lname	= "Zone size",
		.type	= FIO_OPT_STR_VAL,
		.off1	= offsetof(struct thread_options, zone_size),
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
		.off1	= offsetof(struct thread_options, zone_range),
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
		.off1	= offsetof(struct thread_options, zone_skip),
		.help	= "Space between IO zones",
		.def	= "0",
		.interval = 1024 * 1024,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_ZONE,
	},
	{
		.name	= "read_beyond_wp",
		.lname	= "Allow reads beyond the zone write pointer",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, read_beyond_wp),
		.help	= "Allow reads beyond the zone write pointer",
		.def	= "0",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "max_open_zones",
		.lname	= "Maximum number of open zones",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct thread_options, max_open_zones),
		.maxval	= FIO_MAX_OPEN_ZBD_ZONES,
		.help	= "Limit random writes to SMR drives to the specified"
			  " number of sequential zones",
		.def	= "0",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "zone_reset_threshold",
		.lname	= "Zone reset threshold",
		.help	= "Zoned block device reset threshold",
		.type	= FIO_OPT_FLOAT_LIST,
		.maxlen	= 1,
		.off1	= offsetof(struct thread_options, zrt),
		.minfp	= 0,
		.maxfp	= 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_ZONE,
	},
	{
		.name	= "zone_reset_frequency",
		.lname	= "Zone reset frequency",
		.help	= "Zoned block device zone reset frequency in HZ",
		.type	= FIO_OPT_FLOAT_LIST,
		.maxlen	= 1,
		.off1	= offsetof(struct thread_options, zrf),
		.minfp	= 0,
		.maxfp	= 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_ZONE,
	},
	{
		.name	= "lockmem",
		.lname	= "Lock memory",
		.type	= FIO_OPT_STR_VAL,
		.off1	= offsetof(struct thread_options, lockmem),
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
		.off1	= offsetof(struct thread_options, rwmix[DDIR_READ]),
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
		.off1	= offsetof(struct thread_options, rwmix[DDIR_WRITE]),
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
		.off1	= offsetof(struct thread_options, nice),
		.help	= "Set job CPU nice value",
		.minval	= -20,
		.maxval	= 19,
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
		.off1	= offsetof(struct thread_options, ioprio),
		.help	= "Set job IO priority value",
		.minval	= IOPRIO_MIN_PRIO,
		.maxval	= IOPRIO_MAX_PRIO,
		.interval = 1,
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_CRED,
	},
#else
	{
		.name	= "prio",
		.lname	= "I/O nice priority",
		.type	= FIO_OPT_UNSUPPORTED,
		.help	= "Your platform does not support IO priorities",
	},
#endif
#ifdef FIO_HAVE_IOPRIO_CLASS
#ifndef FIO_HAVE_IOPRIO
#error "FIO_HAVE_IOPRIO_CLASS requires FIO_HAVE_IOPRIO"
#endif
	{
		.name	= "prioclass",
		.lname	= "I/O nice priority class",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct thread_options, ioprio_class),
		.help	= "Set job IO priority class",
		.minval	= IOPRIO_MIN_PRIO_CLASS,
		.maxval	= IOPRIO_MAX_PRIO_CLASS,
		.interval = 1,
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_CRED,
	},
#else
	{
		.name	= "prioclass",
		.lname	= "I/O nice priority class",
		.type	= FIO_OPT_UNSUPPORTED,
		.help	= "Your platform does not support IO priority classes",
	},
#endif
	{
		.name	= "thinktime",
		.lname	= "Thinktime",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct thread_options, thinktime),
		.help	= "Idle time between IO buffers (usec)",
		.def	= "0",
		.is_time = 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_THINKTIME,
	},
	{
		.name	= "thinktime_spin",
		.lname	= "Thinktime spin",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct thread_options, thinktime_spin),
		.help	= "Start think time by spinning this amount (usec)",
		.def	= "0",
		.is_time = 1,
		.parent	= "thinktime",
		.hide	= 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_THINKTIME,
	},
	{
		.name	= "thinktime_blocks",
		.lname	= "Thinktime blocks",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct thread_options, thinktime_blocks),
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
		.off1	= offsetof(struct thread_options, rate[DDIR_READ]),
		.off2	= offsetof(struct thread_options, rate[DDIR_WRITE]),
		.off3	= offsetof(struct thread_options, rate[DDIR_TRIM]),
		.help	= "Set bandwidth rate",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_RATE,
	},
	{
		.name	= "rate_min",
		.alias	= "ratemin",
		.lname	= "I/O min rate",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct thread_options, ratemin[DDIR_READ]),
		.off2	= offsetof(struct thread_options, ratemin[DDIR_WRITE]),
		.off3	= offsetof(struct thread_options, ratemin[DDIR_TRIM]),
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
		.off1	= offsetof(struct thread_options, rate_iops[DDIR_READ]),
		.off2	= offsetof(struct thread_options, rate_iops[DDIR_WRITE]),
		.off3	= offsetof(struct thread_options, rate_iops[DDIR_TRIM]),
		.help	= "Limit IO used to this number of IO operations/sec",
		.hide	= 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_RATE,
	},
	{
		.name	= "rate_iops_min",
		.lname	= "I/O min rate IOPS",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct thread_options, rate_iops_min[DDIR_READ]),
		.off2	= offsetof(struct thread_options, rate_iops_min[DDIR_WRITE]),
		.off3	= offsetof(struct thread_options, rate_iops_min[DDIR_TRIM]),
		.help	= "Job must meet this rate or it will be shut down",
		.parent	= "rate_iops",
		.hide	= 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_RATE,
	},
	{
		.name	= "rate_process",
		.lname	= "Rate Process",
		.type	= FIO_OPT_STR,
		.off1	= offsetof(struct thread_options, rate_process),
		.help	= "What process controls how rated IO is managed",
		.def	= "linear",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_RATE,
		.posval = {
			  { .ival = "linear",
			    .oval = RATE_PROCESS_LINEAR,
			    .help = "Linear rate of IO",
			  },
			  {
			    .ival = "poisson",
			    .oval = RATE_PROCESS_POISSON,
			    .help = "Rate follows Poisson process",
			  },
		},
		.parent = "rate",
	},
	{
		.name	= "rate_cycle",
		.alias	= "ratecycle",
		.lname	= "I/O rate cycle",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct thread_options, ratecycle),
		.help	= "Window average for rate limits (msec)",
		.def	= "1000",
		.parent = "rate",
		.hide	= 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_RATE,
	},
	{
		.name	= "rate_ignore_thinktime",
		.lname	= "Rate ignore thinktime",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, rate_ign_think),
		.help	= "Rated IO ignores thinktime settings",
		.parent = "rate",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_RATE,
	},
	{
		.name	= "max_latency",
		.lname	= "Max Latency (usec)",
		.type	= FIO_OPT_STR_VAL_TIME,
		.off1	= offsetof(struct thread_options, max_latency),
		.help	= "Maximum tolerated IO latency (usec)",
		.is_time = 1,
		.category = FIO_OPT_C_IO,
		.group = FIO_OPT_G_LATPROF,
	},
	{
		.name	= "latency_target",
		.lname	= "Latency Target (usec)",
		.type	= FIO_OPT_STR_VAL_TIME,
		.off1	= offsetof(struct thread_options, latency_target),
		.help	= "Ramp to max queue depth supporting this latency",
		.is_time = 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_LATPROF,
	},
	{
		.name	= "latency_window",
		.lname	= "Latency Window (usec)",
		.type	= FIO_OPT_STR_VAL_TIME,
		.off1	= offsetof(struct thread_options, latency_window),
		.help	= "Time to sustain latency_target",
		.is_time = 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_LATPROF,
	},
	{
		.name	= "latency_percentile",
		.lname	= "Latency Percentile",
		.type	= FIO_OPT_FLOAT_LIST,
		.off1	= offsetof(struct thread_options, latency_percentile),
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
		.off1	= offsetof(struct thread_options, invalidate_cache),
		.help	= "Invalidate buffer/page cache prior to running job",
		.def	= "1",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_TYPE,
	},
	{
		.name	= "sync",
		.lname	= "Synchronous I/O",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, sync_io),
		.help	= "Use O_SYNC for buffered writes",
		.def	= "0",
		.parent = "buffered",
		.hide	= 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_TYPE,
	},
#ifdef FIO_HAVE_WRITE_HINT
	{
		.name	= "write_hint",
		.lname	= "Write hint",
		.type	= FIO_OPT_STR,
		.off1	= offsetof(struct thread_options, write_hint),
		.help	= "Set expected write life time",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_INVALID,
		.posval = {
			  { .ival = "none",
			    .oval = RWH_WRITE_LIFE_NONE,
			  },
			  { .ival = "short",
			    .oval = RWH_WRITE_LIFE_SHORT,
			  },
			  { .ival = "medium",
			    .oval = RWH_WRITE_LIFE_MEDIUM,
			  },
			  { .ival = "long",
			    .oval = RWH_WRITE_LIFE_LONG,
			  },
			  { .ival = "extreme",
			    .oval = RWH_WRITE_LIFE_EXTREME,
			  },
		},
	},
#endif
	{
		.name	= "create_serialize",
		.lname	= "Create serialize",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, create_serialize),
		.help	= "Serialize creation of job files",
		.def	= "1",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "create_fsync",
		.lname	= "Create fsync",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, create_fsync),
		.help	= "fsync file after creation",
		.def	= "1",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "create_on_open",
		.lname	= "Create on open",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, create_on_open),
		.help	= "Create files when they are opened for IO",
		.def	= "0",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "create_only",
		.lname	= "Create Only",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, create_only),
		.help	= "Only perform file creation phase",
		.category = FIO_OPT_C_FILE,
		.def	= "0",
	},
	{
		.name	= "allow_file_create",
		.lname	= "Allow file create",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, allow_create),
		.help	= "Permit fio to create files, if they don't exist",
		.def	= "1",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_FILENAME,
	},
	{
		.name	= "allow_mounted_write",
		.lname	= "Allow mounted write",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, allow_mounted_write),
		.help	= "Allow writes to a mounted partition",
		.def	= "0",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_FILENAME,
	},
	{
		.name	= "pre_read",
		.lname	= "Pre-read files",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, pre_read),
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
		.off1	= offsetof(struct thread_options, cpumask),
		.help	= "CPU affinity mask",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_CRED,
	},
	{
		.name	= "cpus_allowed",
		.lname	= "CPUs allowed",
		.type	= FIO_OPT_STR,
		.cb	= str_cpus_allowed_cb,
		.off1	= offsetof(struct thread_options, cpumask),
		.help	= "Set CPUs allowed",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_CRED,
	},
	{
		.name	= "cpus_allowed_policy",
		.lname	= "CPUs allowed distribution policy",
		.type	= FIO_OPT_STR,
		.off1	= offsetof(struct thread_options, cpus_allowed_policy),
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
#else
	{
		.name	= "cpumask",
		.lname	= "CPU mask",
		.type	= FIO_OPT_UNSUPPORTED,
		.help	= "Your platform does not support CPU affinities",
	},
	{
		.name	= "cpus_allowed",
		.lname	= "CPUs allowed",
		.type	= FIO_OPT_UNSUPPORTED,
		.help	= "Your platform does not support CPU affinities",
	},
	{
		.name	= "cpus_allowed_policy",
		.lname	= "CPUs allowed distribution policy",
		.type	= FIO_OPT_UNSUPPORTED,
		.help	= "Your platform does not support CPU affinities",
	},
#endif
#ifdef CONFIG_LIBNUMA
	{
		.name	= "numa_cpu_nodes",
		.lname	= "NUMA CPU Nodes",
		.type	= FIO_OPT_STR,
		.cb	= str_numa_cpunodes_cb,
		.off1	= offsetof(struct thread_options, numa_cpunodes),
		.help	= "NUMA CPU nodes bind",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "numa_mem_policy",
		.lname	= "NUMA Memory Policy",
		.type	= FIO_OPT_STR,
		.cb	= str_numa_mpol_cb,
		.off1	= offsetof(struct thread_options, numa_memnodes),
		.help	= "NUMA memory policy setup",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_INVALID,
	},
#else
	{
		.name	= "numa_cpu_nodes",
		.lname	= "NUMA CPU Nodes",
		.type	= FIO_OPT_UNSUPPORTED,
		.help	= "Build fio with libnuma-dev(el) to enable this option",
	},
	{
		.name	= "numa_mem_policy",
		.lname	= "NUMA Memory Policy",
		.type	= FIO_OPT_UNSUPPORTED,
		.help	= "Build fio with libnuma-dev(el) to enable this option",
	},
#endif
#ifdef CONFIG_CUDA
	{
		.name	= "gpu_dev_id",
		.lname	= "GPU device ID",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct thread_options, gpu_dev_id),
		.help	= "Set GPU device ID for GPUDirect RDMA",
		.def    = "0",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_INVALID,
	},
#endif
	{
		.name	= "end_fsync",
		.lname	= "End fsync",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, end_fsync),
		.help	= "Include fsync at the end of job",
		.def	= "0",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "fsync_on_close",
		.lname	= "Fsync on close",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, fsync_on_close),
		.help	= "fsync files on close",
		.def	= "0",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "unlink",
		.lname	= "Unlink file",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, unlink),
		.help	= "Unlink created files after job has completed",
		.def	= "0",
		.category = FIO_OPT_C_FILE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "unlink_each_loop",
		.lname	= "Unlink file after each loop of a job",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, unlink_each_loop),
		.help	= "Unlink created files after each loop in a job has completed",
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
		.name	= "exit_what",
		.lname	= "What jobs to quit on terminate",
		.type	= FIO_OPT_STR,
		.off1	= offsetof(struct thread_options, exit_what),
		.help	= "Fine-grained control for exitall",
		.def	= "group",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_PROCESS,
		.posval	= {
			  { .ival = "group",
			    .oval = TERMINATE_GROUP,
			    .help = "exit_all=1 default behaviour",
			  },
			  { .ival = "stonewall",
			    .oval = TERMINATE_STONEWALL,
			    .help = "quit all currently running jobs; continue with next stonewall",
			  },
			  { .ival = "all",
			    .oval = TERMINATE_ALL,
			    .help = "Quit everything",
			  },
		},
	},
	{
		.name	= "exitall_on_error",
		.lname	= "Exit-all on terminate in error",
		.type	= FIO_OPT_STR_SET,
		.off1	= offsetof(struct thread_options, exitall_error),
		.help	= "Terminate all jobs when one exits in error",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_PROCESS,
	},
	{
		.name	= "stonewall",
		.lname	= "Wait for previous",
		.alias	= "wait_for_previous",
		.type	= FIO_OPT_STR_SET,
		.off1	= offsetof(struct thread_options, stonewall),
		.help	= "Insert a hard barrier between this job and previous",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_PROCESS,
	},
	{
		.name	= "new_group",
		.lname	= "New group",
		.type	= FIO_OPT_STR_SET,
		.off1	= offsetof(struct thread_options, new_group),
		.help	= "Mark the start of a new group (for reporting)",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_PROCESS,
	},
	{
		.name	= "thread",
		.lname	= "Thread",
		.type	= FIO_OPT_STR_SET,
		.off1	= offsetof(struct thread_options, use_thread),
		.help	= "Use threads instead of processes",
#ifdef CONFIG_NO_SHM
		.def	= "1",
		.no_warn_def = 1,
#endif
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_PROCESS,
	},
	{
		.name	= "per_job_logs",
		.lname	= "Per Job Logs",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, per_job_logs),
		.help	= "Include job number in generated log files or not",
		.def	= "1",
		.category = FIO_OPT_C_LOG,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "write_bw_log",
		.lname	= "Write bandwidth log",
		.type	= FIO_OPT_STR,
		.off1	= offsetof(struct thread_options, bw_log_file),
		.cb	= str_write_bw_log_cb,
		.help	= "Write log of bandwidth during run",
		.category = FIO_OPT_C_LOG,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "write_lat_log",
		.lname	= "Write latency log",
		.type	= FIO_OPT_STR,
		.off1	= offsetof(struct thread_options, lat_log_file),
		.cb	= str_write_lat_log_cb,
		.help	= "Write log of latency during run",
		.category = FIO_OPT_C_LOG,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "write_iops_log",
		.lname	= "Write IOPS log",
		.type	= FIO_OPT_STR,
		.off1	= offsetof(struct thread_options, iops_log_file),
		.cb	= str_write_iops_log_cb,
		.help	= "Write log of IOPS during run",
		.category = FIO_OPT_C_LOG,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "log_avg_msec",
		.lname	= "Log averaging (msec)",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct thread_options, log_avg_msec),
		.help	= "Average bw/iops/lat logs over this period of time",
		.def	= "0",
		.category = FIO_OPT_C_LOG,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "log_hist_msec",
		.lname	= "Log histograms (msec)",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct thread_options, log_hist_msec),
		.help	= "Dump completion latency histograms at frequency of this time value",
		.def	= "0",
		.category = FIO_OPT_C_LOG,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "log_hist_coarseness",
		.lname	= "Histogram logs coarseness",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct thread_options, log_hist_coarseness),
		.help	= "Integer in range [0,6]. Higher coarseness outputs"
			" fewer histogram bins per sample. The number of bins for"
			" these are [1216, 608, 304, 152, 76, 38, 19] respectively.",
		.def	= "0",
		.category = FIO_OPT_C_LOG,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "write_hist_log",
		.lname	= "Write latency histogram logs",
		.type	= FIO_OPT_STR,
		.off1	= offsetof(struct thread_options, hist_log_file),
		.cb	= str_write_hist_log_cb,
		.help	= "Write log of latency histograms during run",
		.category = FIO_OPT_C_LOG,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "log_max_value",
		.lname	= "Log maximum instead of average",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, log_max),
		.help	= "Log max sample in a window instead of average",
		.def	= "0",
		.category = FIO_OPT_C_LOG,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "log_offset",
		.lname	= "Log offset of IO",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, log_offset),
		.help	= "Include offset of IO for each log entry",
		.def	= "0",
		.category = FIO_OPT_C_LOG,
		.group	= FIO_OPT_G_INVALID,
	},
#ifdef CONFIG_ZLIB
	{
		.name	= "log_compression",
		.lname	= "Log compression",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct thread_options, log_gz),
		.help	= "Log in compressed chunks of this size",
		.minval	= 1024ULL,
		.maxval	= 512 * 1024 * 1024ULL,
		.category = FIO_OPT_C_LOG,
		.group	= FIO_OPT_G_INVALID,
	},
#ifdef FIO_HAVE_CPU_AFFINITY
	{
		.name	= "log_compression_cpus",
		.lname	= "Log Compression CPUs",
		.type	= FIO_OPT_STR,
		.cb	= str_log_cpus_allowed_cb,
		.off1	= offsetof(struct thread_options, log_gz_cpumask),
		.parent = "log_compression",
		.help	= "Limit log compression to these CPUs",
		.category = FIO_OPT_C_LOG,
		.group	= FIO_OPT_G_INVALID,
	},
#else
	{
		.name	= "log_compression_cpus",
		.lname	= "Log Compression CPUs",
		.type	= FIO_OPT_UNSUPPORTED,
		.help	= "Your platform does not support CPU affinities",
	},
#endif
	{
		.name	= "log_store_compressed",
		.lname	= "Log store compressed",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, log_gz_store),
		.help	= "Store logs in a compressed format",
		.category = FIO_OPT_C_LOG,
		.group	= FIO_OPT_G_INVALID,
	},
#else
	{
		.name	= "log_compression",
		.lname	= "Log compression",
		.type	= FIO_OPT_UNSUPPORTED,
		.help	= "Install libz-dev(el) to get compression support",
	},
	{
		.name	= "log_store_compressed",
		.lname	= "Log store compressed",
		.type	= FIO_OPT_UNSUPPORTED,
		.help	= "Install libz-dev(el) to get compression support",
	},
#endif
	{
		.name = "log_unix_epoch",
		.lname = "Log epoch unix",
		.type = FIO_OPT_BOOL,
		.off1 = offsetof(struct thread_options, log_unix_epoch),
		.help = "Use Unix time in log files",
		.category = FIO_OPT_C_LOG,
		.group = FIO_OPT_G_INVALID,
	},
	{
		.name	= "block_error_percentiles",
		.lname	= "Block error percentiles",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, block_error_hist),
		.help	= "Record trim block errors and make a histogram",
		.def	= "0",
		.category = FIO_OPT_C_LOG,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "bwavgtime",
		.lname	= "Bandwidth average time",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct thread_options, bw_avg_time),
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
		.off1	= offsetof(struct thread_options, iops_avg_time),
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
		.off1	= offsetof(struct thread_options, group_reporting),
		.help	= "Do reporting on a per-group basis",
		.category = FIO_OPT_C_STAT,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "stats",
		.lname	= "Stats",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, stats),
		.help	= "Enable collection of stats",
		.def	= "1",
		.category = FIO_OPT_C_STAT,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "zero_buffers",
		.lname	= "Zero I/O buffers",
		.type	= FIO_OPT_STR_SET,
		.off1	= offsetof(struct thread_options, zero_buffers),
		.help	= "Init IO buffers to all zeroes",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_BUF,
	},
	{
		.name	= "refill_buffers",
		.lname	= "Refill I/O buffers",
		.type	= FIO_OPT_STR_SET,
		.off1	= offsetof(struct thread_options, refill_buffers),
		.help	= "Refill IO buffers on every IO submit",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_BUF,
	},
	{
		.name	= "scramble_buffers",
		.lname	= "Scramble I/O buffers",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, scramble_buffers),
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
		.off1	= offsetof(struct thread_options, buffer_pattern),
		.help	= "Fill pattern for IO buffers",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_BUF,
	},
	{
		.name	= "buffer_compress_percentage",
		.lname	= "Buffer compression percentage",
		.type	= FIO_OPT_INT,
		.cb	= str_buffer_compress_cb,
		.off1	= offsetof(struct thread_options, compress_percentage),
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
		.off1	= offsetof(struct thread_options, compress_chunk),
		.parent	= "buffer_compress_percentage",
		.hide	= 1,
		.help	= "Size of compressible region in buffer",
		.def	= "512",
		.interval = 256,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_BUF,
	},
	{
		.name	= "dedupe_percentage",
		.lname	= "Dedupe percentage",
		.type	= FIO_OPT_INT,
		.cb	= str_dedupe_cb,
		.off1	= offsetof(struct thread_options, dedupe_percentage),
		.maxval	= 100,
		.minval	= 0,
		.help	= "Percentage of buffers that are dedupable",
		.interval = 1,
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_BUF,
	},
	{
		.name	= "clat_percentiles",
		.lname	= "Completion latency percentiles",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, clat_percentiles),
		.help	= "Enable the reporting of completion latency percentiles",
		.def	= "1",
		.category = FIO_OPT_C_STAT,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "lat_percentiles",
		.lname	= "IO latency percentiles",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, lat_percentiles),
		.help	= "Enable the reporting of IO latency percentiles",
		.def	= "0",
		.category = FIO_OPT_C_STAT,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "slat_percentiles",
		.lname	= "Submission latency percentiles",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, slat_percentiles),
		.help	= "Enable the reporting of submission latency percentiles",
		.def	= "0",
		.category = FIO_OPT_C_STAT,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "percentile_list",
		.lname	= "Percentile list",
		.type	= FIO_OPT_FLOAT_LIST,
		.off1	= offsetof(struct thread_options, percentile_list),
		.off2	= offsetof(struct thread_options, percentile_precision),
		.help	= "Specify a custom list of percentiles to report for "
			  "completion latency and block errors",
		.def    = "1:5:10:20:30:40:50:60:70:80:90:95:99:99.5:99.9:99.95:99.99",
		.maxlen	= FIO_IO_U_LIST_MAX_LEN,
		.minfp	= 0.0,
		.maxfp	= 100.0,
		.category = FIO_OPT_C_STAT,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "significant_figures",
		.lname	= "Significant figures",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct thread_options, sig_figs),
		.maxval	= 10,
		.minval	= 1,
		.help	= "Significant figures for output-format set to normal",
		.def	= "4",
		.interval = 1,
		.category = FIO_OPT_C_STAT,
		.group	= FIO_OPT_G_INVALID,
	},

#ifdef FIO_HAVE_DISK_UTIL
	{
		.name	= "disk_util",
		.lname	= "Disk utilization",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, do_disk_util),
		.help	= "Log disk utilization statistics",
		.def	= "1",
		.category = FIO_OPT_C_STAT,
		.group	= FIO_OPT_G_INVALID,
	},
#else
	{
		.name	= "disk_util",
		.lname	= "Disk utilization",
		.type	= FIO_OPT_UNSUPPORTED,
		.help	= "Your platform does not support disk utilization",
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
		.off1	= offsetof(struct thread_options, disable_lat),
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
		.off1	= offsetof(struct thread_options, disable_clat),
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
		.off1	= offsetof(struct thread_options, disable_slat),
		.help	= "Disable submission latency numbers",
		.parent	= "gtod_reduce",
		.hide	= 1,
		.def	= "0",
		.category = FIO_OPT_C_STAT,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "disable_bw_measurement",
		.alias	= "disable_bw",
		.lname	= "Disable bandwidth stats",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, disable_bw),
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
		.off1	= offsetof(struct thread_options, gtod_cpu),
		.help	= "Set up dedicated gettimeofday() thread on this CPU",
		.verify	= gtod_cpu_verify,
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_CLOCK,
	},
	{
		.name	= "unified_rw_reporting",
		.lname	= "Unified RW Reporting",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, unified_rw_rep),
		.help	= "Unify reporting across data direction",
		.def	= "0",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "continue_on_error",
		.lname	= "Continue on error",
		.type	= FIO_OPT_STR,
		.off1	= offsetof(struct thread_options, continue_on_error),
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
		.lname	= "Ignore Error",
		.type	= FIO_OPT_STR,
		.cb	= str_ignore_error_cb,
		.off1	= offsetof(struct thread_options, ignore_error_nr),
		.help	= "Set a specific list of errors to ignore",
		.parent	= "rw",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_ERR,
	},
	{
		.name	= "error_dump",
		.lname	= "Error Dump",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, error_dump),
		.def	= "0",
		.help	= "Dump info on each error",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_ERR,
	},
	{
		.name	= "profile",
		.lname	= "Profile",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct thread_options, profile),
		.help	= "Select a specific builtin performance test",
		.category = FIO_OPT_C_PROFILE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "cgroup",
		.lname	= "Cgroup",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct thread_options, cgroup),
		.help	= "Add job to cgroup of this name",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_CGROUP,
	},
	{
		.name	= "cgroup_nodelete",
		.lname	= "Cgroup no-delete",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct thread_options, cgroup_nodelete),
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
		.off1	= offsetof(struct thread_options, cgroup_weight),
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
		.off1	= offsetof(struct thread_options, uid),
		.help	= "Run job with this user ID",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_CRED,
	},
	{
		.name	= "gid",
		.lname	= "Group ID",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct thread_options, gid),
		.help	= "Run job with this group ID",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_CRED,
	},
	{
		.name	= "kb_base",
		.lname	= "KB Base",
		.type	= FIO_OPT_STR,
		.off1	= offsetof(struct thread_options, kb_base),
		.prio	= 1,
		.def	= "1024",
		.posval = {
			  { .ival = "1024",
			    .oval = 1024,
			    .help = "Inputs invert IEC and SI prefixes (for compatibility); outputs prefer binary",
			  },
			  { .ival = "1000",
			    .oval = 1000,
			    .help = "Inputs use IEC and SI prefixes; outputs prefer SI",
			  },
		},
		.help	= "Unit prefix interpretation for quantities of data (IEC and SI)",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "unit_base",
		.lname	= "Unit for quantities of data (Bits or Bytes)",
		.type	= FIO_OPT_STR,
		.off1	= offsetof(struct thread_options, unit_base),
		.prio	= 1,
		.posval = {
			  { .ival = "0",
			    .oval = N2S_NONE,
			    .help = "Auto-detect",
			  },
			  { .ival = "8",
			    .oval = N2S_BYTEPERSEC,
			    .help = "Normal (byte based)",
			  },
			  { .ival = "1",
			    .oval = N2S_BITPERSEC,
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
		.off1	= offsetof(struct thread_options, hugepage_size),
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
		.off1	= offsetof(struct thread_options, flow_id),
		.help	= "The flow index ID to use",
		.def	= "0",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_FLOW,
	},
	{
		.name	= "flow",
		.lname	= "I/O flow weight",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct thread_options, flow),
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
		.off1	= offsetof(struct thread_options, flow_watermark),
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
		.off1	= offsetof(struct thread_options, flow_sleep),
		.help	= "How many microseconds to sleep after being held"
			" back by the flow control mechanism",
		.parent	= "flow_id",
		.hide	= 1,
		.def	= "0",
		.category = FIO_OPT_C_IO,
		.group	= FIO_OPT_G_IO_FLOW,
	},
	{
		.name   = "steadystate",
		.lname  = "Steady state threshold",
		.alias  = "ss",
		.type   = FIO_OPT_STR,
		.off1   = offsetof(struct thread_options, ss_state),
		.cb	= str_steadystate_cb,
		.help   = "Define the criterion and limit to judge when a job has reached steady state",
		.def	= "iops_slope:0.01%",
		.posval	= {
			  { .ival = "iops",
			    .oval = FIO_SS_IOPS,
			    .help = "maximum mean deviation of IOPS measurements",
			  },
			  { .ival = "iops_slope",
			    .oval = FIO_SS_IOPS_SLOPE,
			    .help = "slope calculated from IOPS measurements",
			  },
			  { .ival = "bw",
			    .oval = FIO_SS_BW,
			    .help = "maximum mean deviation of bandwidth measurements",
			  },
			  {
			    .ival = "bw_slope",
			    .oval = FIO_SS_BW_SLOPE,
			    .help = "slope calculated from bandwidth measurements",
			  },
		},
		.category = FIO_OPT_C_GENERAL,
		.group  = FIO_OPT_G_RUNTIME,
	},
        {
		.name   = "steadystate_duration",
		.lname  = "Steady state duration",
		.alias  = "ss_dur",
		.parent	= "steadystate",
		.type   = FIO_OPT_STR_VAL_TIME,
		.off1   = offsetof(struct thread_options, ss_dur),
		.help   = "Stop workload upon attaining steady state for specified duration",
		.def    = "0",
		.is_seconds = 1,
		.is_time = 1,
		.category = FIO_OPT_C_GENERAL,
		.group  = FIO_OPT_G_RUNTIME,
	},
        {
		.name   = "steadystate_ramp_time",
		.lname  = "Steady state ramp time",
		.alias  = "ss_ramp",
		.parent	= "steadystate",
		.type   = FIO_OPT_STR_VAL_TIME,
		.off1   = offsetof(struct thread_options, ss_ramp_time),
		.help   = "Delay before initiation of data collection for steady state job termination testing",
		.def    = "0",
		.is_seconds = 1,
		.is_time = 1,
		.category = FIO_OPT_C_GENERAL,
		.group  = FIO_OPT_G_RUNTIME,
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

void fio_keywords_exit(void)
{
	struct fio_keyword *kw;

	kw = &fio_keywords[0];
	while (kw->word) {
		free(kw->replace);
		kw->replace = NULL;
		kw++;
	}
}

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
char *fio_option_dup_subs(const char *opt)
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

	snprintf(in, sizeof(in), "%s", opt);

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
		opts_copy[i] = fio_option_dup_subs(opts[i]);
		if (!opts_copy[i])
			continue;
		opts_copy[i] = fio_keyword_replace(opts_copy[i]);
	}
	return opts_copy;
}

static void show_closest_option(const char *opt)
{
	int best_option, best_distance;
	int i, distance;
	char *name;

	if (!strlen(opt))
		return;

	name = strdup(opt);
	i = 0;
	while (name[i] != '\0' && name[i] != '=')
		i++;
	name[i] = '\0';

	best_option = -1;
	best_distance = INT_MAX;
	i = 0;
	while (fio_options[i].name) {
		distance = string_distance(name, fio_options[i].name);
		if (distance < best_distance) {
			best_distance = distance;
			best_option = i;
		}
		i++;
	}

	if (best_option != -1 && string_distance_ok(name, best_distance) &&
	    fio_options[best_option].type != FIO_OPT_UNSUPPORTED)
		log_err("Did you mean %s?\n", fio_options[best_option].name);

	free(name);
}

int fio_options_parse(struct thread_data *td, char **opts, int num_opts)
{
	int i, ret, unknown;
	char **opts_copy;

	sort_options(opts, fio_options, num_opts);
	opts_copy = dup_and_sub_options(opts, num_opts);

	for (ret = 0, i = 0, unknown = 0; i < num_opts; i++) {
		const struct fio_option *o;
		int newret = parse_option(opts_copy[i], opts[i], fio_options,
						&o, &td->o, &td->opt_list);

		if (!newret && o)
			fio_option_mark_set(&td->o, o);

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
			const struct fio_option *o = NULL;
			int newret = 1;

			if (!opts_copy[i])
				continue;

			if (td->eo)
				newret = parse_option(opts_copy[i], opts[i],
						      td->io_ops->options, &o,
						      td->eo, &td->opt_list);

			ret |= newret;
			if (!o) {
				log_err("Bad option <%s>\n", opts[i]);
				show_closest_option(opts[i]);
			}
			free(opts_copy[i]);
			opts_copy[i] = NULL;
		}
	}

	free(opts_copy);
	return ret;
}

int fio_cmd_option_parse(struct thread_data *td, const char *opt, char *val)
{
	int ret;

	ret = parse_cmd_option(opt, val, fio_options, &td->o, &td->opt_list);
	if (!ret) {
		const struct fio_option *o;

		o = find_option_c(fio_options, opt);
		if (o)
			fio_option_mark_set(&td->o, o);
	}

	return ret;
}

int fio_cmd_ioengine_option_parse(struct thread_data *td, const char *opt,
				char *val)
{
	return parse_cmd_option(opt, val, td->io_ops->options, td->eo,
					&td->opt_list);
}

void fio_fill_default_options(struct thread_data *td)
{
	td->o.magic = OPT_MAGIC;
	fill_default_options(&td->o, fio_options);
}

int fio_show_option_help(const char *opt)
{
	return show_cmd_help(fio_options, opt);
}

/*
 * dupe FIO_OPT_STR_STORE options
 */
void fio_options_mem_dupe(struct thread_data *td)
{
	options_mem_dupe(fio_options, &td->o);

	if (td->eo && td->io_ops) {
		void *oldeo = td->eo;

		td->eo = malloc(td->io_ops->option_struct_size);
		memcpy(td->eo, oldeo, td->io_ops->option_struct_size);
		options_mem_dupe(td->io_ops->options, td->eo);
	}
}

unsigned int fio_get_kb_base(void *data)
{
	struct thread_data *td = cb_data_to_td(data);
	struct thread_options *o = &td->o;
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

int add_option(const struct fio_option *o)
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
	options_free(fio_options, &td->o);
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

static struct fio_option *find_next_opt(struct fio_option *from,
					unsigned int off1)
{
	struct fio_option *opt;

	if (!from)
		from = &fio_options[0];
	else
		from++;

	opt = NULL;
	do {
		if (off1 == from->off1) {
			opt = from;
			break;
		}
		from++;
	} while (from->name);

	return opt;
}

static int opt_is_set(struct thread_options *o, struct fio_option *opt)
{
	unsigned int opt_off, index, offset;

	opt_off = opt - &fio_options[0];
	index = opt_off / (8 * sizeof(uint64_t));
	offset = opt_off & ((8 * sizeof(uint64_t)) - 1);
	return (o->set_options[index] & ((uint64_t)1 << offset)) != 0;
}

bool __fio_option_is_set(struct thread_options *o, unsigned int off1)
{
	struct fio_option *opt, *next;

	next = NULL;
	while ((opt = find_next_opt(next, off1)) != NULL) {
		if (opt_is_set(o, opt))
			return true;

		next = opt;
	}

	return false;
}

void fio_option_mark_set(struct thread_options *o, const struct fio_option *opt)
{
	unsigned int opt_off, index, offset;

	opt_off = opt - &fio_options[0];
	index = opt_off / (8 * sizeof(uint64_t));
	offset = opt_off & ((8 * sizeof(uint64_t)) - 1);
	o->set_options[index] |= (uint64_t)1 << offset;
}
