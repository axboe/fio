/*
 * This file contains the ini and command liner parser main.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <math.h>
#include <float.h>

#include "parse.h"
#include "debug.h"
#include "options.h"
#include "optgroup.h"
#include "minmax.h"
#include "lib/ieee754.h"
#include "lib/pow2.h"

#ifdef CONFIG_ARITHMETIC
#include "y.tab.h"
#endif

static struct fio_option *__fio_options;

static int vp_cmp(const void *p1, const void *p2)
{
	const struct value_pair *vp1 = p1;
	const struct value_pair *vp2 = p2;

	return strlen(vp2->ival) - strlen(vp1->ival);
}

static void posval_sort(struct fio_option *o, struct value_pair *vpmap)
{
	const struct value_pair *vp;
	int entries;

	memset(vpmap, 0, PARSE_MAX_VP * sizeof(struct value_pair));

	for (entries = 0; entries < PARSE_MAX_VP; entries++) {
		vp = &o->posval[entries];
		if (!vp->ival || vp->ival[0] == '\0')
			break;

		memcpy(&vpmap[entries], vp, sizeof(*vp));
	}

	qsort(vpmap, entries, sizeof(struct value_pair), vp_cmp);
}

static void show_option_range(struct fio_option *o,
			      size_t (*logger)(const char *format, ...))
{
	if (o->type == FIO_OPT_FLOAT_LIST) {
		if (o->minfp == DBL_MIN && o->maxfp == DBL_MAX)
			return;

		logger("%20s: min=%f", "range", o->minfp);
		if (o->maxfp != DBL_MAX)
			logger(", max=%f", o->maxfp);
		logger("\n");
	} else if (!o->posval[0].ival) {
		if (!o->minval && !o->maxval)
			return;

		logger("%20s: min=%d", "range", o->minval);
		if (o->maxval)
			logger(", max=%d", o->maxval);
		logger("\n");
	}
}

static void show_option_values(struct fio_option *o)
{
	int i;

	for (i = 0; i < PARSE_MAX_VP; i++) {
		const struct value_pair *vp = &o->posval[i];

		if (!vp->ival)
			continue;

		log_info("%20s: %-10s", i == 0 ? "valid values" : "", vp->ival);
		if (vp->help)
			log_info(" %s", vp->help);
		log_info("\n");
	}

	if (i)
		log_info("\n");
}

static void show_option_help(struct fio_option *o, int is_err)
{
	const char *typehelp[] = {
		"invalid",
		"string (opt=bla)",
		"string (opt=bla)",
		"string with possible k/m/g postfix (opt=4k)",
		"string with time postfix (opt=10s)",
		"string (opt=bla)",
		"string with dual range (opt=1k-4k,4k-8k)",
		"integer value (opt=100)",
		"boolean value (opt=1)",
		"list of floating point values separated by ':' (opt=5.9:7.8)",
		"no argument (opt)",
		"deprecated",
		"unsupported",
	};
	size_t (*logger)(const char *format, ...);

	if (is_err)
		logger = log_err;
	else
		logger = log_info;

	if (o->alias)
		logger("%20s: %s\n", "alias", o->alias);

	logger("%20s: %s\n", "type", typehelp[o->type]);
	logger("%20s: %s\n", "default", o->def ? o->def : "no default");
	if (o->prof_name)
		logger("%20s: only for profile '%s'\n", "valid", o->prof_name);
	show_option_range(o, logger);
	show_option_values(o);
}

static unsigned long long get_mult_time(const char *str, int len,
					int is_seconds)
{
	const char *p = str;
	char *c;
	unsigned long long mult = 1;
	int i;

	/*
         * Go forward until we hit a non-digit, or +/- sign
         */
	while ((p - str) <= len) {
		if (!isdigit((int) *p) && (*p != '+') && (*p != '-'))
			break;
		p++;
	}

	if (!isalpha((int) *p)) {
		if (is_seconds)
			return 1000000UL;
		else
			return 1;
	}

	c = strdup(p);
	for (i = 0; i < strlen(c); i++)
		c[i] = tolower(c[i]);

	if (!strncmp("us", c, 2) || !strncmp("usec", c, 4))
		mult = 1;
	else if (!strncmp("ms", c, 2) || !strncmp("msec", c, 4))
		mult = 1000;
	else if (!strcmp("s", c))
		mult = 1000000;
	else if (!strcmp("m", c))
		mult = 60 * 1000000UL;
	else if (!strcmp("h", c))
		mult = 60 * 60 * 1000000UL;
	else if (!strcmp("d", c))
		mult = 24 * 60 * 60 * 1000000ULL;

	free(c);
	return mult;
}

static int is_separator(char c)
{
	switch (c) {
	case ':':
	case '-':
	case ',':
	case '/':
		return 1;
	default:
		return 0;
	}
}

static unsigned long long __get_mult_bytes(const char *p, void *data,
					   int *percent)
{
	unsigned int kb_base = fio_get_kb_base(data);
	unsigned long long ret = 1;
	unsigned int i, pow = 0, mult = kb_base;
	char *c;

	if (!p)
		return 1;

	c = strdup(p);

	for (i = 0; i < strlen(c); i++) {
		c[i] = tolower(c[i]);
		if (is_separator(c[i])) {
			c[i] = '\0';
			break;
		}
	}

	/* If kb_base is 1000, use true units.
	 * If kb_base is 1024, use opposite units.
	 */
	if (!strncmp("pib", c, 3)) {
		pow = 5;
		if (kb_base == 1000)
			mult = 1024;
		else if (kb_base == 1024)
			mult = 1000;
	} else if (!strncmp("tib", c, 3)) {
		pow = 4;
		if (kb_base == 1000)
			mult = 1024;
		else if (kb_base == 1024)
			mult = 1000;
	} else if (!strncmp("gib", c, 3)) {
		pow = 3;
		if (kb_base == 1000)
			mult = 1024;
		else if (kb_base == 1024)
			mult = 1000;
	} else if (!strncmp("mib", c, 3)) {
		pow = 2;
		if (kb_base == 1000)
			mult = 1024;
		else if (kb_base == 1024)
			mult = 1000;
	} else if (!strncmp("kib", c, 3)) {
		pow = 1;
		if (kb_base == 1000)
			mult = 1024;
		else if (kb_base == 1024)
			mult = 1000;
	} else if (!strncmp("p", c, 1) || !strncmp("pb", c, 2)) {
		pow = 5;
	} else if (!strncmp("t", c, 1) || !strncmp("tb", c, 2)) {
		pow = 4;
	} else if (!strncmp("g", c, 1) || !strncmp("gb", c, 2)) {
		pow = 3;
	} else if (!strncmp("m", c, 1) || !strncmp("mb", c, 2)) {
		pow = 2;
	} else if (!strncmp("k", c, 1) || !strncmp("kb", c, 2)) {
		pow = 1;
	} else if (!strncmp("%", c, 1)) {
		*percent = 1;
		free(c);
		return ret;
	}

	while (pow--)
		ret *= (unsigned long long) mult;

	free(c);
	return ret;
}

static unsigned long long get_mult_bytes(const char *str, int len, void *data,
					 int *percent)
{
	const char *p = str;
	int digit_seen = 0;

	if (len < 2)
		return __get_mult_bytes(str, data, percent);

	/*
	 * Go forward until we hit a non-digit, or +/- sign
	 */
	while ((p - str) <= len) {
		if (!isdigit((int) *p) &&
		    (((*p != '+') && (*p != '-')) || digit_seen))
			break;
		digit_seen |= isdigit((int) *p);
		p++;
	}

	if (!isalpha((int) *p) && (*p != '%'))
		p = NULL;

	return __get_mult_bytes(p, data, percent);
}

extern int evaluate_arithmetic_expression(const char *buffer, long long *ival,
					  double *dval, double implied_units,
					  int is_time);

/*
 * Convert string into a floating number. Return 1 for success and 0 otherwise.
 */
int str_to_float(const char *str, double *val, int is_time)
{
#ifdef CONFIG_ARITHMETIC
	int rc;
	long long ival;
	double dval;

	if (str[0] == '(') {
		rc = evaluate_arithmetic_expression(str, &ival, &dval, 1.0, is_time);
		if (!rc) {
			*val = dval;
			return 1;
		}
	}
#endif
	return 1 == sscanf(str, "%lf", val);
}

/*
 * convert string into decimal value, noting any size suffix
 */
int str_to_decimal(const char *str, long long *val, int kilo, void *data,
		   int is_seconds, int is_time)
{
	int len, base;
	int rc = 1;
#ifdef CONFIG_ARITHMETIC
	long long ival;
	double dval;
	double implied_units = 1.0;
#endif

	len = strlen(str);
	if (!len)
		return 1;

#ifdef CONFIG_ARITHMETIC
	if (is_seconds)
		implied_units = 1000000.0;
	if (str[0] == '(')
		rc = evaluate_arithmetic_expression(str, &ival, &dval, implied_units, is_time);
	if (str[0] == '(' && !rc) {
		if (!kilo && is_seconds)
			*val = ival / 1000000LL;
		else
			*val = ival;
	}
#endif

	if (rc == 1) {
		if (strstr(str, "0x") || strstr(str, "0X"))
			base = 16;
		else
			base = 10;

		*val = strtoll(str, NULL, base);
		if (*val == LONG_MAX && errno == ERANGE)
			return 1;
	}

	if (kilo) {
		unsigned long long mult;
		int perc = 0;

		mult = get_mult_bytes(str, len, data, &perc);
		if (perc)
			*val = -1ULL - *val;
		else
			*val *= mult;
	} else
		*val *= get_mult_time(str, len, is_seconds);

	return 0;
}

int check_str_bytes(const char *p, long long *val, void *data)
{
	return str_to_decimal(p, val, 1, data, 0, 0);
}

int check_str_time(const char *p, long long *val, int is_seconds)
{
	return str_to_decimal(p, val, 0, NULL, is_seconds, 1);
}

void strip_blank_front(char **p)
{
	char *s = *p;

	if (!strlen(s))
		return;
	while (isspace((int) *s))
		s++;

	*p = s;
}

void strip_blank_end(char *p)
{
	char *start = p, *s;

	if (!strlen(p))
		return;

	s = strchr(p, ';');
	if (s)
		*s = '\0';
	s = strchr(p, '#');
	if (s)
		*s = '\0';
	if (s)
		p = s;

	s = p + strlen(p);
	while ((isspace((int) *s) || iscntrl((int) *s)) && (s > start))
		s--;

	*(s + 1) = '\0';
}

static int check_range_bytes(const char *str, long *val, void *data)
{
	long long __val;

	if (!str_to_decimal(str, &__val, 1, data, 0, 0)) {
		*val = __val;
		return 0;
	}

	return 1;
}

static int check_int(const char *p, int *val)
{
	if (!strlen(p))
		return 1;
	if (strstr(p, "0x") || strstr(p, "0X")) {
		if (sscanf(p, "%x", val) == 1)
			return 0;
	} else {
		if (sscanf(p, "%u", val) == 1)
			return 0;
	}

	return 1;
}

static size_t opt_len(const char *str)
{
	char *postfix;

	postfix = strchr(str, ':');
	if (!postfix)
		return strlen(str);

	return (int)(postfix - str);
}

static int str_match_len(const struct value_pair *vp, const char *str)
{
	return max(strlen(vp->ival), opt_len(str));
}

#define val_store(ptr, val, off, or, data, o)		\
	do {						\
		ptr = td_var((data), (o), (off));	\
		if ((or))				\
			*ptr |= (val);			\
		else					\
			*ptr = (val);			\
	} while (0)

static int __handle_option(struct fio_option *o, const char *ptr, void *data,
			   int first, int more, int curr)
{
	int il=0, *ilp;
	fio_fp64_t *flp;
	long long ull, *ullp;
	long ul1, ul2;
	double uf;
	char **cp = NULL;
	int ret = 0, is_time = 0;
	const struct value_pair *vp;
	struct value_pair posval[PARSE_MAX_VP];
	int i, all_skipped = 1;

	dprint(FD_PARSE, "__handle_option=%s, type=%d, ptr=%s\n", o->name,
							o->type, ptr);

	if (!ptr && o->type != FIO_OPT_STR_SET && o->type != FIO_OPT_STR) {
		log_err("Option %s requires an argument\n", o->name);
		return 1;
	}

	switch (o->type) {
	case FIO_OPT_STR:
	case FIO_OPT_STR_MULTI: {
		fio_opt_str_fn *fn = o->cb;

		posval_sort(o, posval);

		ret = 1;
		for (i = 0; i < PARSE_MAX_VP; i++) {
			vp = &posval[i];
			if (!vp->ival || vp->ival[0] == '\0')
				continue;
			all_skipped = 0;
			if (!ptr)
				break;
			if (!strncmp(vp->ival, ptr, str_match_len(vp, ptr))) {
				ret = 0;
				if (o->off1)
					val_store(ilp, vp->oval, o->off1, vp->orval, data, o);
				continue;
			}
		}

		if (ret && !all_skipped)
			show_option_values(o);
		else if (fn)
			ret = fn(data, ptr);
		break;
	}
	case FIO_OPT_STR_VAL_TIME:
		is_time = 1;
	case FIO_OPT_INT:
	case FIO_OPT_STR_VAL: {
		fio_opt_str_val_fn *fn = o->cb;
		char tmp[128], *p;

		if (!is_time && o->is_time)
			is_time = o->is_time;

		tmp[sizeof(tmp) - 1] = '\0';
		strncpy(tmp, ptr, sizeof(tmp) - 1);
		p = strchr(tmp, ',');
		if (p)
			*p = '\0';

		if (is_time)
			ret = check_str_time(tmp, &ull, o->is_seconds);
		else
			ret = check_str_bytes(tmp, &ull, data);

		dprint(FD_PARSE, "  ret=%d, out=%llu\n", ret, ull);

		if (ret)
			break;
		if (o->pow2 && !is_power_of_2(ull)) {
			log_err("%s: must be a power-of-2\n", o->name);
			return 1;
		}

		if (o->maxval && ull > o->maxval) {
			log_err("max value out of range: %llu"
					" (%u max)\n", ull, o->maxval);
			return 1;
		}
		if (o->minval && ull < o->minval) {
			log_err("min value out of range: %llu"
					" (%u min)\n", ull, o->minval);
			return 1;
		}
		if (o->posval[0].ival) {
			posval_sort(o, posval);

			ret = 1;
			for (i = 0; i < PARSE_MAX_VP; i++) {
				vp = &posval[i];
				if (!vp->ival || vp->ival[0] == '\0')
					continue;
				if (vp->oval == ull) {
					ret = 0;
					break;
				}
			}
			if (ret) {
				log_err("fio: value %llu not allowed:\n", ull);
				show_option_values(o);
				return 1;
			}
		}

		if (fn)
			ret = fn(data, &ull);
		else {
			if (o->type == FIO_OPT_INT) {
				if (first)
					val_store(ilp, ull, o->off1, 0, data, o);
				if (curr == 1) {
					if (o->off2)
						val_store(ilp, ull, o->off2, 0, data, o);
				}
				if (curr == 2) {
					if (o->off3)
						val_store(ilp, ull, o->off3, 0, data, o);
				}
				if (!more) {
					if (curr < 1) {
						if (o->off2)
							val_store(ilp, ull, o->off2, 0, data, o);
					}
					if (curr < 2) {
						if (o->off3)
							val_store(ilp, ull, o->off3, 0, data, o);
					}
				}
			} else {
				if (first)
					val_store(ullp, ull, o->off1, 0, data, o);
				if (!more) {
					if (o->off2)
						val_store(ullp, ull, o->off2, 0, data, o);
				}
			}
		}
		break;
	}
	case FIO_OPT_FLOAT_LIST: {
		char *cp2;

		if (first) {
			/*
			** Initialize precision to 0 and zero out list
			** in case specified list is shorter than default
			*/
			if (o->off2) {
				ul2 = 0;
				ilp = td_var(data, o, o->off2);
				*ilp = ul2;
			}

			flp = td_var(data, o, o->off1);
			for(i = 0; i < o->maxlen; i++)
				flp[i].u.f = 0.0;
		}
		if (curr >= o->maxlen) {
			log_err("the list exceeding max length %d\n",
					o->maxlen);
			return 1;
		}
		if (!str_to_float(ptr, &uf, 0)) { /* this breaks if we ever have lists of times */
			log_err("not a floating point value: %s\n", ptr);
			return 1;
		}
		if (uf > o->maxfp) {
			log_err("value out of range: %f"
				" (range max: %f)\n", uf, o->maxfp);
			return 1;
		}
		if (uf < o->minfp) {
			log_err("value out of range: %f"
				" (range min: %f)\n", uf, o->minfp);
			return 1;
		}

		flp = td_var(data, o, o->off1);
		flp[curr].u.f = uf;

		dprint(FD_PARSE, "  out=%f\n", uf);

		/*
		** Calculate precision for output by counting
		** number of digits after period. Find first
		** period in entire remaining list each time
		*/
		cp2 = strchr(ptr, '.');
		if (cp2 != NULL) {
			int len = 0;

			while (*++cp2 != '\0' && *cp2 >= '0' && *cp2 <= '9')
				len++;

			if (o->off2) {
				ilp = td_var(data, o, o->off2);
				if (len > *ilp)
					*ilp = len;
			}
		}

		break;
	}
	case FIO_OPT_STR_STORE: {
		fio_opt_str_fn *fn = o->cb;

		if (!strlen(ptr))
			return 1;

		if (o->off1) {
			cp = td_var(data, o, o->off1);
			*cp = strdup(ptr);
		}

		if (fn)
			ret = fn(data, ptr);
		else if (o->posval[0].ival) {
			posval_sort(o, posval);

			ret = 1;
			for (i = 0; i < PARSE_MAX_VP; i++) {
				vp = &posval[i];
				if (!vp->ival || vp->ival[0] == '\0' || !cp)
					continue;
				all_skipped = 0;
				if (!strncmp(vp->ival, ptr, str_match_len(vp, ptr))) {
					char *rest;

					ret = 0;
					if (vp->cb)
						fn = vp->cb;
					rest = strstr(*cp ?: ptr, ":");
					if (rest) {
						if (*cp)
							*rest = '\0';
						ptr = rest + 1;
					} else
						ptr = NULL;
					break;
				}
			}
		}

		if (!all_skipped) {
			if (ret && !*cp)
				show_option_values(o);
			else if (ret && *cp)
				ret = 0;
			else if (fn && ptr)
				ret = fn(data, ptr);
		}

		break;
	}
	case FIO_OPT_RANGE: {
		char tmp[128];
		char *p1, *p2;

		tmp[sizeof(tmp) - 1] = '\0';
		strncpy(tmp, ptr, sizeof(tmp) - 1);

		/* Handle bsrange with separate read,write values: */
		p1 = strchr(tmp, ',');
		if (p1)
			*p1 = '\0';

		p1 = strchr(tmp, '-');
		if (!p1) {
			p1 = strchr(tmp, ':');
			if (!p1) {
				ret = 1;
				break;
			}
		}

		p2 = p1 + 1;
		*p1 = '\0';
		p1 = tmp;

		ret = 1;
		if (!check_range_bytes(p1, &ul1, data) &&
		    !check_range_bytes(p2, &ul2, data)) {
			ret = 0;
			if (ul1 > ul2) {
				unsigned long foo = ul1;

				ul1 = ul2;
				ul2 = foo;
			}

			if (first) {
				val_store(ilp, ul1, o->off1, 0, data, o);
				val_store(ilp, ul2, o->off2, 0, data, o);
			}
			if (curr == 1) {
				if (o->off3 && o->off4) {
					val_store(ilp, ul1, o->off3, 0, data, o);
					val_store(ilp, ul2, o->off4, 0, data, o);
				}
			}
			if (curr == 2) {
				if (o->off5 && o->off6) {
					val_store(ilp, ul1, o->off5, 0, data, o);
					val_store(ilp, ul2, o->off6, 0, data, o);
				}
			}
			if (!more) {
				if (curr < 1) {
					if (o->off3 && o->off4) {
						val_store(ilp, ul1, o->off3, 0, data, o);
						val_store(ilp, ul2, o->off4, 0, data, o);
					}
				}
				if (curr < 2) {
					if (o->off5 && o->off6) {
						val_store(ilp, ul1, o->off5, 0, data, o);
						val_store(ilp, ul2, o->off6, 0, data, o);
					}
				}
			}
		}

		break;
	}
	case FIO_OPT_BOOL:
	case FIO_OPT_STR_SET: {
		fio_opt_int_fn *fn = o->cb;

		if (ptr)
			ret = check_int(ptr, &il);
		else if (o->type == FIO_OPT_BOOL)
			ret = 1;
		else
			il = 1;

		dprint(FD_PARSE, "  ret=%d, out=%d\n", ret, il);

		if (ret)
			break;

		if (o->maxval && il > (int) o->maxval) {
			log_err("max value out of range: %d (%d max)\n",
								il, o->maxval);
			return 1;
		}
		if (o->minval && il < o->minval) {
			log_err("min value out of range: %d (%d min)\n",
								il, o->minval);
			return 1;
		}

		if (o->neg)
			il = !il;

		if (fn)
			ret = fn(data, &il);
		else {
			if (first)
				val_store(ilp, il, o->off1, 0, data, o);
			if (!more) {
				if (o->off2)
					val_store(ilp, il, o->off2, 0, data, o);
			}
		}
		break;
	}
	case FIO_OPT_DEPRECATED:
		log_info("Option %s is deprecated\n", o->name);
		ret = 1;
		break;
	default:
		log_err("Bad option type %u\n", o->type);
		ret = 1;
	}

	if (ret)
		return ret;

	if (o->verify) {
		ret = o->verify(o, data);
		if (ret) {
			log_err("Correct format for offending option\n");
			log_err("%20s: %s\n", o->name, o->help);
			show_option_help(o, 1);
		}
	}

	return ret;
}

static int handle_option(struct fio_option *o, const char *__ptr, void *data)
{
	char *o_ptr, *ptr, *ptr2;
	int ret, done;

	dprint(FD_PARSE, "handle_option=%s, ptr=%s\n", o->name, __ptr);

	o_ptr = ptr = NULL;
	if (__ptr)
		o_ptr = ptr = strdup(__ptr);

	/*
	 * See if we have another set of parameters, hidden after a comma.
	 * Do this before parsing this round, to check if we should
	 * copy set 1 options to set 2.
	 */
	done = 0;
	ret = 1;
	do {
		int __ret;

		ptr2 = NULL;
		if (ptr &&
		    (o->type != FIO_OPT_STR_STORE) &&
		    (o->type != FIO_OPT_STR) &&
		    (o->type != FIO_OPT_FLOAT_LIST)) {
			ptr2 = strchr(ptr, ',');
			if (ptr2 && *(ptr2 + 1) == '\0')
				*ptr2 = '\0';
			if (o->type != FIO_OPT_STR_MULTI && o->type != FIO_OPT_RANGE) {
				if (!ptr2)
					ptr2 = strchr(ptr, ':');
				if (!ptr2)
					ptr2 = strchr(ptr, '-');
			}
		} else if (ptr && o->type == FIO_OPT_FLOAT_LIST) {
			ptr2 = strchr(ptr, ':');
		}

		/*
		 * Don't return early if parsing the first option fails - if
		 * we are doing multiple arguments, we can allow the first one
		 * being empty.
		 */
		__ret = __handle_option(o, ptr, data, !done, !!ptr2, done);
		if (ret)
			ret = __ret;

		if (!ptr2)
			break;

		ptr = ptr2 + 1;
		done++;
	} while (1);

	if (o_ptr)
		free(o_ptr);
	return ret;
}

struct fio_option *find_option(struct fio_option *options, const char *opt)
{
	struct fio_option *o;

	for (o = &options[0]; o->name; o++) {
		if (!o_match(o, opt))
			continue;
		if (o->type == FIO_OPT_UNSUPPORTED) {
			log_err("Option <%s>: %s\n", o->name, o->help);
			continue;
		}

		return o;
	}

	return NULL;
}


static struct fio_option *get_option(char *opt,
				     struct fio_option *options, char **post)
{
	struct fio_option *o;
	char *ret;

	ret = strchr(opt, '=');
	if (ret) {
		*post = ret;
		*ret = '\0';
		ret = opt;
		(*post)++;
		strip_blank_end(ret);
		o = find_option(options, ret);
	} else {
		o = find_option(options, opt);
		*post = NULL;
	}

	return o;
}

static int opt_cmp(const void *p1, const void *p2)
{
	struct fio_option *o;
	char *s, *foo;
	int prio1, prio2;

	prio1 = prio2 = 0;

	if (*(char **)p1) {
		s = strdup(*((char **) p1));
		o = get_option(s, __fio_options, &foo);
		if (o)
			prio1 = o->prio;
		free(s);
	}
	if (*(char **)p2) {
		s = strdup(*((char **) p2));
		o = get_option(s, __fio_options, &foo);
		if (o)
			prio2 = o->prio;
		free(s);
	}

	return prio2 - prio1;
}

void sort_options(char **opts, struct fio_option *options, int num_opts)
{
	__fio_options = options;
	qsort(opts, num_opts, sizeof(char *), opt_cmp);
	__fio_options = NULL;
}

static void add_to_dump_list(struct fio_option *o, struct flist_head *dump_list,
			     const char *post)
{
	struct print_option *p;

	if (!dump_list)
		return;

	p = malloc(sizeof(*p));
	p->name = strdup(o->name);
	if (post)
		p->value = strdup(post);
	else
		p->value = NULL;

	flist_add_tail(&p->list, dump_list);
}

int parse_cmd_option(const char *opt, const char *val,
		     struct fio_option *options, void *data,
		     struct flist_head *dump_list)
{
	struct fio_option *o;

	o = find_option(options, opt);
	if (!o) {
		log_err("Bad option <%s>\n", opt);
		return 1;
	}

	if (handle_option(o, val, data)) {
		log_err("fio: failed parsing %s=%s\n", opt, val);
		return 1;
	}

	add_to_dump_list(o, dump_list, val);
	return 0;
}

int parse_option(char *opt, const char *input,
		 struct fio_option *options, struct fio_option **o, void *data,
		 struct flist_head *dump_list)
{
	char *post;

	if (!opt) {
		log_err("fio: failed parsing %s\n", input);
		*o = NULL;
		return 1;
	}

	*o = get_option(opt, options, &post);
	if (!*o) {
		if (post) {
			int len = strlen(opt);
			if (opt + len + 1 != post)
				memmove(opt + len + 1, post, strlen(post));
			opt[len] = '=';
		}
		return 1;
	}

	if (handle_option(*o, post, data)) {
		log_err("fio: failed parsing %s\n", input);
		return 1;
	}

	add_to_dump_list(*o, dump_list, post);
	return 0;
}

/*
 * Option match, levenshtein distance. Handy for not quite remembering what
 * the option name is.
 */
int string_distance(const char *s1, const char *s2)
{
	unsigned int s1_len = strlen(s1);
	unsigned int s2_len = strlen(s2);
	unsigned int *p, *q, *r;
	unsigned int i, j;

	p = malloc(sizeof(unsigned int) * (s2_len + 1));
	q = malloc(sizeof(unsigned int) * (s2_len + 1));

	p[0] = 0;
	for (i = 1; i <= s2_len; i++)
		p[i] = p[i - 1] + 1;

	for (i = 1; i <= s1_len; i++) {
		q[0] = p[0] + 1;
		for (j = 1; j <= s2_len; j++) {
			unsigned int sub = p[j - 1];
			unsigned int pmin;

			if (s1[i - 1] != s2[j - 1])
				sub++;

			pmin = min(q[j - 1] + 1, sub);
			q[j] = min(p[j] + 1, pmin);
		}
		r = p;
		p = q;
		q = r;
	}

	i = p[s2_len];
	free(p);
	free(q);
	return i;
}

/*
 * Make a guess of whether the distance from 's1' is significant enough
 * to warrant printing the guess. We set this to a 1/2 match.
 */
int string_distance_ok(const char *opt, int distance)
{
	size_t len;

	len = strlen(opt);
	len = (len + 1) / 2;
	return distance <= len;
}

static struct fio_option *find_child(struct fio_option *options,
				     struct fio_option *o)
{
	struct fio_option *__o;

	for (__o = options + 1; __o->name; __o++)
		if (__o->parent && !strcmp(__o->parent, o->name))
			return __o;

	return NULL;
}

static void __print_option(struct fio_option *o, struct fio_option *org,
			   int level)
{
	char name[256], *p;
	int depth;

	if (!o)
		return;
	if (!org)
		org = o;

	p = name;
	depth = level;
	while (depth--)
		p += sprintf(p, "%s", "  ");

	sprintf(p, "%s", o->name);

	log_info("%-24s: %s\n", name, o->help);
}

static void print_option(struct fio_option *o)
{
	struct fio_option *parent;
	struct fio_option *__o;
	unsigned int printed;
	unsigned int level;

	__print_option(o, NULL, 0);
	parent = o;
	level = 0;
	do {
		level++;
		printed = 0;

		while ((__o = find_child(o, parent)) != NULL) {
			__print_option(__o, o, level);
			o = __o;
			printed++;
		}

		parent = o;
	} while (printed);
}

int show_cmd_help(struct fio_option *options, const char *name)
{
	struct fio_option *o, *closest;
	unsigned int best_dist = -1U;
	int found = 0;
	int show_all = 0;

	if (!name || !strcmp(name, "all"))
		show_all = 1;

	closest = NULL;
	best_dist = -1;
	for (o = &options[0]; o->name; o++) {
		int match = 0;

		if (o->type == FIO_OPT_DEPRECATED)
			continue;
		if (!exec_profile && o->prof_name)
			continue;
		if (exec_profile && !(o->prof_name && !strcmp(exec_profile, o->prof_name)))
			continue;

		if (name) {
			if (!strcmp(name, o->name) ||
			    (o->alias && !strcmp(name, o->alias)))
				match = 1;
			else {
				unsigned int dist;

				dist = string_distance(name, o->name);
				if (dist < best_dist) {
					best_dist = dist;
					closest = o;
				}
			}
		}

		if (show_all || match) {
			found = 1;
			if (match)
				log_info("%20s: %s\n", o->name, o->help);
			if (show_all) {
				if (!o->parent)
					print_option(o);
				continue;
			}
		}

		if (!match)
			continue;

		show_option_help(o, 0);
	}

	if (found)
		return 0;

	log_err("No such command: %s", name);

	/*
	 * Only print an appropriately close option, one where the edit
	 * distance isn't too big. Otherwise we get crazy matches.
	 */
	if (closest && best_dist < 3) {
		log_info(" - showing closest match\n");
		log_info("%20s: %s\n", closest->name, closest->help);
		show_option_help(closest, 0);
	} else
		log_info("\n");

	return 1;
}

/*
 * Handle parsing of default parameters.
 */
void fill_default_options(void *data, struct fio_option *options)
{
	struct fio_option *o;

	dprint(FD_PARSE, "filling default options\n");

	for (o = &options[0]; o->name; o++)
		if (o->def)
			handle_option(o, o->def, data);
}

static void option_init(struct fio_option *o)
{
	if (o->type == FIO_OPT_DEPRECATED || o->type == FIO_OPT_UNSUPPORTED)
		return;
	if (o->name && !o->lname)
		log_err("Option %s: missing long option name\n", o->name);
	if (o->type == FIO_OPT_BOOL) {
		o->minval = 0;
		o->maxval = 1;
	}
	if (o->type == FIO_OPT_INT) {
		if (!o->maxval)
			o->maxval = UINT_MAX;
	}
	if (o->type == FIO_OPT_FLOAT_LIST) {
		o->minfp = DBL_MIN;
		o->maxfp = DBL_MAX;
	}
	if (o->type == FIO_OPT_STR_SET && o->def && !o->no_warn_def) {
		log_err("Option %s: string set option with"
				" default will always be true\n", o->name);
	}
	if (!o->cb && !o->off1)
		log_err("Option %s: neither cb nor offset given\n", o->name);
	if (!o->category) {
		log_info("Option %s: no category defined. Setting to misc\n", o->name);
		o->category = FIO_OPT_C_GENERAL;
		o->group = FIO_OPT_G_INVALID;
	}
	if (o->type == FIO_OPT_STR || o->type == FIO_OPT_STR_STORE ||
	    o->type == FIO_OPT_STR_MULTI)
		return;
}

/*
 * Sanitize the options structure. For now it just sets min/max for bool
 * values and whether both callback and offsets are given.
 */
void options_init(struct fio_option *options)
{
	struct fio_option *o;

	dprint(FD_PARSE, "init options\n");

	for (o = &options[0]; o->name; o++) {
		option_init(o);
		if (o->inverse)
			o->inv_opt = find_option(options, o->inverse);
	}
}

void options_mem_dupe(struct fio_option *options, void *data)
{
	struct fio_option *o;
	char **ptr;

	dprint(FD_PARSE, "dup options\n");

	for (o = &options[0]; o->name; o++) {
		if (o->type != FIO_OPT_STR_STORE)
			continue;

		ptr = td_var(data, o, o->off1);
		if (*ptr)
			*ptr = strdup(*ptr);
	}
}

void options_free(struct fio_option *options, void *data)
{
	struct fio_option *o;
	char **ptr;

	dprint(FD_PARSE, "free options\n");

	for (o = &options[0]; o->name; o++) {
		if (o->type != FIO_OPT_STR_STORE || !o->off1)
			continue;

		ptr = td_var(data, o, o->off1);
		if (*ptr) {
			free(*ptr);
			*ptr = NULL;
		}
	}
}
