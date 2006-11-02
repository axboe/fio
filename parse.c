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

#include "parse.h"

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
 * convert string into decimal value, noting any size suffix
 */
static int str_to_decimal(const char *str, unsigned long long *val, int kilo)
{
	int len;

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

static int check_str_bytes(const char *p, unsigned long long *val)
{
	return str_to_decimal(p, val, 1);
}

static int check_str_time(const char *p, unsigned long long *val)
{
	return str_to_decimal(p, val, 0);
}

void strip_blank_front(char **p)
{
	char *s = *p;

	while (isspace(*s))
		s++;
}

void strip_blank_end(char *p)
{
	char *s = p + strlen(p) - 1;

	while (isspace(*s) || iscntrl(*s))
		s--;

	*(s + 1) = '\0';
}

static int check_range_bytes(const char *str, unsigned long *val)
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

static int check_int(const char *p, unsigned int *val)
{
	if (sscanf(p, "%u", val) == 1)
		return 0;

	return 1;
}

static struct fio_option *find_option(struct fio_option *options,
				      const char *opt)
{
	struct fio_option *o = &options[0];

	while (o->name) {
		if (!strcmp(o->name, opt))
			return o;

		o++;
	}

	return NULL;
}

static int handle_option(struct fio_option *o, const char *ptr, void *data)
{
	unsigned int il, *ilp;
	unsigned long long ull, *ullp;
	unsigned long ul1, ul2, *ulp1, *ulp2;
	char **cp;
	int ret = 0, is_time = 0;

	switch (o->type) {
	case FIO_OPT_STR: {
		fio_opt_str_fn *fn = o->cb;

		ret = fn(data, ptr);
		break;
	}
	case FIO_OPT_STR_VAL_TIME:
		is_time = 1;
	case FIO_OPT_STR_VAL: {
		fio_opt_str_val_fn *fn = o->cb;

		if (is_time)
			ret = check_str_time(ptr, &ull);
		else
			ret = check_str_bytes(ptr, &ull);

		if (ret)
			break;

		if (o->max_val && ull > o->max_val)
			ull = o->max_val;

		if (fn)
			ret = fn(data, &ull);
		else {
			ullp = td_var(data, o->off1);
			*ullp = ull;
		}
		break;
	}
	case FIO_OPT_STR_STORE:
		cp = td_var(data, o->off1);
		*cp = strdup(ptr);
		break;
	case FIO_OPT_RANGE: {
		char tmp[128];
		char *p1, *p2;

		strcpy(tmp, ptr);

		p1 = strchr(tmp, '-');
		if (!p1) {
			ret = 1;
			break;
		}

		p2 = p1 + 1;
		*p1 = '\0';
		p1 = tmp;

		ret = 1;
		if (!check_range_bytes(p1, &ul1) && !check_range_bytes(p2, &ul2)) {
			ret = 0;
			ulp1 = td_var(data, o->off1);
			ulp2 = td_var(data, o->off2);
			if (ul1 > ul2) {
				*ulp1 = ul2;
				*ulp2 = ul1;
			} else {
				*ulp2 = ul2;
				*ulp1 = ul1;
			}
		}	
			
		break;
	}
	case FIO_OPT_INT: {
		fio_opt_int_fn *fn = o->cb;

		ret = check_int(ptr, &il);
		if (ret)
			break;

		if (o->max_val && il > o->max_val)
			il = o->max_val;

		if (fn)
			ret = fn(data, &il);
		else {
			ilp = td_var(data, o->off1);
			*ilp = il;
		}
		break;
	}
	case FIO_OPT_STR_SET: {
		fio_opt_str_set_fn *fn = o->cb;

		if (fn)
			ret = fn(data);
		else {
			ilp = td_var(data, o->off1);
			*ilp = 1;
		}
		break;
	}
	default:
		fprintf(stderr, "Bad option type %d\n", o->type);
		ret = 1;
	}

	if (ret)
		fprintf(stderr, "fio: failed parsing %s=%s\n", o->name, ptr);

	return ret;
}

int parse_cmd_option(const char *opt, const char *val,
		     struct fio_option *options, void *data)
{
	struct fio_option *o;

	o = find_option(options, opt);
	if (!o) {
		fprintf(stderr, "Bad option %s\n", opt);
		return 1;
	}

	return handle_option(o, val, data);
}

int parse_option(const char *opt, struct fio_option *options, void *data)
{
	struct fio_option *o;
	char *pre, *post;
	char tmp[64];

	strcpy(tmp, opt);

	pre = strchr(tmp, '=');
	if (pre) {
		post = pre;
		*pre = '\0';
		pre = tmp;
		post++;
		o = find_option(options, pre);
	} else {
		o = find_option(options, tmp);
		post = NULL;
	}

	if (!o) {
		fprintf(stderr, "Bad option %s\n", tmp);
		return 1;
	}

	return handle_option(o, post, data);
}
