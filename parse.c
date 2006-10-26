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

int check_str_bytes(char *p, char *name, unsigned long long *val)
{
	if (strncmp(p, name, strlen(name) - 1))
		return 1;

	return str_to_decimal(p, val, 1);
}

int check_str_time(char *p, char *name, unsigned long long *val)
{
	if (strncmp(p, name, strlen(name) - 1))
		return 1;

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

int check_str(char *p, char *name, str_cb_fn *cb, void *data)
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
	return cb(data, s);
}

int check_strstore(char *p, char *name, char *dest)
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

int check_range_bytes(char *p, char *name, unsigned long *s, unsigned long *e)
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

int check_int(char *p, char *name, unsigned int *val)
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

int check_strset(char *p, char *name)
{
	return strncmp(p, name, strlen(name));
}

