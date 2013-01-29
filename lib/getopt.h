#ifdef CONFIG_GETOPT_LONG_ONLY

#include <getopt.h>

#else

#ifndef _GETOPT_H
#define _GETOPT_H

struct option {
	const char *name;
	int has_arg;
	int *flag;
	int val;
};

enum {
	no_argument	  = 0,
	required_argument = 1,
	optional_argument = 2,
};

int getopt_long_only(int, char *const *, const char *, const struct option *, int *);

#endif
#endif
