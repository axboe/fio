/*
 * getopt.c
 *
 * getopt_long(), or at least a common subset thereof:
 *
 * - Option reordering is not supported
 * - -W foo is not supported
 * - First optstring character "-" not supported.
 *
 * This file was imported from the klibc library from hpa
 */

#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include "getopt.h"

char *optarg = NULL;
int optind = 0, opterr = 0, optopt = 0;

static struct getopt_private_state {
	const char *optptr;
	const char *last_optstring;
	char *const *last_argv;
} pvt;

static inline const char *option_matches(const char *arg_str,
					 const char *opt_name, int smatch)
{
	while (*arg_str != '\0' && *arg_str != '=') {
		if (*arg_str++ != *opt_name++)
			return NULL;
	}

	if (*opt_name && !smatch)
		return NULL;

	return arg_str;
}

int getopt_long_only(int argc, char *const *argv, const char *optstring,
		const struct option *longopts, int *longindex)
{
	const char *carg;
	const char *osptr;
	int opt;

	optarg = NULL;

	/* getopt() relies on a number of different global state
	   variables, which can make this really confusing if there is
	   more than one use of getopt() in the same program.  This
	   attempts to detect that situation by detecting if the
	   "optstring" or "argv" argument have changed since last time
	   we were called; if so, reinitialize the query state. */

	if (optstring != pvt.last_optstring || argv != pvt.last_argv ||
	    optind < 1 || optind > argc) {
		/* optind doesn't match the current query */
		pvt.last_optstring = optstring;
		pvt.last_argv = argv;
		optind = 1;
		pvt.optptr = NULL;
	}

	carg = argv[optind];

	/* First, eliminate all non-option cases */

	if (!carg || carg[0] != '-' || !carg[1])
		return -1;

	if (carg[1] == '-') {
		const struct option *lo;
		const char *opt_end = NULL;

		optind++;

		/* Either it's a long option, or it's -- */
		if (!carg[2]) {
			/* It's -- */
			return -1;
		}

		for (lo = longopts; lo->name; lo++) {
			opt_end = option_matches(carg+2, lo->name, 0);
			if (opt_end)
			    break;
		}
		/*
		 * The GNU getopt_long_only() apparently allows a short match,
		 * if it's unique and if we don't have a full match. Let's
		 * do the same here, search and see if there is one (and only
		 * one) short match.
		 */
		if (!opt_end) {
			const struct option *lo_match = NULL;

			for (lo = longopts; lo->name; lo++) {
				const char *ret;

				ret = option_matches(carg+2, lo->name, 1);
				if (!ret)
					continue;
				if (!opt_end) {
					opt_end = ret;
					lo_match = lo;
				} else {
					opt_end = NULL;
					break;
				}
			}
			if (!opt_end)
				return '?';
			lo = lo_match;
		}

		if (longindex)
			*longindex = lo-longopts;

		if (*opt_end == '=') {
			if (lo->has_arg)
				optarg = (char *)opt_end+1;
			else
				return '?';
		} else if (lo->has_arg == 1) {
			if (!(optarg = argv[optind]))
				return '?';
			optind++;
		}

		if (lo->flag) {
			*lo->flag = lo->val;
			return 0;
		} else {
			return lo->val;
		}
	}

	if ((uintptr_t) (pvt.optptr - carg) > (uintptr_t) strlen(carg)) {
		/* Someone frobbed optind, change to new opt. */
		pvt.optptr = carg + 1;
	}

	opt = *pvt.optptr++;

	if (opt != ':' && (osptr = strchr(optstring, opt))) {
		if (osptr[1] == ':') {
			if (*pvt.optptr) {
				/* Argument-taking option with attached
				   argument */
				optarg = (char *)pvt.optptr;
				optind++;
			} else {
				/* Argument-taking option with non-attached
				   argument */
				if (osptr[2] == ':') {
					if (argv[optind + 1]) {
						optarg = (char *)argv[optind+1];
						optind += 2;
					} else {
						optarg = NULL;
						optind++;
					}
					return opt;
				} else if (argv[optind + 1]) {
					optarg = (char *)argv[optind+1];
					optind += 2;
				} else {
					/* Missing argument */
					optind++;
					return (optstring[0] == ':')
						? ':' : '?';
				}
			}
			return opt;
		} else {
			/* Non-argument-taking option */
			/* pvt.optptr will remember the exact position to
			   resume at */
			if (!*pvt.optptr)
				optind++;
			return opt;
		}
	} else {
		/* Unknown option */
		optopt = opt;
		if (!*pvt.optptr)
			optind++;
		return '?';
	}
}
