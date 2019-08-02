#ifndef FIO_PARSE_H
#define FIO_PARSE_H

#include <inttypes.h>
#include "flist.h"

/*
 * Option types
 */
enum fio_opt_type {
	FIO_OPT_INVALID = 0,
	FIO_OPT_STR,
	FIO_OPT_STR_ULL,
	FIO_OPT_STR_MULTI,
	FIO_OPT_STR_VAL,
	FIO_OPT_STR_VAL_TIME,
	FIO_OPT_STR_STORE,
	FIO_OPT_RANGE,
	FIO_OPT_INT,
	FIO_OPT_ULL,
	FIO_OPT_BOOL,
	FIO_OPT_FLOAT_LIST,
	FIO_OPT_STR_SET,
	FIO_OPT_DEPRECATED,
	FIO_OPT_SOFT_DEPRECATED,
	FIO_OPT_UNSUPPORTED,	/* keep this last */
};

/*
 * Match a possible value string with the integer option.
 */
struct value_pair {
	const char *ival;		/* string option */
	unsigned long long oval;/* output value */
	const char *help;		/* help text for sub option */
	int orval;			/* OR value */
	void *cb;			/* sub-option callback */
};

#define OPT_LEN_MAX 	8192
#define PARSE_MAX_VP	32

/*
 * Option define
 */
struct fio_option {
	const char *name;		/* option name */
	const char *lname;		/* long option name */
	const char *alias;		/* possible old allowed name */
	enum fio_opt_type type;		/* option type */
	unsigned int off1;		/* potential parameters */
	unsigned int off2;
	unsigned int off3;
	unsigned int off4;
	unsigned int off5;
	unsigned int off6;
	unsigned long long maxval;		/* max and min value */
	int minval;
	double maxfp;			/* max and min floating value */
	double minfp;
	unsigned int interval;		/* client hint for suitable interval */
	unsigned int maxlen;		/* max length */
	int neg;			/* negate value stored */
	int prio;
	void *cb;			/* callback */
	const char *help;		/* help text for option */
	const char *def;		/* default setting */
	struct value_pair posval[PARSE_MAX_VP];/* possible values */
	const char *parent;		/* parent option */
	int hide;			/* hide if parent isn't set */
	int hide_on_set;		/* hide on set, not on unset */
	const char *inverse;		/* if set, apply opposite action to this option */
	struct fio_option *inv_opt;	/* cached lookup */
	int (*verify)(const struct fio_option *, void *);
	const char *prof_name;		/* only valid for specific profile */
	void *prof_opts;
	uint64_t category;		/* what type of option */
	uint64_t group;			/* who to group with */
	void *gui_data;
	int is_seconds;			/* time value with seconds base */
	int is_time;			/* time based value */
	int no_warn_def;
	int pow2;			/* must be a power-of-2 */
	int no_free;
};

extern int parse_option(char *, const char *, const struct fio_option *,
			const struct fio_option **, void *,
			struct flist_head *);
extern void sort_options(char **, const struct fio_option *, int);
extern int parse_cmd_option(const char *t, const char *l,
			    const struct fio_option *, void *,
			    struct flist_head *);
extern int show_cmd_help(const struct fio_option *, const char *);
extern void fill_default_options(void *, const struct fio_option *);
extern void options_init(struct fio_option *);
extern void options_mem_dupe(const struct fio_option *, void *);
extern void options_free(const struct fio_option *, void *);

extern void strip_blank_front(char **);
extern void strip_blank_end(char *);
extern int str_to_decimal(const char *, long long *, int, void *, int, int);
extern int check_str_bytes(const char *p, long long *val, void *data);
extern int check_str_time(const char *p, long long *val, int);
extern int str_to_float(const char *str, double *val, int is_time);

extern int string_distance(const char *s1, const char *s2);
extern int string_distance_ok(const char *s1, int dist);

/*
 * Handlers for the options
 */
typedef int (fio_opt_str_fn)(void *, const char *);
typedef int (fio_opt_str_val_fn)(void *, long long *);
typedef int (fio_opt_int_fn)(void *, int *);

struct thread_options;
static inline void *td_var(void *to, const struct fio_option *o,
			   unsigned int offset)
{
	void *ret;

	if (o->prof_opts)
		ret = o->prof_opts;
	else
		ret = to;

	return ret + offset;
}

static inline int parse_is_percent(unsigned long long val)
{
	return val <= -1ULL && val >= (-1ULL - 100ULL);
}

struct print_option {
	struct flist_head list;
	char *name;
	char *value;
};

#endif
