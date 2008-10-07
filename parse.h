#ifndef FIO_PARSE_H
#define FIO_PARSE_H

/*
 * Option types
 */
enum fio_opt_type {
	FIO_OPT_STR = 0,
	FIO_OPT_STR_VAL,
	FIO_OPT_STR_VAL_INT,
	FIO_OPT_STR_VAL_TIME,
	FIO_OPT_STR_STORE,
	FIO_OPT_RANGE,
	FIO_OPT_INT,
	FIO_OPT_BOOL,
	FIO_OPT_STR_SET,
	FIO_OPT_DEPRECATED,
};

/*
 * Match a possible value string with the integer option.
 */
struct value_pair {
	const char *ival;		/* string option */
	unsigned int oval;		/* output value */
	const char *help;		/* help text for sub option */
};

#define OPT_LEN_MAX 	1024
#define PARSE_MAX_VP	16

/*
 * Option define
 */
struct fio_option {
	const char *name;		/* option name */
	const char *alias;		/* possible old allowed name */
	enum fio_opt_type type;		/* option type */
	unsigned int off1;		/* potential parameters */
	unsigned int off2;
	unsigned int off3;
	unsigned int off4;
	unsigned int maxval;		/* max and min value */
	int minval;
	int neg;			/* negate value stored */
	int prio;
	void *cb;			/* callback */
	const char *help;		/* help text for option */
	const char *def;		/* default setting */
	const struct value_pair posval[PARSE_MAX_VP];/* possible values */
	const char *parent;		/* parent option */
};

typedef int (str_cb_fn)(void *, char *);

extern int parse_option(const char *, struct fio_option *, void *);
extern void sort_options(char **, struct fio_option *, int);
extern int parse_cmd_option(const char *t, const char *l, struct fio_option *, void *);
extern int show_cmd_help(struct fio_option *, const char *);
extern void fill_default_options(void *, struct fio_option *);
extern void options_init(struct fio_option *);

extern void strip_blank_front(char **);
extern void strip_blank_end(char *);
extern int str_to_decimal(const char *, long long *, int);

/*
 * Handlers for the options
 */
typedef int (fio_opt_str_fn)(void *, const char *);
typedef int (fio_opt_str_val_fn)(void *, long long *);
typedef int (fio_opt_int_fn)(void *, int *);
typedef int (fio_opt_str_set_fn)(void *);

#define td_var(start, offset)	((void *) start + (offset))

#ifndef min
#define min(a, b)	((a) < (b) ? (a) : (b))
#endif
#ifndef max
#define max(a, b)	((a) > (b) ? (a) : (b))
#endif

#endif
