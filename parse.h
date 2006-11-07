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
	FIO_OPT_STR_SET,
};

/*
 * Option define
 */
struct fio_option {
	const char *name;
	enum fio_opt_type type;
	unsigned int off1;
	unsigned int off2;
	unsigned int off3;
	unsigned int off4;
	unsigned int max_val;
	void *cb;
};

typedef int (str_cb_fn)(void *, char *);

extern int parse_option(const char *, struct fio_option *, void *);
extern int parse_cmd_option(const char *t, const char *l, struct fio_option *, void *);

extern void strip_blank_front(char **);
extern void strip_blank_end(char *);

/*
 * Handlers for the options
 */
typedef int (fio_opt_str_fn)(void *, const char *);
typedef int (fio_opt_str_val_fn)(void *, unsigned long long *);
typedef int (fio_opt_int_fn)(void *, unsigned int *);
typedef int (fio_opt_str_set_fn)(void *);

#define td_var(start, offset)	((void *) start + (offset))

#endif
