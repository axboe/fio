#ifndef FIO_TD_ERROR_H
#define FIO_TD_ERROR_H

/*
 * What type of errors to continue on when continue_on_error is used
 */
enum error_type_bit {
	ERROR_TYPE_READ_BIT = 0,
	ERROR_TYPE_WRITE_BIT = 1,
	ERROR_TYPE_VERIFY_BIT = 2,
	ERROR_TYPE_CNT = 3,
};

enum error_type {
        ERROR_TYPE_NONE = 0,
        ERROR_TYPE_READ = 1 << ERROR_TYPE_READ_BIT,
        ERROR_TYPE_WRITE = 1 << ERROR_TYPE_WRITE_BIT,
        ERROR_TYPE_VERIFY = 1 << ERROR_TYPE_VERIFY_BIT,
        ERROR_TYPE_ANY = 0xffff,
};

enum error_type_bit td_error_type(enum fio_ddir ddir, int err);
int td_non_fatal_error(struct thread_data *td, enum error_type_bit etype,
		       int err);
void update_error_count(struct thread_data *td, int err);

#endif
