#ifndef FIO_LOG_H
#define FIO_LOG_H

extern int read_iolog_get(struct thread_data *, struct io_u *);
extern void write_iolog_put(struct thread_data *, struct io_u *);
extern int init_iolog(struct thread_data *td);
extern void log_io_piece(struct thread_data *, struct io_u *);
extern void prune_io_piece_log(struct thread_data *);
extern void write_iolog_close(struct thread_data *);

#endif
