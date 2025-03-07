#ifndef FIO_RATE_SUBMIT
#define FIO_RATE_SUBMIT

int rate_submit_init(struct thread_data *, struct sk_out *);
void rate_submit_exit(struct thread_data *);

#endif
