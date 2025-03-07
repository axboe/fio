#ifndef FIO_FLOW_H
#define FIO_FLOW_H

#define FLOW_MAX_WEIGHT 1000

int flow_threshold_exceeded(struct thread_data *td);
void flow_init_job(struct thread_data *td);
void flow_exit_job(struct thread_data *td);

void flow_exit(void);
void flow_init(void);

#endif
