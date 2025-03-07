#ifndef DEDUPE_H
#define DEDUPE_H

int init_dedupe_working_set_seeds(struct thread_data *td, bool global_dedupe);
int init_global_dedupe_working_set_seeds(void);

#endif
