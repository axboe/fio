#ifndef FIO_FDP_H
#define FIO_FDP_H

#include "io_u.h"

struct fio_ruhs_info {
	uint32_t nr_ruhs;
	uint32_t pli_loc;
	uint16_t plis[];
};

int fdp_init(struct thread_data *td);
void fdp_free_ruhs_info(struct fio_file *f);
void fdp_fill_dspec_data(struct thread_data *td, struct io_u *io_u);

#endif /* FIO_FDP_H */
