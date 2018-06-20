#include <glusterfs/api/glfs.h>
#include "../fio.h"

struct gf_options {
	void *pad;
	char *gf_vol;
	char *gf_brick;
	int gf_single_instance;
};

struct gf_data {
	glfs_t *fs;
	glfs_fd_t *fd;
	struct io_u **aio_events;
};

extern struct fio_option gfapi_options[];
extern int fio_gf_setup(struct thread_data *td);
extern void fio_gf_cleanup(struct thread_data *td);
extern int fio_gf_get_file_size(struct thread_data *td, struct fio_file *f);
extern int fio_gf_open_file(struct thread_data *td, struct fio_file *f);
extern int fio_gf_close_file(struct thread_data *td, struct fio_file *f);
extern int fio_gf_unlink_file(struct thread_data *td, struct fio_file *f);
