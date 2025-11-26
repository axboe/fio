#include <stddef.h>
#include <math.h>

#include "../fio.h"
#include "../optgroup.h"

/* zonda_fs client headers */
#include "zonda_fs_c.h"

struct zondafsio_data {
	zonda_fs_client_t* client;
	zonda_fs_file_t* file;
};

struct zondafsio_options {
    char *master;
    char *cluster;
    char *client;
    char *fence_dir;
    char *log_path;
    char *role;
    char *ip;
};

static struct fio_option options[] = {
    {
        .name	= "master",
        .lname	= "zonda2 fs master addr",
        .type	= FIO_OPT_STR_STORE,
        .off1   = offsetof(struct zondafsio_options, master),
        .def    = "",
        .help	= "Master addr of the zonda2 fs",
        .category = FIO_OPT_C_ENGINE,
        .group	= FIO_OPT_G_ZONDAFS,
    },
    {
        .name	= "cluster",
        .lname	= "zonda2 cluster id",
        .type	= FIO_OPT_STR_STORE,
        .off1   = offsetof(struct zondafsio_options, cluster),
        .def    = "",
        .help	= "Cluster id of the zonda2 fs",
        .category = FIO_OPT_C_ENGINE,
        .group	= FIO_OPT_G_ZONDAFS,
    },
    {
        .name	= "client",
        .lname	= "zonda2 client id",
        .type	= FIO_OPT_STR_STORE,
        .off1   = offsetof(struct zondafsio_options, client),
        .def    = "fio_client",
        .help	= "Client id of the zonda2 fs",
        .category = FIO_OPT_C_ENGINE,
        .group	= FIO_OPT_G_ZONDAFS,
    },
    {
        .name	= "fence_dir",
        .lname	= "zonda2 read/write fence_dir",
        .type	= FIO_OPT_STR_STORE,
        .off1   = offsetof(struct zondafsio_options, fence_dir),
        .def    = "",
        .help	= "Fence dir id of the zonda2 fs",
        .category = FIO_OPT_C_ENGINE,
        .group	= FIO_OPT_G_ZONDAFS,
    },
    {
        .name	= "log_path",
        .lname	= "zonda2 cpp client log path",
        .type	= FIO_OPT_STR_STORE,
        .off1   = offsetof(struct zondafsio_options, log_path),
        .def    = "./logs",
        .help	= "Log path of the zonda2 fs",
        .category = FIO_OPT_C_ENGINE,
        .group	= FIO_OPT_G_ZONDAFS,
    },
    {
        .name	= "role",
        .lname	= "zonda2 cpp client role",
        .type	= FIO_OPT_STR_STORE,
        .off1   = offsetof(struct zondafsio_options, role),
        .def    = "fio_role",
        .help	= "Role of the zonda2 fs",
        .category = FIO_OPT_C_ENGINE,
        .group	= FIO_OPT_G_ZONDAFS,
    },
    {
        .name	= "ip",
        .lname	= "zonda2 ip used by io fence",
        .type	= FIO_OPT_STR_STORE,
        .off1   = offsetof(struct zondafsio_options, ip),
        .def    = "127.0.0.1",
        .help	= "The host ip of the zonda2 fence",
        .category = FIO_OPT_C_ENGINE,
        .group	= FIO_OPT_G_ZONDAFS,
    },
    {
        .name	= NULL,
    },
};

static enum fio_q_status fio_zondafs_queue(struct thread_data *td,
					  struct io_u *io_u)
{
	struct zondafsio_data *zd = td->io_ops_data;
	zonda_fs_file_t* file = NULL;
	zonda_error_code_t code;
	int ret;
	unsigned long offset;
	unsigned long bytes_written = 0, bytes_read = 0;
    file = zd->file;

	if (io_u->ddir == DDIR_READ) {
		code = zonda_fs_file_read_at(file, io_u->xfer_buflen, io_u->offset, io_u->xfer_buflen, &bytes_read);
        if(code != 0 && code != 23014) {
          	io_u->error = EIO;
			return FIO_Q_COMPLETED;
        }
        if(bytes_read != io_u->xfer_buflen) {
          	if(code != 23014) {
          		io_u->error = EIO;
          	}
        }
	} else if (io_u->ddir == DDIR_WRITE) {
		code = zonda_fs_file_append(file,  io_u->xfer_buflen, io_u->xfer_buf, &bytes_written);
        if(code != 0 || bytes_written != io_u->xfer_buflen) {
        	io_u->error = EIO;
        }
	} else {
		log_err("zondafs: Invalid I/O Operation: %d\n", io_u->ddir);
		io_u->error = EINVAL;
	}
	if (io_u->error)
		td_verror(td, io_u->error, "xfer");

	return FIO_Q_COMPLETED;
}

int fio_zondafs_open_file(struct thread_data *td, struct fio_file *f)
{
	struct zondafsio_data *zd = td->io_ops_data;

	zonda_fs_file_t* file = NULL;
	zonda_error_code_t code;

	uint32_t flags = ZONDA_FS_OPEN_FLAGS_RDWR | ZONDA_FS_OPEN_FLAGS_CREAT;
	code = zonda_fs_client_open(zd->client, f->file_name, flags, &file);
	if(code != 0) {
		log_err("zondafs: unable to open");
		return code;
	}
	zd->file = file;
	return 0;
}

int fio_zondafs_close_file(struct thread_data *td, struct fio_file *f)
{
	struct zondafsio_data *zd = td->io_ops_data;

	zonda_fs_file_close(zd->file);
	zonda_fs_file_destroy(zd->file);
	zonda_fs_client_destroy(zd->client);
	return 0;
}

static int fio_zondafs_setup(struct thread_data *td)
{
	struct zondafsio_data *zd;
	struct fio_file *f;
	int i;
	uint64_t file_size, total_file_size;

	if (!td->io_ops_data) {
		zd = calloc(1, sizeof(*zd));
		td->io_ops_data = zd;
	}

	total_file_size = 0;
	file_size = 0;

	for_each_file(td, f, i) {
		if(!td->o.file_size_low) {
			file_size = floor(td->o.size / td->o.nr_files);
			total_file_size += file_size;
		}
		else if (td->o.file_size_low == td->o.file_size_high)
			file_size = td->o.file_size_low;
		else {
			file_size = get_rand_file_size(td);
		}
		f->real_file_size = file_size;
	}
	return 0;
}

static int fio_zondafs_init(struct thread_data *td)
{
	struct zondafsio_data *zd = td->io_ops_data;
	struct zondafsio_options *option = td->eo;

	zonda_fs_client_t* client = NULL;
	zonda_error_code_t code;

	zonda_fs_conn_config_t config = {
		.master_addr = option->master,
		.cluster_id = option->cluster,
		.client_id = option->client,
		.fence_dir = option->fence_dir,
		.log_path = option->log_path,
		.role = option->role,
		.ip = option->ip,
	};

	code = zonda_fs_client_new(&config, &client);
    if(code != 0) {
    	log_err("zondafs: unable to new client\n");
    	return EINVAL;
    }
	zd->client = client;

	code = zonda_fs_client_fence_directory(client, option->fence_dir);
	if(code != 0) {
		log_err("zondafs: unable to fence dir\n");
		return EINVAL;
	}
	return 0;
}

FIO_STATIC struct ioengine_ops ioengine = {
	.name = "zondafs",
	.version = FIO_IOOPS_VERSION,
	.flags = FIO_SYNCIO | FIO_DISKLESSIO | FIO_NODISKUTIL,
	.setup = fio_zondafs_setup,
	.init = fio_zondafs_init,
	.queue = fio_zondafs_queue,
	.open_file = fio_zondafs_open_file,
	.close_file = fio_zondafs_close_file,
	.option_struct_size	= sizeof(struct zondafsio_options),
	.options		= options,
};

static void fio_init fio_zondafs_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_zondafs_unregister(void)
{
	unregister_ioengine(&ioengine);
}