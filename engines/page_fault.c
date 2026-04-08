/*
 * page_fault engine
 *
 * IO engine that reads/writes directly to/from anonymous memory
 * by triggering page faults.
 */
#include "fio.h"
#include "ioengines.h"
#include <sys/mman.h>

struct fio_page_fault_data {
	void *mmap_ptr;
	size_t mmap_sz;
};

static int fio_page_fault_init(struct thread_data *td)
{
	size_t total_io_size;
	struct fio_page_fault_data *fpd;

	if (td->o.nr_files > 1) {
		log_err("fio: page_fault ioengine does not support multiple files\n");
		return 1;
	}

	if (td->o.start_offset != 0) {
		log_err("fio: page_fault engine does not support start_offset\n");
		return 1;
	}

	fpd = calloc(1, sizeof(*fpd));
	if (!fpd)
		return 1;

	total_io_size = td->o.size;
	fpd->mmap_sz = total_io_size;
	fpd->mmap_ptr = mmap(NULL, total_io_size, PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (fpd->mmap_ptr == MAP_FAILED) {
		free(fpd);
		return 1;
	}

	td->io_ops_data = fpd;
	return 0;
}

static enum fio_q_status fio_page_fault_queue(struct thread_data *td,
					      struct io_u *io_u)
{
	void *mmap_head;
	struct fio_page_fault_data *fpd = td->io_ops_data;
	if (!fpd) {
		io_u->error = EINVAL;
		return FIO_Q_COMPLETED;
	}

	if (io_u->offset + io_u->buflen > fpd->mmap_sz) {
		io_u->error = EINVAL;
		return FIO_Q_COMPLETED;
	}

	mmap_head = fpd->mmap_ptr + io_u->offset;
	switch (io_u->ddir) {
	case DDIR_READ:
		memcpy(io_u->xfer_buf, mmap_head, io_u->buflen);
		break;
	case DDIR_WRITE:
		memcpy(mmap_head, io_u->xfer_buf, io_u->buflen);
		break;
	case DDIR_SYNC:
	case DDIR_DATASYNC:
	case DDIR_SYNC_FILE_RANGE:
	case DDIR_SYNCFS:
		break;
	default:
		io_u->error = EINVAL;
		break;
	}

	return FIO_Q_COMPLETED;
}

static int fio_page_fault_open_file(struct thread_data *td, struct fio_file *f)
{
	return 0;
}

static int fio_page_fault_close_file(struct thread_data *td, struct fio_file *f)
{
	return 0;
}

static void fio_page_fault_cleanup(struct thread_data *td)
{
	struct fio_page_fault_data *fpd = td->io_ops_data;

	if (!fpd)
		return;
	if (fpd->mmap_ptr && fpd->mmap_sz)
		munmap(fpd->mmap_ptr, fpd->mmap_sz);
	free(fpd);
}

static struct ioengine_ops ioengine = {
	.name = "page_fault",
	.version = FIO_IOOPS_VERSION,
	.init = fio_page_fault_init,
	.cleanup = fio_page_fault_cleanup,
	.queue = fio_page_fault_queue,
	.open_file = fio_page_fault_open_file,
	.close_file = fio_page_fault_close_file,
	.get_file_size = generic_get_file_size,
	.flags = FIO_SYNCIO | FIO_NOEXTEND | FIO_DISKLESSIO,
};

static void fio_init fio_page_fault_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_page_fault_unregister(void)
{
	unregister_ioengine(&ioengine);
}