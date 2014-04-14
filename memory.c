/*
 * Memory helpers
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "fio.h"
#ifndef FIO_NO_HAVE_SHM_H
#include <sys/shm.h>
#endif

void fio_unpin_memory(struct thread_data *td)
{
	if (td->pinned_mem) {
		dprint(FD_MEM, "unpinning %llu bytes\n", td->o.lockmem);
		if (munlock(td->pinned_mem, td->o.lockmem) < 0)
			perror("munlock");
		munmap(td->pinned_mem, td->o.lockmem);
		td->pinned_mem = NULL;
	}
}

int fio_pin_memory(struct thread_data *td)
{
	unsigned long long phys_mem;

	if (!td->o.lockmem)
		return 0;

	dprint(FD_MEM, "pinning %llu bytes\n", td->o.lockmem);

	/*
	 * Don't allow mlock of more than real_mem-128MB
	 */
	phys_mem = os_phys_mem();
	if (phys_mem) {
		if ((td->o.lockmem + 128 * 1024 * 1024) > phys_mem) {
			td->o.lockmem = phys_mem - 128 * 1024 * 1024;
			log_info("fio: limiting mlocked memory to %lluMB\n",
							td->o.lockmem >> 20);
		}
	}

	td->pinned_mem = mmap(NULL, td->o.lockmem, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | OS_MAP_ANON, -1, 0);
	if (td->pinned_mem == MAP_FAILED) {
		perror("malloc locked mem");
		td->pinned_mem = NULL;
		return 1;
	}
	if (mlock(td->pinned_mem, td->o.lockmem) < 0) {
		perror("mlock");
		munmap(td->pinned_mem, td->o.lockmem);
		td->pinned_mem = NULL;
		return 1;
	}

	return 0;
}

static int alloc_mem_shm(struct thread_data *td, unsigned int total_mem)
{
	int flags = IPC_CREAT | S_IRUSR | S_IWUSR;

	if (td->o.mem_type == MEM_SHMHUGE) {
		unsigned long mask = td->o.hugepage_size - 1;

		flags |= SHM_HUGETLB;
		total_mem = (total_mem + mask) & ~mask;
	}

	td->shm_id = shmget(IPC_PRIVATE, total_mem, flags);
	dprint(FD_MEM, "shmget %u, %d\n", total_mem, td->shm_id);
	if (td->shm_id < 0) {
		td_verror(td, errno, "shmget");
		if (geteuid() != 0 && (errno == ENOMEM || errno == EPERM))
			log_err("fio: you may need to run this job as root\n");
		if (td->o.mem_type == MEM_SHMHUGE) {
			if (errno == EINVAL) {
				log_err("fio: check that you have free huge"
					" pages and that hugepage-size is"
					" correct.\n");
			} else if (errno == ENOSYS) {
				log_err("fio: your system does not appear to"
					" support huge pages.\n");
			} else if (errno == ENOMEM) {
				log_err("fio: no huge pages available, do you"
					" need to alocate some? See HOWTO.\n");
			}
		}

		return 1;
	}

	td->orig_buffer = shmat(td->shm_id, NULL, 0);
	dprint(FD_MEM, "shmat %d, %p\n", td->shm_id, td->orig_buffer);
	if (td->orig_buffer == (void *) -1) {
		td_verror(td, errno, "shmat");
		td->orig_buffer = NULL;
		return 1;
	}

	return 0;
}

static void free_mem_shm(struct thread_data *td)
{
	struct shmid_ds sbuf;

	dprint(FD_MEM, "shmdt/ctl %d %p\n", td->shm_id, td->orig_buffer);
	shmdt(td->orig_buffer);
	shmctl(td->shm_id, IPC_RMID, &sbuf);
}

static int alloc_mem_mmap(struct thread_data *td, size_t total_mem)
{
	int flags = 0;

	td->mmapfd = 1;

	if (td->o.mem_type == MEM_MMAPHUGE) {
		unsigned long mask = td->o.hugepage_size - 1;

		/* TODO: make sure the file is a real hugetlbfs file */
		if (!td->o.mmapfile)
			flags |= MAP_HUGETLB;
		total_mem = (total_mem + mask) & ~mask;
	}

	if (td->o.mmapfile) {
		td->mmapfd = open(td->o.mmapfile, O_RDWR|O_CREAT, 0644);

		if (td->mmapfd < 0) {
			td_verror(td, errno, "open mmap file");
			td->orig_buffer = NULL;
			return 1;
		}
		if (td->o.mem_type != MEM_MMAPHUGE &&
		    ftruncate(td->mmapfd, total_mem) < 0) {
			td_verror(td, errno, "truncate mmap file");
			td->orig_buffer = NULL;
			return 1;
		}
		if (td->o.mem_type == MEM_MMAPHUGE)
			flags |= MAP_SHARED;
		else
			flags |= MAP_PRIVATE;
	} else
		flags |= OS_MAP_ANON | MAP_PRIVATE;

	td->orig_buffer = mmap(NULL, total_mem, PROT_READ | PROT_WRITE, flags,
				td->mmapfd, 0);
	dprint(FD_MEM, "mmap %llu/%d %p\n", (unsigned long long) total_mem,
						td->mmapfd, td->orig_buffer);
	if (td->orig_buffer == MAP_FAILED) {
		td_verror(td, errno, "mmap");
		td->orig_buffer = NULL;
		if (td->mmapfd != 1) {
			close(td->mmapfd);
			if (td->o.mmapfile)
				unlink(td->o.mmapfile);
		}

		return 1;
	}

	return 0;
}

static void free_mem_mmap(struct thread_data *td, size_t total_mem)
{
	dprint(FD_MEM, "munmap %llu %p\n", (unsigned long long) total_mem,
						td->orig_buffer);
	munmap(td->orig_buffer, td->orig_buffer_size);
	if (td->o.mmapfile) {
		close(td->mmapfd);
		unlink(td->o.mmapfile);
		free(td->o.mmapfile);
	}
}

static int alloc_mem_malloc(struct thread_data *td, size_t total_mem)
{
	td->orig_buffer = malloc(total_mem);
	dprint(FD_MEM, "malloc %llu %p\n", (unsigned long long) total_mem,
							td->orig_buffer);

	return td->orig_buffer == NULL;
}

static void free_mem_malloc(struct thread_data *td)
{
	dprint(FD_MEM, "free malloc mem %p\n", td->orig_buffer);
	free(td->orig_buffer);
}

/*
 * Set up the buffer area we need for io.
 */
int allocate_io_mem(struct thread_data *td)
{
	size_t total_mem;
	int ret = 0;

	if (td->io_ops->flags & FIO_NOIO)
		return 0;

	total_mem = td->orig_buffer_size;

	if (td->o.odirect || td->o.mem_align || td->o.oatomic ||
	    (td->io_ops->flags & FIO_MEMALIGN)) {
		total_mem += page_mask;
		if (td->o.mem_align && td->o.mem_align > page_size)
			total_mem += td->o.mem_align - page_size;
	}

	dprint(FD_MEM, "Alloc %llu for buffers\n", (unsigned long long) total_mem);

	if (td->o.mem_type == MEM_MALLOC)
		ret = alloc_mem_malloc(td, total_mem);
	else if (td->o.mem_type == MEM_SHM || td->o.mem_type == MEM_SHMHUGE)
		ret = alloc_mem_shm(td, total_mem);
	else if (td->o.mem_type == MEM_MMAP || td->o.mem_type == MEM_MMAPHUGE)
		ret = alloc_mem_mmap(td, total_mem);
	else {
		log_err("fio: bad mem type: %d\n", td->o.mem_type);
		ret = 1;
	}

	if (ret)
		td_verror(td, ENOMEM, "iomem allocation");

	return ret;
}

void free_io_mem(struct thread_data *td)
{
	unsigned int total_mem;

	total_mem = td->orig_buffer_size;
	if (td->o.odirect || td->o.oatomic)
		total_mem += page_mask;

	if (td->o.mem_type == MEM_MALLOC)
		free_mem_malloc(td);
	else if (td->o.mem_type == MEM_SHM || td->o.mem_type == MEM_SHMHUGE)
		free_mem_shm(td);
	else if (td->o.mem_type == MEM_MMAP || td->o.mem_type == MEM_MMAPHUGE)
		free_mem_mmap(td, total_mem);
	else
		log_err("Bad memory type %u\n", td->o.mem_type);

	td->orig_buffer = NULL;
	td->orig_buffer_size = 0;
}
