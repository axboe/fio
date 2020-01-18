/*
 * pmemblk: IO engine that uses PMDK libpmemblk to read and write data
 *
 * Copyright (C) 2016 Hewlett Packard Enterprise Development LP
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License,
 * version 2 as published by the Free Software Foundation..
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

/*
 * pmemblk engine
 *
 * IO engine that uses libpmemblk to read and write data
 *
 * To use:
 *   ioengine=pmemblk
 *
 * Other relevant settings:
 *   thread=1   REQUIRED
 *   iodepth=1
 *   direct=1
 *   unlink=1
 *   filename=/mnt/pmem0/fiotestfile,BSIZE,FSIZEMiB
 *
 *   thread must be set to 1 for pmemblk as multiple processes cannot
 *     open the same block pool file.
 *
 *   iodepth should be set to 1 as pmemblk is always synchronous.
 *   Use numjobs to scale up.
 *
 *   direct=1 is implied as pmemblk is always direct. A warning message
 *   is printed if this is not specified.
 *
 *   unlink=1 removes the block pool file after testing, and is optional.
 *
 *   The pmem device must have a DAX-capable filesystem and be mounted
 *   with DAX enabled.  filename must point to a file on that filesystem.
 *
 *   Example:
 *     mkfs.xfs /dev/pmem0
 *     mkdir /mnt/pmem0
 *     mount -o dax /dev/pmem0 /mnt/pmem0
 *
 *   When specifying the filename, if the block pool file does not already
 *   exist, then the pmemblk engine creates the pool file if you specify
 *   the block and file sizes.  BSIZE is the block size in bytes.
 *   FSIZEMB is the pool file size in MiB.
 *
 *   See examples/pmemblk.fio for more.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/uio.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <libpmem.h>
#include <libpmemblk.h>

#include "../fio.h"

/*
 * libpmemblk
 */
typedef struct fio_pmemblk_file *fio_pmemblk_file_t;

struct fio_pmemblk_file {
	fio_pmemblk_file_t pmb_next;
	char *pmb_filename;
	uint64_t pmb_refcnt;
	PMEMblkpool *pmb_pool;
	size_t pmb_bsize;
	size_t pmb_nblocks;
};

static fio_pmemblk_file_t Cache;

static pthread_mutex_t CacheLock = PTHREAD_MUTEX_INITIALIZER;

#define PMB_CREATE   (0x0001)	/* should create file */

fio_pmemblk_file_t fio_pmemblk_cache_lookup(const char *filename)
{
	fio_pmemblk_file_t i;

	for (i = Cache; i != NULL; i = i->pmb_next)
		if (!strcmp(filename, i->pmb_filename))
			return i;

	return NULL;
}

static void fio_pmemblk_cache_insert(fio_pmemblk_file_t pmb)
{
	pmb->pmb_next = Cache;
	Cache = pmb;
}

static void fio_pmemblk_cache_remove(fio_pmemblk_file_t pmb)
{
	fio_pmemblk_file_t i;

	if (pmb == Cache) {
		Cache = Cache->pmb_next;
		pmb->pmb_next = NULL;
		return;
	}

	for (i = Cache; i != NULL; i = i->pmb_next)
		if (pmb == i->pmb_next) {
			i->pmb_next = i->pmb_next->pmb_next;
			pmb->pmb_next = NULL;
			return;
		}
}

/*
 * to control block size and gross file size at the libpmemblk
 * level, we allow the block size and file size to be appended
 * to the file name:
 *
 *   path[,bsize,fsizemib]
 *
 * note that we do not use the fio option "filesize" to dictate
 * the file size because we can only give libpmemblk the gross
 * file size, which is different from the net or usable file
 * size (which is probably what fio wants).
 *
 * the final path without the parameters is returned in ppath.
 * the block size and file size are returned in pbsize and fsize.
 *
 * note that the user specifies the file size in MiB, but
 * we return bytes from here.
 */
static void pmb_parse_path(const char *pathspec, char **ppath, uint64_t *pbsize,
			   uint64_t *pfsize)
{
	char *path;
	char *s;
	uint64_t bsize;
	uint64_t fsizemib;

	path = strdup(pathspec);
	if (!path) {
		*ppath = NULL;
		return;
	}

	/* extract sizes, if given */
	s = strrchr(path, ',');
	if (s && (fsizemib = strtoull(s + 1, NULL, 10))) {
		*s = 0;
		s = strrchr(path, ',');
		if (s && (bsize = strtoull(s + 1, NULL, 10))) {
			*s = 0;
			*ppath = path;
			*pbsize = bsize;
			*pfsize = fsizemib << 20;
			return;
		}
	}

	/* size specs not found */
	strcpy(path, pathspec);
	*ppath = path;
	*pbsize = 0;
	*pfsize = 0;
}

static fio_pmemblk_file_t pmb_open(const char *pathspec, int flags)
{
	fio_pmemblk_file_t pmb;
	char *path = NULL;
	uint64_t bsize = 0;
	uint64_t fsize = 0;

	pmb_parse_path(pathspec, &path, &bsize, &fsize);
	if (!path)
		return NULL;

	pthread_mutex_lock(&CacheLock);

	pmb = fio_pmemblk_cache_lookup(path);
	if (!pmb) {
		pmb = malloc(sizeof(*pmb));
		if (!pmb)
			goto error;

		/* try opening existing first, create it if needed */
		pmb->pmb_pool = pmemblk_open(path, bsize);
		if (!pmb->pmb_pool && (errno == ENOENT) &&
		    (flags & PMB_CREATE) && (0 < fsize) && (0 < bsize)) {
			pmb->pmb_pool =
			    pmemblk_create(path, bsize, fsize, 0644);
		}
		if (!pmb->pmb_pool) {
			log_err("pmemblk: unable to open pmemblk pool file %s (%s)\n",
			     path, strerror(errno));
			goto error;
		}

		pmb->pmb_filename = path;
		pmb->pmb_next = NULL;
		pmb->pmb_refcnt = 0;
		pmb->pmb_bsize = pmemblk_bsize(pmb->pmb_pool);
		pmb->pmb_nblocks = pmemblk_nblock(pmb->pmb_pool);

		fio_pmemblk_cache_insert(pmb);
	}

	pmb->pmb_refcnt += 1;

	pthread_mutex_unlock(&CacheLock);

	free(path);

	return pmb;

error:
	if (pmb) {
		if (pmb->pmb_pool)
			pmemblk_close(pmb->pmb_pool);
		pmb->pmb_pool = NULL;
		pmb->pmb_filename = NULL;
		free(pmb);
	}
	if (path)
		free(path);

	pthread_mutex_unlock(&CacheLock);
	return NULL;
}

static void pmb_close(fio_pmemblk_file_t pmb, const bool keep)
{
	pthread_mutex_lock(&CacheLock);

	pmb->pmb_refcnt--;

	if (!keep && !pmb->pmb_refcnt) {
		pmemblk_close(pmb->pmb_pool);
		pmb->pmb_pool = NULL;
		free(pmb->pmb_filename);
		pmb->pmb_filename = NULL;
		fio_pmemblk_cache_remove(pmb);
		free(pmb);
	}

	pthread_mutex_unlock(&CacheLock);
}

static int pmb_get_flags(struct thread_data *td, uint64_t *pflags)
{
	static int thread_warned = 0;
	static int odirect_warned = 0;

	uint64_t flags = 0;

	if (!td->o.use_thread) {
		if (!thread_warned) {
			thread_warned = 1;
			log_err("pmemblk: must set thread=1 for pmemblk engine\n");
		}
		return 1;
	}

	if (!td->o.odirect && !odirect_warned) {
		odirect_warned = 1;
		log_info("pmemblk: direct == 0, but pmemblk is always direct\n");
	}

	if (td->o.allow_create)
		flags |= PMB_CREATE;

	(*pflags) = flags;
	return 0;
}

static int fio_pmemblk_open_file(struct thread_data *td, struct fio_file *f)
{
	uint64_t flags = 0;
	fio_pmemblk_file_t pmb;

	if (pmb_get_flags(td, &flags))
		return 1;

	pmb = pmb_open(f->file_name, flags);
	if (!pmb)
		return 1;

	FILE_SET_ENG_DATA(f, pmb);
	return 0;
}

static int fio_pmemblk_close_file(struct thread_data fio_unused *td,
				  struct fio_file *f)
{
	fio_pmemblk_file_t pmb = FILE_ENG_DATA(f);

	if (pmb)
		pmb_close(pmb, false);

	FILE_SET_ENG_DATA(f, NULL);
	return 0;
}

static int fio_pmemblk_get_file_size(struct thread_data *td, struct fio_file *f)
{
	uint64_t flags = 0;
	fio_pmemblk_file_t pmb = FILE_ENG_DATA(f);

	if (fio_file_size_known(f))
		return 0;

	if (!pmb) {
		if (pmb_get_flags(td, &flags))
			return 1;
		pmb = pmb_open(f->file_name, flags);
		if (!pmb)
			return 1;
	}

	f->real_file_size = pmb->pmb_bsize * pmb->pmb_nblocks;

	fio_file_set_size_known(f);

	if (!FILE_ENG_DATA(f))
		pmb_close(pmb, true);

	return 0;
}

static enum fio_q_status fio_pmemblk_queue(struct thread_data *td,
					   struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	fio_pmemblk_file_t pmb = FILE_ENG_DATA(f);

	unsigned long long off;
	unsigned long len;
	void *buf;

	fio_ro_check(td, io_u);

	switch (io_u->ddir) {
	case DDIR_READ:
	case DDIR_WRITE:
		off = io_u->offset;
		len = io_u->xfer_buflen;

		io_u->error = EINVAL;
		if (off % pmb->pmb_bsize)
			break;
		if (len % pmb->pmb_bsize)
			break;
		if ((off + len) / pmb->pmb_bsize > pmb->pmb_nblocks)
			break;

		io_u->error = 0;
		buf = io_u->xfer_buf;
		off /= pmb->pmb_bsize;
		len /= pmb->pmb_bsize;
		while (0 < len) {
			if (io_u->ddir == DDIR_READ &&
			   0 != pmemblk_read(pmb->pmb_pool, buf, off)) {
				io_u->error = errno;
				break;
			} else if (0 != pmemblk_write(pmb->pmb_pool, buf, off)) {
				io_u->error = errno;
				break;
			}
			buf += pmb->pmb_bsize;
			off++;
			len--;
		}
		off *= pmb->pmb_bsize;
		len *= pmb->pmb_bsize;
		io_u->resid = io_u->xfer_buflen - (off - io_u->offset);
		break;
	case DDIR_SYNC:
	case DDIR_DATASYNC:
	case DDIR_SYNC_FILE_RANGE:
		/* we're always sync'd */
		io_u->error = 0;
		break;
	default:
		io_u->error = EINVAL;
		break;
	}

	return FIO_Q_COMPLETED;
}

static int fio_pmemblk_unlink_file(struct thread_data *td, struct fio_file *f)
{
	char *path = NULL;
	uint64_t bsize = 0;
	uint64_t fsize = 0;

	/*
	 * we need our own unlink in case the user has specified
	 * the block and file sizes in the path name.  we parse
	 * the file_name to determine the file name we actually used.
	 */

	pmb_parse_path(f->file_name, &path, &bsize, &fsize);
	if (!path)
		return ENOENT;

	unlink(path);
	free(path);
	return 0;
}

static struct ioengine_ops ioengine = {
	.name = "pmemblk",
	.version = FIO_IOOPS_VERSION,
	.queue = fio_pmemblk_queue,
	.open_file = fio_pmemblk_open_file,
	.close_file = fio_pmemblk_close_file,
	.get_file_size = fio_pmemblk_get_file_size,
	.unlink_file = fio_pmemblk_unlink_file,
	.flags = FIO_SYNCIO | FIO_DISKLESSIO | FIO_NOEXTEND | FIO_NODISKUTIL,
};

static void fio_init fio_pmemblk_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_pmemblk_unregister(void)
{
	unregister_ioengine(&ioengine);
}
