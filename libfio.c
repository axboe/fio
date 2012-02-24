/*
 * fio - the flexible io tester
 *
 * Copyright (C) 2005 Jens Axboe <axboe@suse.de>
 * Copyright (C) 2006-2012 Jens Axboe <axboe@kernel.dk>
 *
 * The license below covers all files distributed with fio unless otherwise
 * noted in the file itself.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <stdint.h>
#include <locale.h>

#include "fio.h"
#include "smalloc.h"
#include "os/os.h"

/*
 * Just expose an empty list, if the OS does not support disk util stats
 */
#ifndef FIO_HAVE_DISK_UTIL
FLIST_HEAD(disk_list);
#endif

unsigned long arch_flags = 0;

unsigned long page_mask;
unsigned long page_size;

static const char *fio_os_strings[os_nr] = {
	"Invalid",
	"Linux",
	"AIX",
	"FreeBSD",
	"HP-UX",
	"OSX",
	"NetBSD",
	"Solaris",
	"Windows"
};

static const char *fio_arch_strings[arch_nr] = {
	"Invalid",
	"x86-64",
	"x86",
	"ppc",
	"ia64",
	"s390",
	"alpha",
	"sparc",
	"sparc64",
	"arm",
	"sh",
	"hppa",
	"generic"
};

static void reset_io_counters(struct thread_data *td)
{
	td->stat_io_bytes[0] = td->stat_io_bytes[1] = 0;
	td->this_io_bytes[0] = td->this_io_bytes[1] = 0;
	td->stat_io_blocks[0] = td->stat_io_blocks[1] = 0;
	td->this_io_blocks[0] = td->this_io_blocks[1] = 0;
	td->zone_bytes = 0;
	td->rate_bytes[0] = td->rate_bytes[1] = 0;
	td->rate_blocks[0] = td->rate_blocks[1] = 0;

	td->last_was_sync = 0;

	/*
	 * reset file done count if we are to start over
	 */
	if (td->o.time_based || td->o.loops)
		td->nr_done_files = 0;
}

void clear_io_state(struct thread_data *td)
{
	struct fio_file *f;
	unsigned int i;

	reset_io_counters(td);

	close_files(td);
	for_each_file(td, f, i)
		fio_file_clear_done(f);

	/*
	 * Set the same seed to get repeatable runs
	 */
	td_fill_rand_seeds(td);
}

void reset_all_stats(struct thread_data *td)
{
	struct timeval tv;
	int i;

	reset_io_counters(td);

	for (i = 0; i < 2; i++) {
		td->io_bytes[i] = 0;
		td->io_blocks[i] = 0;
		td->io_issues[i] = 0;
		td->ts.total_io_u[i] = 0;
	}

	fio_gettime(&tv, NULL);
	td->ts.runtime[0] = 0;
	td->ts.runtime[1] = 0;
	memcpy(&td->epoch, &tv, sizeof(tv));
	memcpy(&td->start, &tv, sizeof(tv));
}

void reset_fio_state(void)
{
	groupid = 0;
	thread_number = 0;
	nr_process = 0;
	nr_thread = 0;
	done_secs = 0;
}

const char *fio_get_os_string(int nr)
{
	if (nr < os_nr)
		return fio_os_strings[nr];

	return NULL;
}

const char *fio_get_arch_string(int nr)
{
	if (nr < arch_nr)
		return fio_arch_strings[nr];

	return NULL;
}

void td_set_runstate(struct thread_data *td, int runstate)
{
	if (td->runstate == runstate)
		return;

	dprint(FD_PROCESS, "pid=%d: runstate %d -> %d\n", (int) td->pid,
						td->runstate, runstate);
	td->runstate = runstate;
}

void fio_terminate_threads(int group_id)
{
	struct thread_data *td;
	int i;

	dprint(FD_PROCESS, "terminate group_id=%d\n", group_id);

	for_each_td(td, i) {
		if (group_id == TERMINATE_ALL || groupid == td->groupid) {
			dprint(FD_PROCESS, "setting terminate on %s/%d\n",
						td->o.name, (int) td->pid);
			td->terminate = 1;
			td->o.start_delay = 0;

			/*
			 * if the thread is running, just let it exit
			 */
			if (!td->pid)
				continue;
			else if (td->runstate < TD_RAMP)
				kill(td->pid, SIGTERM);
			else {
				struct ioengine_ops *ops = td->io_ops;

				if (ops && (ops->flags & FIO_SIGTERM))
					kill(td->pid, SIGTERM);
			}
		}
	}
}

static int endian_check(void)
{
	union {
		uint8_t c[8];
		uint64_t v;
	} u;
	int le = 0, be = 0;

	u.v = 0x12;
	if (u.c[7] == 0x12)
		be = 1;
	else if (u.c[0] == 0x12)
		le = 1;

#if defined(FIO_LITTLE_ENDIAN)
	if (be)
		return 1;
#elif defined(FIO_BIG_ENDIAN)
	if (le)
		return 1;
#else
	return 1;
#endif

	if (!le && !be)
		return 1;

	return 0;
}

int initialize_fio(char *envp[])
{
	long ps;

	if (endian_check()) {
		log_err("fio: endianness settings appear wrong.\n");
		log_err("fio: please report this to fio@vger.kernel.org\n");
		return 1;
	}

	arch_init(envp);

	sinit();

	/*
	 * We need locale for number printing, if it isn't set then just
	 * go with the US format.
	 */
	if (!getenv("LC_NUMERIC"))
		setlocale(LC_NUMERIC, "en_US");

	ps = sysconf(_SC_PAGESIZE);
	if (ps < 0) {
		log_err("Failed to get page size\n");
		return 1;
	}

	page_size = ps;
	page_mask = ps - 1;

	fio_keywords_init();
	return 0;
}
