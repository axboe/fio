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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <locale.h>
#include <fcntl.h>

#include "fio.h"
#include "smalloc.h"
#include "os/os.h"
#include "filelock.h"
#include "helper_thread.h"
#include "filehash.h"

FLIST_HEAD(disk_list);

unsigned long arch_flags = 0;

uintptr_t page_mask = 0;
uintptr_t page_size = 0;

/* see os/os.h */
static const char *fio_os_strings[os_nr] = {
	"Invalid",
	"Linux",
	"AIX",
	"FreeBSD",
	"HP-UX",
	"OSX",
	"NetBSD",
	"OpenBSD",
	"Solaris",
	"Windows",
	"Android",
	"DragonFly",
};

/* see arch/arch.h */
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
	"mips",
	"aarch64",
	"loongarch64",
	"riscv64",
	"generic"
};

static void reset_io_counters(struct thread_data *td, int all)
{
	int ddir;

	if (all) {
		for (ddir = 0; ddir < DDIR_RWDIR_CNT; ddir++) {
			td->stat_io_bytes[ddir] = 0;
			td->this_io_bytes[ddir] = 0;
			td->stat_io_blocks[ddir] = 0;
			td->this_io_blocks[ddir] = 0;
			td->last_rate_check_bytes[ddir] = 0;
			td->last_rate_check_blocks[ddir] = 0;
			td->bytes_done[ddir] = 0;
			td->rate_io_issue_bytes[ddir] = 0;
			td->rate_next_io_time[ddir] = 0;
			td->last_usec[ddir] = 0;
		}
		td->bytes_verified = 0;
	}

	td->zone_bytes = 0;

	td->rwmix_issues = 0;

	/*
	 * reset file done count if we are to start over
	 */
	if (td->o.time_based || td->loops > 1 || td->o.do_verify)
		td->nr_done_files = 0;
}

void clear_io_state(struct thread_data *td, int all)
{
	struct fio_file *f;
	unsigned int i;

	reset_io_counters(td, all);

	close_files(td);
	for_each_file(td, f, i) {
		fio_file_clear_done(f);
		f->file_offset = get_start_offset(td, f);
	}

	/*
	 * Re-Seed random number generator if rand_repeatable is true
	 */
	if (td->o.rand_repeatable)
		td_fill_rand_seeds(td);

	clear_inflight(td);
}

void reset_all_stats(struct thread_data *td)
{
	unsigned long long b;
	int i;

	reset_io_counters(td, 1);

	b = ddir_rw_sum(td->thinktime_blocks_counter);
	td->last_thinktime_blocks -= b;

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		td->io_bytes[i] = 0;
		td->io_blocks[i] = 0;
		td->io_issues[i] = 0;
		td->ts.total_io_u[i] = 0;
		td->ts.runtime[i] = 0;
	}

	set_epoch_time(td, td->o.log_alternate_epoch_clock_id, td->o.job_start_clock_id);
	memcpy(&td->start, &td->epoch, sizeof(td->epoch));
	memcpy(&td->iops_sample_time, &td->epoch, sizeof(td->epoch));
	memcpy(&td->bw_sample_time, &td->epoch, sizeof(td->epoch));
	memcpy(&td->ss.prev_time, &td->epoch, sizeof(td->epoch));

	td->last_thinktime = td->epoch;

	lat_target_reset(td);
	clear_rusage_stat(td);
	helper_reset();
}

void reset_fio_state(void)
{
	int i;

	groupid = 0;
	thread_number = 0;
	cur_segment = 0;
	for (i = 0; i < nr_segments; i++)
		segments[i].nr_threads = 0;
	stat_number = 0;
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

static const char *td_runstates[] = {
	"NOT_CREATED",
	"CREATED",
	"INITIALIZED",
	"RAMP",
	"SETTING_UP",
	"RUNNING",
	"PRE_READING",
	"VERIFYING",
	"FSYNCING",
	"FINISHING",
	"EXITED",
	"REAPED",
};

const char *runstate_to_name(int runstate)
{
	compiletime_assert(TD_LAST == 12, "td runstate list");
	if (runstate >= 0 && runstate < TD_LAST)
		return td_runstates[runstate];

	return "invalid";
}

void td_set_runstate(struct thread_data *td, int runstate)
{
	if (td->runstate == runstate)
		return;

	dprint(FD_PROCESS, "pid=%d: runstate %s -> %s\n", (int) td->pid,
						runstate_to_name(td->runstate),
						runstate_to_name(runstate));
	td->runstate = runstate;
}

int td_bump_runstate(struct thread_data *td, int new_state)
{
	int old_state = td->runstate;

	td_set_runstate(td, new_state);
	return old_state;
}

void td_restore_runstate(struct thread_data *td, int old_state)
{
	td_set_runstate(td, old_state);
}

void fio_mark_td_terminate(struct thread_data *td)
{
	fio_gettime(&td->terminate_time, NULL);
	write_barrier();
	td->terminate = true;
}

void fio_terminate_threads(unsigned int group_id, unsigned int terminate)
{
	pid_t pid = getpid();

	dprint(FD_PROCESS, "terminate group_id=%d\n", group_id);

	for_each_td(td) {
		if ((terminate == TERMINATE_GROUP && group_id == TERMINATE_ALL) ||
		    (terminate == TERMINATE_GROUP && group_id == td->groupid) ||
		    (terminate == TERMINATE_STONEWALL && td->runstate >= TD_RUNNING) ||
		    (terminate == TERMINATE_ALL)) {
			dprint(FD_PROCESS, "setting terminate on %s/%d\n",
						td->o.name, (int) td->pid);

			if (td->terminate)
				continue;

			fio_mark_td_terminate(td);
			td->o.start_delay = 0;

			/*
			 * if the thread is running, just let it exit
			 */
			if (!td->pid || pid == td->pid)
				continue;
			else if (td->runstate < TD_RAMP)
				kill(td->pid, SIGTERM);
			else {
				struct ioengine_ops *ops = td->io_ops;

				if (ops && ops->terminate)
					ops->terminate(td);
			}
		}
	} end_for_each();
}

int fio_running_or_pending_io_threads(void)
{
	int nr_io_threads = 0;

	for_each_td(td) {
		if (td->io_ops_init && td_ioengine_flagged(td, FIO_NOIO))
			continue;
		nr_io_threads++;
		if (td->runstate < TD_EXITED)
			return 1;
	} end_for_each();

	if (!nr_io_threads)
		return -1; /* we only had cpuio threads to begin with */
	return 0;
}

int fio_set_fd_nonblocking(int fd, const char *who)
{
	int flags;

	flags = fcntl(fd, F_GETFL);
	if (flags < 0)
		log_err("fio: %s failed to get file flags: %s\n", who, strerror(errno));
	else {
		int new_flags = flags | O_NONBLOCK;

		new_flags = fcntl(fd, F_SETFL, new_flags);
		if (new_flags < 0)
			log_err("fio: %s failed to get file flags: %s\n", who, strerror(errno));
	}

	return flags;
}

enum {
	ENDIAN_INVALID_BE = 1,
	ENDIAN_INVALID_LE,
	ENDIAN_INVALID_CONFIG,
	ENDIAN_BROKEN,
};

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

#if defined(CONFIG_LITTLE_ENDIAN)
	if (be)
		return ENDIAN_INVALID_BE;
#elif defined(CONFIG_BIG_ENDIAN)
	if (le)
		return ENDIAN_INVALID_LE;
#else
	return ENDIAN_INVALID_CONFIG;
#endif

	if (!le && !be)
		return ENDIAN_BROKEN;

	return 0;
}

int initialize_fio(char *envp[])
{
	long ps;
	int err;

	/*
	 * We need these to be properly 64-bit aligned, otherwise we
	 * can run into problems on archs that fault on unaligned fp
	 * access (ARM).
	 */
	compiletime_assert((offsetof(struct thread_data, ts) % sizeof(void *)) == 0, "ts");
	compiletime_assert((offsetof(struct thread_stat, percentile_list) % 8) == 0, "stat percentile_list");
	compiletime_assert((offsetof(struct thread_stat, total_run_time) % 8) == 0, "total_run_time");
	compiletime_assert((offsetof(struct thread_stat, total_err_count) % 8) == 0, "total_err_count");
	compiletime_assert((offsetof(struct thread_stat, latency_percentile) % 8) == 0, "stat latency_percentile");
	compiletime_assert((offsetof(struct thread_data, ts.clat_stat) % 8) == 0, "ts.clat_stat");
	compiletime_assert((offsetof(struct thread_options_pack, zipf_theta) % 8) == 0, "zipf_theta");
	compiletime_assert((offsetof(struct thread_options_pack, pareto_h) % 8) == 0, "pareto_h");
	compiletime_assert((offsetof(struct thread_options_pack, percentile_list) % 8) == 0, "percentile_list");
	compiletime_assert((offsetof(struct thread_options_pack, latency_percentile) % 8) == 0, "latency_percentile");
	compiletime_assert((offsetof(struct jobs_eta, m_rate) % 8) == 0, "m_rate");

	compiletime_assert(__TD_F_LAST <= TD_ENG_FLAG_SHIFT, "TD_ENG_FLAG_SHIFT");
	compiletime_assert((__TD_F_LAST + __FIO_IOENGINE_F_LAST) <= 8*sizeof(((struct thread_data *)0)->flags), "td->flags");
	compiletime_assert(BSSPLIT_MAX <= ZONESPLIT_MAX, "bsssplit/zone max");

	err = endian_check();
	if (err) {
		log_err("fio: endianness settings appear wrong.\n");
		switch (err) {
		case ENDIAN_INVALID_BE:
			log_err("fio: got big-endian when configured for little\n");
			break;
		case ENDIAN_INVALID_LE:
			log_err("fio: got little-endian when configured for big\n");
			break;
		case ENDIAN_INVALID_CONFIG:
			log_err("fio: not configured to any endianness\n");
			break;
		case ENDIAN_BROKEN:
			log_err("fio: failed to detect endianness\n");
			break;
		default:
			assert(0);
			break;
		}
		log_err("fio: please report this to fio@vger.kernel.org\n");
		return 1;
	}

	arch_init(envp);

	sinit();

	if (fio_filelock_init()) {
		log_err("fio: failed initializing filelock subsys\n");
		return 1;
	}

	file_hash_init();

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

void deinitialize_fio(void)
{
	fio_keywords_exit();
}
