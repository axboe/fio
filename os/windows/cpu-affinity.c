#include "os/os.h"

#include <windows.h>

static void print_mask(os_cpu_mask_t *cpumask)
{
	for (int i = 0; i < FIO_CPU_MASK_ROWS; i++)
		dprint(FD_PROCESS, "cpumask[%d]=%" PRIu64 "\n", i, cpumask->row[i]);
}

/* Return the index of the least significant set CPU in cpumask or -1 if no
 * CPUs are set */
int first_set_cpu(os_cpu_mask_t *cpumask)
{
	int cpus_offset, mask_first_cpu, row;

	cpus_offset = 0;
	row = 0;
	mask_first_cpu = -1;
	while (mask_first_cpu < 0 && row < FIO_CPU_MASK_ROWS) {
		int row_first_cpu;

		row_first_cpu = __builtin_ffsll(cpumask->row[row]) - 1;
		dprint(FD_PROCESS, "row_first_cpu=%d cpumask->row[%d]=%" PRIu64 "\n",
		       row_first_cpu, row, cpumask->row[row]);
		if (row_first_cpu > -1) {
			mask_first_cpu = cpus_offset + row_first_cpu;
			dprint(FD_PROCESS, "first set cpu in mask is at index %d\n",
			       mask_first_cpu);
		} else {
			cpus_offset += FIO_CPU_MASK_STRIDE;
			row++;
		}
	}

	return mask_first_cpu;
}

/* Return the index of the most significant set CPU in cpumask or -1 if no
 * CPUs are set */
static int last_set_cpu(os_cpu_mask_t *cpumask)
{
	int cpus_offset, mask_last_cpu, row;

	cpus_offset = (FIO_CPU_MASK_ROWS - 1) * FIO_CPU_MASK_STRIDE;
	row = FIO_CPU_MASK_ROWS - 1;
	mask_last_cpu = -1;
	while (mask_last_cpu < 0 && row >= 0) {
		int row_last_cpu;

		if (cpumask->row[row] == 0)
			row_last_cpu = -1;
		else {
			uint64_t tmp = cpumask->row[row];

			row_last_cpu = 0;
			while (tmp >>= 1)
			    row_last_cpu++;
		}

		dprint(FD_PROCESS, "row_last_cpu=%d cpumask->row[%d]=%" PRIu64 "\n",
		       row_last_cpu, row, cpumask->row[row]);
		if (row_last_cpu > -1) {
			mask_last_cpu = cpus_offset + row_last_cpu;
			dprint(FD_PROCESS, "last set cpu in mask is at index %d\n",
			       mask_last_cpu);
		} else {
			cpus_offset -= FIO_CPU_MASK_STRIDE;
			row--;
		}
	}

	return mask_last_cpu;
}

static int mask_to_group_mask(os_cpu_mask_t *cpumask, int *processor_group, uint64_t *affinity_mask)
{
	WORD online_groups, group, group_size;
	bool found;
	int cpus_offset, search_cpu, last_cpu, bit_offset, row, end;
	uint64_t group_cpumask;

	search_cpu = first_set_cpu(cpumask);
	if (search_cpu < 0) {
		log_info("CPU mask doesn't set any CPUs\n");
		return 1;
	}

	/* Find processor group first set CPU applies to */
	online_groups = GetActiveProcessorGroupCount();
	group = 0;
	found = false;
	cpus_offset = 0;
	group_size = 0;
	while (!found && group < online_groups) {
		group_size = GetActiveProcessorCount(group);
		dprint(FD_PROCESS, "group=%d group_start=%d group_size=%u search_cpu=%d\n",
		       group, cpus_offset, group_size, search_cpu);
		if (cpus_offset + group_size > search_cpu)
			found = true;
		else {
			cpus_offset += group_size;
			group++;
		}
	}

	if (!found) {
		log_err("CPU mask contains processor beyond last active processor index (%d)\n",
			 cpus_offset - 1);
		print_mask(cpumask);
		return 1;
	}

	/* Check all the CPUs in the mask apply to ONLY that processor group */
	last_cpu = last_set_cpu(cpumask);
	if (last_cpu > (cpus_offset + group_size - 1)) {
		log_info("CPU mask cannot bind CPUs (e.g. %d, %d) that are "
			 "in different processor groups\n", search_cpu,
			 last_cpu);
		print_mask(cpumask);
		return 1;
	}

	/* Extract the current processor group mask from the cpumask */
	row = cpus_offset / FIO_CPU_MASK_STRIDE;
	bit_offset = cpus_offset % FIO_CPU_MASK_STRIDE;
	group_cpumask = cpumask->row[row] >> bit_offset;
	end = bit_offset + group_size;
	if (end > FIO_CPU_MASK_STRIDE && (row + 1 < FIO_CPU_MASK_ROWS)) {
		/* Some of the next row needs to be part of the mask */
		int needed, needed_shift, needed_mask_shift;
		uint64_t needed_mask;

		needed = end - FIO_CPU_MASK_STRIDE;
		needed_shift = FIO_CPU_MASK_STRIDE - bit_offset;
		needed_mask_shift = FIO_CPU_MASK_STRIDE - needed;
		needed_mask = (uint64_t)-1 >> needed_mask_shift;
		dprint(FD_PROCESS,
		       "bit_offset=%d end=%d needed=%d needed_shift=%d needed_mask=%" PRIu64 "needed_mask_shift=%d\n",
		       bit_offset, end, needed, needed_shift, needed_mask,
		       needed_mask_shift);
		group_cpumask |= (cpumask->row[row + 1] & needed_mask) << needed_shift;
	}
	group_cpumask &= (uint64_t)-1 >> (FIO_CPU_MASK_STRIDE - group_size);

	/* Return group and mask */
	dprint(FD_PROCESS, "Returning group=%d group_mask=%" PRIu64 "\n",
	       group, group_cpumask);
	*processor_group = group;
	*affinity_mask = group_cpumask;

	return 0;
}

int fio_setaffinity(int pid, os_cpu_mask_t cpumask)
{
	HANDLE handle = NULL;
	int group, ret;
	uint64_t group_mask = 0;
	GROUP_AFFINITY new_group_affinity;

	ret = -1;

	if (mask_to_group_mask(&cpumask, &group, &group_mask) != 0)
		goto err;

	handle = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION,
			    TRUE, pid);
	if (handle == NULL) {
		log_err("fio_setaffinity: failed to get handle for pid %d\n", pid);
		goto err;
	}

	/* Set group and mask.
	 * Note: if the GROUP_AFFINITY struct's Reserved members are not
	 * initialised to 0 then SetThreadGroupAffinity will fail with
	 * GetLastError() set to ERROR_INVALID_PARAMETER */
	new_group_affinity.Mask = (KAFFINITY) group_mask;
	new_group_affinity.Group = group;
	new_group_affinity.Reserved[0] = 0;
	new_group_affinity.Reserved[1] = 0;
	new_group_affinity.Reserved[2] = 0;
	if (SetThreadGroupAffinity(handle, &new_group_affinity, NULL) != 0)
		ret = 0;
	else {
		log_err("fio_setaffinity: failed to set thread affinity (pid %d, group %d, mask %" PRIx64 ", GetLastError=%lu)\n",
			pid, group, group_mask, GetLastError());
		goto err;
	}

err:
	if (handle)
		CloseHandle(handle);
	return ret;
}

static void cpu_to_row_offset(int cpu, int *row, int *offset)
{
	*row = cpu / FIO_CPU_MASK_STRIDE;
	*offset = cpu << FIO_CPU_MASK_STRIDE * *row;
}

int fio_cpuset_init(os_cpu_mask_t *mask)
{
	for (int i = 0; i < FIO_CPU_MASK_ROWS; i++)
		mask->row[i] = 0;
	return 0;
}

/*
 * fio_getaffinity() should not be called once a fio_setaffinity() call has
 * been made because fio_setaffinity() may put the process into multiple
 * processor groups
 */
int fio_getaffinity(int pid, os_cpu_mask_t *mask)
{
	int ret;
	int row, offset, end, group, group_size, group_start_cpu;
	DWORD_PTR process_mask, system_mask;
	HANDLE handle;
	PUSHORT current_groups;
	USHORT group_count;
	WORD online_groups;

	ret = -1;
	current_groups = NULL;
	handle = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
	if (handle == NULL) {
		log_err("fio_getaffinity: failed to get handle for pid %d\n",
			pid);
		goto err;
	}

	group_count = 16;
	/*
	 * GetProcessGroupAffinity() seems to expect more than the natural
	 * alignment for a USHORT from the area pointed to by current_groups so
	 * arrange for maximum alignment by allocating via malloc()
	 */
	current_groups = malloc(group_count * sizeof(USHORT));
	if (!current_groups) {
		log_err("fio_getaffinity: malloc failed\n");
		goto err;
	}
	if (!GetProcessGroupAffinity(handle, &group_count, current_groups)) {
		log_err("%s: failed to get single group affinity for pid %d (%lu)\n",
			__func__, pid, GetLastError());
		goto err;
	}
	if (group_count > 1) {
		log_err("%s: pid %d is associated with %d process groups\n",
			__func__, pid, group_count);
		goto err;
	}
	if (!GetProcessAffinityMask(handle, &process_mask, &system_mask)) {
		log_err("%s: GetProcessAffinityMask() failed for pid %d\n",
			__func__, pid);
		goto err;
	}

	/* Convert group and group relative mask to full CPU mask */
	online_groups = GetActiveProcessorGroupCount();
	if (online_groups == 0) {
		log_err("fio_getaffinity: error retrieving total processor groups\n");
		goto err;
	}

	group = 0;
	group_start_cpu = 0;
	group_size = 0;
	dprint(FD_PROCESS, "current_groups=%d group_count=%d\n",
	       current_groups[0], group_count);
	while (true) {
		group_size = GetActiveProcessorCount(group);
		if (group_size == 0) {
			log_err("fio_getaffinity: error retrieving size of "
				"processor group %d\n", group);
			goto err;
		} else if (group >= current_groups[0] || group >= online_groups)
			break;
		else {
			group_start_cpu += group_size;
			group++;
		}
	}

	if (group != current_groups[0]) {
		log_err("fio_getaffinity: could not find processor group %d\n",
			current_groups[0]);
		goto err;
	}

	dprint(FD_PROCESS, "group_start_cpu=%d, group size=%u\n",
	       group_start_cpu, group_size);
	if ((group_start_cpu + group_size) >= FIO_MAX_CPUS) {
		log_err("fio_getaffinity failed: current CPU affinity (group "
			"%d, group_start_cpu %d, group_size %d) extends "
			"beyond mask's highest CPU (%d)\n", group,
			group_start_cpu, group_size, FIO_MAX_CPUS);
		goto err;
	}

	fio_cpuset_init(mask);
	cpu_to_row_offset(group_start_cpu, &row, &offset);
	mask->row[row] = process_mask;
	mask->row[row] <<= offset;
	end = offset + group_size;
	if (end > FIO_CPU_MASK_STRIDE) {
		int needed;
		uint64_t needed_mask;

		needed = FIO_CPU_MASK_STRIDE - end;
		needed_mask = (uint64_t)-1 >> (FIO_CPU_MASK_STRIDE - needed);
		row++;
		mask->row[row] = process_mask;
		mask->row[row] >>= needed;
		mask->row[row] &= needed_mask;
	}
	ret = 0;

err:
	if (handle)
		CloseHandle(handle);
	if (current_groups)
		free(current_groups);

	return ret;
}

void fio_cpu_clear(os_cpu_mask_t *mask, int cpu)
{
	int row, offset;
	cpu_to_row_offset(cpu, &row, &offset);

	mask->row[row] &= ~(1ULL << offset);
}

void fio_cpu_set(os_cpu_mask_t *mask, int cpu)
{
	int row, offset;
	cpu_to_row_offset(cpu, &row, &offset);

	mask->row[row] |= 1ULL << offset;
}

int fio_cpu_isset(os_cpu_mask_t *mask, int cpu)
{
	int row, offset;
	cpu_to_row_offset(cpu, &row, &offset);

	return (mask->row[row] & (1ULL << offset)) != 0;
}

int fio_cpu_count(os_cpu_mask_t *mask)
{
	int count = 0;

	for (int i = 0; i < FIO_CPU_MASK_ROWS; i++)
		count += hweight64(mask->row[i]);

	return count;
}

int fio_cpuset_exit(os_cpu_mask_t *mask)
{
	return 0;
}
