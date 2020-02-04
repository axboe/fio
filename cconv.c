#include <string.h>

#include "log.h"
#include "thread_options.h"

static void string_to_cpu(char **dst, const uint8_t *src)
{
	const char *__src = (const char *) src;

	if (strlen(__src))
		*dst = strdup(__src);
}

static void __string_to_net(uint8_t *dst, const char *src, size_t dst_size)
{
	if (src)
		snprintf((char *) dst, dst_size, "%s", src);
	else
		dst[0] = '\0';
}

#define string_to_net(dst, src)	__string_to_net((dst), (src), sizeof(dst))

static void free_thread_options_to_cpu(struct thread_options *o)
{
	int i;

	free(o->description);
	free(o->name);
	free(o->wait_for);
	free(o->directory);
	free(o->filename);
	free(o->filename_format);
	free(o->opendir);
	free(o->ioengine);
	free(o->mmapfile);
	free(o->read_iolog_file);
	free(o->write_iolog_file);
	free(o->merge_blktrace_file);
	free(o->bw_log_file);
	free(o->lat_log_file);
	free(o->iops_log_file);
	free(o->hist_log_file);
	free(o->replay_redirect);
	free(o->exec_prerun);
	free(o->exec_postrun);
	free(o->ioscheduler);
	free(o->profile);
	free(o->cgroup);

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		free(o->bssplit[i]);
		free(o->zone_split[i]);
	}
}

void convert_thread_options_to_cpu(struct thread_options *o,
				   struct thread_options_pack *top)
{
	int i, j;

	for (i = 0; i < NR_OPTS_SZ; i++)
		o->set_options[i] = le64_to_cpu(top->set_options[i]);

	string_to_cpu(&o->description, top->description);
	string_to_cpu(&o->name, top->name);
	string_to_cpu(&o->wait_for, top->wait_for);
	string_to_cpu(&o->directory, top->directory);
	string_to_cpu(&o->filename, top->filename);
	string_to_cpu(&o->filename_format, top->filename_format);
	string_to_cpu(&o->opendir, top->opendir);
	string_to_cpu(&o->ioengine, top->ioengine);
	string_to_cpu(&o->mmapfile, top->mmapfile);
	string_to_cpu(&o->read_iolog_file, top->read_iolog_file);
	string_to_cpu(&o->write_iolog_file, top->write_iolog_file);
	string_to_cpu(&o->merge_blktrace_file, top->merge_blktrace_file);
	string_to_cpu(&o->bw_log_file, top->bw_log_file);
	string_to_cpu(&o->lat_log_file, top->lat_log_file);
	string_to_cpu(&o->iops_log_file, top->iops_log_file);
	string_to_cpu(&o->hist_log_file, top->hist_log_file);
	string_to_cpu(&o->replay_redirect, top->replay_redirect);
	string_to_cpu(&o->exec_prerun, top->exec_prerun);
	string_to_cpu(&o->exec_postrun, top->exec_postrun);
	string_to_cpu(&o->ioscheduler, top->ioscheduler);
	string_to_cpu(&o->profile, top->profile);
	string_to_cpu(&o->cgroup, top->cgroup);

	o->allow_create = le32_to_cpu(top->allow_create);
	o->allow_mounted_write = le32_to_cpu(top->allow_mounted_write);
	o->td_ddir = le32_to_cpu(top->td_ddir);
	o->rw_seq = le32_to_cpu(top->rw_seq);
	o->kb_base = le32_to_cpu(top->kb_base);
	o->unit_base = le32_to_cpu(top->unit_base);
	o->ddir_seq_nr = le32_to_cpu(top->ddir_seq_nr);
	o->ddir_seq_add = le64_to_cpu(top->ddir_seq_add);
	o->iodepth = le32_to_cpu(top->iodepth);
	o->iodepth_low = le32_to_cpu(top->iodepth_low);
	o->iodepth_batch = le32_to_cpu(top->iodepth_batch);
	o->iodepth_batch_complete_min = le32_to_cpu(top->iodepth_batch_complete_min);
	o->iodepth_batch_complete_max = le32_to_cpu(top->iodepth_batch_complete_max);
	o->serialize_overlap = le32_to_cpu(top->serialize_overlap);
	o->size = le64_to_cpu(top->size);
	o->io_size = le64_to_cpu(top->io_size);
	o->size_percent = le32_to_cpu(top->size_percent);
	o->fill_device = le32_to_cpu(top->fill_device);
	o->file_append = le32_to_cpu(top->file_append);
	o->file_size_low = le64_to_cpu(top->file_size_low);
	o->file_size_high = le64_to_cpu(top->file_size_high);
	o->start_offset = le64_to_cpu(top->start_offset);
	o->start_offset_align = le64_to_cpu(top->start_offset_align);
	o->start_offset_percent = le32_to_cpu(top->start_offset_percent);

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		o->bs[i] = le64_to_cpu(top->bs[i]);
		o->ba[i] = le64_to_cpu(top->ba[i]);
		o->min_bs[i] = le64_to_cpu(top->min_bs[i]);
		o->max_bs[i] = le64_to_cpu(top->max_bs[i]);
		o->bssplit_nr[i] = le32_to_cpu(top->bssplit_nr[i]);

		if (o->bssplit_nr[i]) {
			o->bssplit[i] = malloc(o->bssplit_nr[i] * sizeof(struct bssplit));
			for (j = 0; j < o->bssplit_nr[i]; j++) {
				o->bssplit[i][j].bs = le64_to_cpu(top->bssplit[i][j].bs);
				o->bssplit[i][j].perc = le32_to_cpu(top->bssplit[i][j].perc);
			}
		}

		o->zone_split_nr[i] = le32_to_cpu(top->zone_split_nr[i]);

		if (o->zone_split_nr[i]) {
			o->zone_split[i] = malloc(o->zone_split_nr[i] * sizeof(struct zone_split));
			for (j = 0; j < o->zone_split_nr[i]; j++) {
				o->zone_split[i][j].access_perc = top->zone_split[i][j].access_perc;
				o->zone_split[i][j].size_perc = top->zone_split[i][j].size_perc;
			}
		}

		o->rwmix[i] = le32_to_cpu(top->rwmix[i]);
		o->rate[i] = le64_to_cpu(top->rate[i]);
		o->ratemin[i] = le64_to_cpu(top->ratemin[i]);
		o->rate_iops[i] = le32_to_cpu(top->rate_iops[i]);
		o->rate_iops_min[i] = le32_to_cpu(top->rate_iops_min[i]);

		o->perc_rand[i] = le32_to_cpu(top->perc_rand[i]);
	}

	o->ratecycle = le32_to_cpu(top->ratecycle);
	o->io_submit_mode = le32_to_cpu(top->io_submit_mode);
	o->unique_filename = le32_to_cpu(top->unique_filename);
	o->nr_files = le32_to_cpu(top->nr_files);
	o->open_files = le32_to_cpu(top->open_files);
	o->file_lock_mode = le32_to_cpu(top->file_lock_mode);
	o->odirect = le32_to_cpu(top->odirect);
	o->oatomic = le32_to_cpu(top->oatomic);
	o->invalidate_cache = le32_to_cpu(top->invalidate_cache);
	o->create_serialize = le32_to_cpu(top->create_serialize);
	o->create_fsync = le32_to_cpu(top->create_fsync);
	o->create_on_open = le32_to_cpu(top->create_on_open);
	o->create_only = le32_to_cpu(top->create_only);
	o->end_fsync = le32_to_cpu(top->end_fsync);
	o->pre_read = le32_to_cpu(top->pre_read);
	o->sync_io = le32_to_cpu(top->sync_io);
	o->write_hint = le32_to_cpu(top->write_hint);
	o->verify = le32_to_cpu(top->verify);
	o->do_verify = le32_to_cpu(top->do_verify);
	o->experimental_verify = le32_to_cpu(top->experimental_verify);
	o->verify_state = le32_to_cpu(top->verify_state);
	o->verify_interval = le32_to_cpu(top->verify_interval);
	o->verify_offset = le32_to_cpu(top->verify_offset);

	memcpy(o->verify_pattern, top->verify_pattern, MAX_PATTERN_SIZE);
	memcpy(o->buffer_pattern, top->buffer_pattern, MAX_PATTERN_SIZE);

	o->verify_pattern_bytes = le32_to_cpu(top->verify_pattern_bytes);
	o->verify_fatal = le32_to_cpu(top->verify_fatal);
	o->verify_dump = le32_to_cpu(top->verify_dump);
	o->verify_async = le32_to_cpu(top->verify_async);
	o->verify_batch = le32_to_cpu(top->verify_batch);
	o->use_thread = le32_to_cpu(top->use_thread);
	o->unlink = le32_to_cpu(top->unlink);
	o->unlink_each_loop = le32_to_cpu(top->unlink_each_loop);
	o->do_disk_util = le32_to_cpu(top->do_disk_util);
	o->override_sync = le32_to_cpu(top->override_sync);
	o->rand_repeatable = le32_to_cpu(top->rand_repeatable);
	o->allrand_repeatable = le32_to_cpu(top->allrand_repeatable);
	o->rand_seed = le64_to_cpu(top->rand_seed);
	o->log_avg_msec = le32_to_cpu(top->log_avg_msec);
	o->log_hist_msec = le32_to_cpu(top->log_hist_msec);
	o->log_hist_coarseness = le32_to_cpu(top->log_hist_coarseness);
	o->log_max = le32_to_cpu(top->log_max);
	o->log_offset = le32_to_cpu(top->log_offset);
	o->log_gz = le32_to_cpu(top->log_gz);
	o->log_gz_store = le32_to_cpu(top->log_gz_store);
	o->log_unix_epoch = le32_to_cpu(top->log_unix_epoch);
	o->norandommap = le32_to_cpu(top->norandommap);
	o->softrandommap = le32_to_cpu(top->softrandommap);
	o->bs_unaligned = le32_to_cpu(top->bs_unaligned);
	o->fsync_on_close = le32_to_cpu(top->fsync_on_close);
	o->bs_is_seq_rand = le32_to_cpu(top->bs_is_seq_rand);
	o->random_distribution = le32_to_cpu(top->random_distribution);
	o->exitall_error = le32_to_cpu(top->exitall_error);
	o->zipf_theta.u.f = fio_uint64_to_double(le64_to_cpu(top->zipf_theta.u.i));
	o->pareto_h.u.f = fio_uint64_to_double(le64_to_cpu(top->pareto_h.u.i));
	o->gauss_dev.u.f = fio_uint64_to_double(le64_to_cpu(top->gauss_dev.u.i));
	o->random_generator = le32_to_cpu(top->random_generator);
	o->hugepage_size = le32_to_cpu(top->hugepage_size);
	o->rw_min_bs = le64_to_cpu(top->rw_min_bs);
	o->thinktime = le32_to_cpu(top->thinktime);
	o->thinktime_spin = le32_to_cpu(top->thinktime_spin);
	o->thinktime_blocks = le32_to_cpu(top->thinktime_blocks);
	o->fsync_blocks = le32_to_cpu(top->fsync_blocks);
	o->fdatasync_blocks = le32_to_cpu(top->fdatasync_blocks);
	o->barrier_blocks = le32_to_cpu(top->barrier_blocks);

	o->verify_backlog = le64_to_cpu(top->verify_backlog);
	o->start_delay = le64_to_cpu(top->start_delay);
	o->start_delay_high = le64_to_cpu(top->start_delay_high);
	o->timeout = le64_to_cpu(top->timeout);
	o->ramp_time = le64_to_cpu(top->ramp_time);
	o->ss_dur = le64_to_cpu(top->ss_dur);
	o->ss_ramp_time = le64_to_cpu(top->ss_ramp_time);
	o->ss_state = le32_to_cpu(top->ss_state);
	o->ss_limit.u.f = fio_uint64_to_double(le64_to_cpu(top->ss_limit.u.i));
	o->zone_range = le64_to_cpu(top->zone_range);
	o->zone_size = le64_to_cpu(top->zone_size);
	o->zone_skip = le64_to_cpu(top->zone_skip);
	o->zone_mode = le32_to_cpu(top->zone_mode);
	o->lockmem = le64_to_cpu(top->lockmem);
	o->offset_increment_percent = le32_to_cpu(top->offset_increment_percent);
	o->offset_increment = le64_to_cpu(top->offset_increment);
	o->number_ios = le64_to_cpu(top->number_ios);

	o->overwrite = le32_to_cpu(top->overwrite);
	o->bw_avg_time = le32_to_cpu(top->bw_avg_time);
	o->iops_avg_time = le32_to_cpu(top->iops_avg_time);
	o->loops = le32_to_cpu(top->loops);
	o->mem_type = le32_to_cpu(top->mem_type);
	o->mem_align = le32_to_cpu(top->mem_align);
	o->exit_what = le16_to_cpu(top->exit_what);
	o->stonewall = le16_to_cpu(top->stonewall);
	o->new_group = le32_to_cpu(top->new_group);
	o->numjobs = le32_to_cpu(top->numjobs);
	o->cpus_allowed_policy = le32_to_cpu(top->cpus_allowed_policy);
	o->gpu_dev_id = le32_to_cpu(top->gpu_dev_id);
	o->iolog = le32_to_cpu(top->iolog);
	o->rwmixcycle = le32_to_cpu(top->rwmixcycle);
	o->nice = le32_to_cpu(top->nice);
	o->ioprio = le32_to_cpu(top->ioprio);
	o->ioprio_class = le32_to_cpu(top->ioprio_class);
	o->file_service_type = le32_to_cpu(top->file_service_type);
	o->group_reporting = le32_to_cpu(top->group_reporting);
	o->stats = le32_to_cpu(top->stats);
	o->fadvise_hint = le32_to_cpu(top->fadvise_hint);
	o->fallocate_mode = le32_to_cpu(top->fallocate_mode);
	o->zero_buffers = le32_to_cpu(top->zero_buffers);
	o->refill_buffers = le32_to_cpu(top->refill_buffers);
	o->scramble_buffers = le32_to_cpu(top->scramble_buffers);
	o->buffer_pattern_bytes = le32_to_cpu(top->buffer_pattern_bytes);
	o->time_based = le32_to_cpu(top->time_based);
	o->disable_lat = le32_to_cpu(top->disable_lat);
	o->disable_clat = le32_to_cpu(top->disable_clat);
	o->disable_slat = le32_to_cpu(top->disable_slat);
	o->disable_bw = le32_to_cpu(top->disable_bw);
	o->unified_rw_rep = le32_to_cpu(top->unified_rw_rep);
	o->gtod_reduce = le32_to_cpu(top->gtod_reduce);
	o->gtod_cpu = le32_to_cpu(top->gtod_cpu);
	o->clocksource = le32_to_cpu(top->clocksource);
	o->no_stall = le32_to_cpu(top->no_stall);
	o->trim_percentage = le32_to_cpu(top->trim_percentage);
	o->trim_batch = le32_to_cpu(top->trim_batch);
	o->trim_zero = le32_to_cpu(top->trim_zero);
	o->clat_percentiles = le32_to_cpu(top->clat_percentiles);
	o->lat_percentiles = le32_to_cpu(top->lat_percentiles);
	o->slat_percentiles = le32_to_cpu(top->slat_percentiles);
	o->percentile_precision = le32_to_cpu(top->percentile_precision);
	o->sig_figs = le32_to_cpu(top->sig_figs);
	o->continue_on_error = le32_to_cpu(top->continue_on_error);
	o->cgroup_weight = le32_to_cpu(top->cgroup_weight);
	o->cgroup_nodelete = le32_to_cpu(top->cgroup_nodelete);
	o->uid = le32_to_cpu(top->uid);
	o->gid = le32_to_cpu(top->gid);
	o->flow_id = __le32_to_cpu(top->flow_id);
	o->flow = __le32_to_cpu(top->flow);
	o->flow_watermark = __le32_to_cpu(top->flow_watermark);
	o->flow_sleep = le32_to_cpu(top->flow_sleep);
	o->sync_file_range = le32_to_cpu(top->sync_file_range);
	o->latency_target = le64_to_cpu(top->latency_target);
	o->latency_window = le64_to_cpu(top->latency_window);
	o->max_latency = le64_to_cpu(top->max_latency);
	o->latency_percentile.u.f = fio_uint64_to_double(le64_to_cpu(top->latency_percentile.u.i));
	o->compress_percentage = le32_to_cpu(top->compress_percentage);
	o->compress_chunk = le32_to_cpu(top->compress_chunk);
	o->dedupe_percentage = le32_to_cpu(top->dedupe_percentage);
	o->block_error_hist = le32_to_cpu(top->block_error_hist);
	o->replay_align = le32_to_cpu(top->replay_align);
	o->replay_scale = le32_to_cpu(top->replay_scale);
	o->replay_time_scale = le32_to_cpu(top->replay_time_scale);
	o->replay_skip = le32_to_cpu(top->replay_skip);
	o->per_job_logs = le32_to_cpu(top->per_job_logs);
	o->write_bw_log = le32_to_cpu(top->write_bw_log);
	o->write_lat_log = le32_to_cpu(top->write_lat_log);
	o->write_iops_log = le32_to_cpu(top->write_iops_log);
	o->write_hist_log = le32_to_cpu(top->write_hist_log);

	o->trim_backlog = le64_to_cpu(top->trim_backlog);
	o->rate_process = le32_to_cpu(top->rate_process);
	o->rate_ign_think = le32_to_cpu(top->rate_ign_think);

	for (i = 0; i < FIO_IO_U_LIST_MAX_LEN; i++)
		o->percentile_list[i].u.f = fio_uint64_to_double(le64_to_cpu(top->percentile_list[i].u.i));

	for (i = 0; i < FIO_IO_U_LIST_MAX_LEN; i++)
		o->merge_blktrace_scalars[i].u.f = fio_uint64_to_double(le64_to_cpu(top->merge_blktrace_scalars[i].u.i));

	for (i = 0; i < FIO_IO_U_LIST_MAX_LEN; i++)
		o->merge_blktrace_iters[i].u.f = fio_uint64_to_double(le64_to_cpu(top->merge_blktrace_iters[i].u.i));
#if 0
	uint8_t cpumask[FIO_TOP_STR_MAX];
	uint8_t verify_cpumask[FIO_TOP_STR_MAX];
	uint8_t log_gz_cpumask[FIO_TOP_STR_MAX];
#endif
}

void convert_thread_options_to_net(struct thread_options_pack *top,
				   struct thread_options *o)
{
	int i, j;

	for (i = 0; i < NR_OPTS_SZ; i++)
		top->set_options[i] = cpu_to_le64(o->set_options[i]);

	string_to_net(top->description, o->description);
	string_to_net(top->name, o->name);
	string_to_net(top->wait_for, o->wait_for);
	string_to_net(top->directory, o->directory);
	string_to_net(top->filename, o->filename);
	string_to_net(top->filename_format, o->filename_format);
	string_to_net(top->opendir, o->opendir);
	string_to_net(top->ioengine, o->ioengine);
	string_to_net(top->mmapfile, o->mmapfile);
	string_to_net(top->read_iolog_file, o->read_iolog_file);
	string_to_net(top->write_iolog_file, o->write_iolog_file);
	string_to_net(top->merge_blktrace_file, o->merge_blktrace_file);
	string_to_net(top->bw_log_file, o->bw_log_file);
	string_to_net(top->lat_log_file, o->lat_log_file);
	string_to_net(top->iops_log_file, o->iops_log_file);
	string_to_net(top->hist_log_file, o->hist_log_file);
	string_to_net(top->replay_redirect, o->replay_redirect);
	string_to_net(top->exec_prerun, o->exec_prerun);
	string_to_net(top->exec_postrun, o->exec_postrun);
	string_to_net(top->ioscheduler, o->ioscheduler);
	string_to_net(top->profile, o->profile);
	string_to_net(top->cgroup, o->cgroup);

	top->allow_create = cpu_to_le32(o->allow_create);
	top->allow_mounted_write = cpu_to_le32(o->allow_mounted_write);
	top->td_ddir = cpu_to_le32(o->td_ddir);
	top->rw_seq = cpu_to_le32(o->rw_seq);
	top->kb_base = cpu_to_le32(o->kb_base);
	top->unit_base = cpu_to_le32(o->unit_base);
	top->ddir_seq_nr = cpu_to_le32(o->ddir_seq_nr);
	top->iodepth = cpu_to_le32(o->iodepth);
	top->iodepth_low = cpu_to_le32(o->iodepth_low);
	top->iodepth_batch = cpu_to_le32(o->iodepth_batch);
	top->iodepth_batch_complete_min = cpu_to_le32(o->iodepth_batch_complete_min);
	top->iodepth_batch_complete_max = cpu_to_le32(o->iodepth_batch_complete_max);
	top->serialize_overlap = cpu_to_le32(o->serialize_overlap);
	top->size_percent = cpu_to_le32(o->size_percent);
	top->fill_device = cpu_to_le32(o->fill_device);
	top->file_append = cpu_to_le32(o->file_append);
	top->ratecycle = cpu_to_le32(o->ratecycle);
	top->io_submit_mode = cpu_to_le32(o->io_submit_mode);
	top->nr_files = cpu_to_le32(o->nr_files);
	top->unique_filename = cpu_to_le32(o->unique_filename);
	top->open_files = cpu_to_le32(o->open_files);
	top->file_lock_mode = cpu_to_le32(o->file_lock_mode);
	top->odirect = cpu_to_le32(o->odirect);
	top->oatomic = cpu_to_le32(o->oatomic);
	top->invalidate_cache = cpu_to_le32(o->invalidate_cache);
	top->create_serialize = cpu_to_le32(o->create_serialize);
	top->create_fsync = cpu_to_le32(o->create_fsync);
	top->create_on_open = cpu_to_le32(o->create_on_open);
	top->create_only = cpu_to_le32(o->create_only);
	top->end_fsync = cpu_to_le32(o->end_fsync);
	top->pre_read = cpu_to_le32(o->pre_read);
	top->sync_io = cpu_to_le32(o->sync_io);
	top->write_hint = cpu_to_le32(o->write_hint);
	top->verify = cpu_to_le32(o->verify);
	top->do_verify = cpu_to_le32(o->do_verify);
	top->experimental_verify = cpu_to_le32(o->experimental_verify);
	top->verify_state = cpu_to_le32(o->verify_state);
	top->verify_interval = cpu_to_le32(o->verify_interval);
	top->verify_offset = cpu_to_le32(o->verify_offset);
	top->verify_pattern_bytes = cpu_to_le32(o->verify_pattern_bytes);
	top->verify_fatal = cpu_to_le32(o->verify_fatal);
	top->verify_dump = cpu_to_le32(o->verify_dump);
	top->verify_async = cpu_to_le32(o->verify_async);
	top->verify_batch = cpu_to_le32(o->verify_batch);
	top->use_thread = cpu_to_le32(o->use_thread);
	top->unlink = cpu_to_le32(o->unlink);
	top->unlink_each_loop = cpu_to_le32(o->unlink_each_loop);
	top->do_disk_util = cpu_to_le32(o->do_disk_util);
	top->override_sync = cpu_to_le32(o->override_sync);
	top->rand_repeatable = cpu_to_le32(o->rand_repeatable);
	top->allrand_repeatable = cpu_to_le32(o->allrand_repeatable);
	top->rand_seed = __cpu_to_le64(o->rand_seed);
	top->log_avg_msec = cpu_to_le32(o->log_avg_msec);
	top->log_max = cpu_to_le32(o->log_max);
	top->log_offset = cpu_to_le32(o->log_offset);
	top->log_gz = cpu_to_le32(o->log_gz);
	top->log_gz_store = cpu_to_le32(o->log_gz_store);
	top->log_unix_epoch = cpu_to_le32(o->log_unix_epoch);
	top->norandommap = cpu_to_le32(o->norandommap);
	top->softrandommap = cpu_to_le32(o->softrandommap);
	top->bs_unaligned = cpu_to_le32(o->bs_unaligned);
	top->fsync_on_close = cpu_to_le32(o->fsync_on_close);
	top->bs_is_seq_rand = cpu_to_le32(o->bs_is_seq_rand);
	top->random_distribution = cpu_to_le32(o->random_distribution);
	top->exitall_error = cpu_to_le32(o->exitall_error);
	top->zipf_theta.u.i = __cpu_to_le64(fio_double_to_uint64(o->zipf_theta.u.f));
	top->pareto_h.u.i = __cpu_to_le64(fio_double_to_uint64(o->pareto_h.u.f));
	top->gauss_dev.u.i = __cpu_to_le64(fio_double_to_uint64(o->gauss_dev.u.f));
	top->random_generator = cpu_to_le32(o->random_generator);
	top->hugepage_size = cpu_to_le32(o->hugepage_size);
	top->rw_min_bs = __cpu_to_le64(o->rw_min_bs);
	top->thinktime = cpu_to_le32(o->thinktime);
	top->thinktime_spin = cpu_to_le32(o->thinktime_spin);
	top->thinktime_blocks = cpu_to_le32(o->thinktime_blocks);
	top->fsync_blocks = cpu_to_le32(o->fsync_blocks);
	top->fdatasync_blocks = cpu_to_le32(o->fdatasync_blocks);
	top->barrier_blocks = cpu_to_le32(o->barrier_blocks);
	top->overwrite = cpu_to_le32(o->overwrite);
	top->bw_avg_time = cpu_to_le32(o->bw_avg_time);
	top->iops_avg_time = cpu_to_le32(o->iops_avg_time);
	top->loops = cpu_to_le32(o->loops);
	top->mem_type = cpu_to_le32(o->mem_type);
	top->mem_align = cpu_to_le32(o->mem_align);
	top->exit_what = cpu_to_le16(o->exit_what);
	top->stonewall = cpu_to_le16(o->stonewall);
	top->new_group = cpu_to_le32(o->new_group);
	top->numjobs = cpu_to_le32(o->numjobs);
	top->cpus_allowed_policy = cpu_to_le32(o->cpus_allowed_policy);
	top->gpu_dev_id = cpu_to_le32(o->gpu_dev_id);
	top->iolog = cpu_to_le32(o->iolog);
	top->rwmixcycle = cpu_to_le32(o->rwmixcycle);
	top->nice = cpu_to_le32(o->nice);
	top->ioprio = cpu_to_le32(o->ioprio);
	top->ioprio_class = cpu_to_le32(o->ioprio_class);
	top->file_service_type = cpu_to_le32(o->file_service_type);
	top->group_reporting = cpu_to_le32(o->group_reporting);
	top->stats = cpu_to_le32(o->stats);
	top->fadvise_hint = cpu_to_le32(o->fadvise_hint);
	top->fallocate_mode = cpu_to_le32(o->fallocate_mode);
	top->zero_buffers = cpu_to_le32(o->zero_buffers);
	top->refill_buffers = cpu_to_le32(o->refill_buffers);
	top->scramble_buffers = cpu_to_le32(o->scramble_buffers);
	top->buffer_pattern_bytes = cpu_to_le32(o->buffer_pattern_bytes);
	top->time_based = cpu_to_le32(o->time_based);
	top->disable_lat = cpu_to_le32(o->disable_lat);
	top->disable_clat = cpu_to_le32(o->disable_clat);
	top->disable_slat = cpu_to_le32(o->disable_slat);
	top->disable_bw = cpu_to_le32(o->disable_bw);
	top->unified_rw_rep = cpu_to_le32(o->unified_rw_rep);
	top->gtod_reduce = cpu_to_le32(o->gtod_reduce);
	top->gtod_cpu = cpu_to_le32(o->gtod_cpu);
	top->clocksource = cpu_to_le32(o->clocksource);
	top->no_stall = cpu_to_le32(o->no_stall);
	top->trim_percentage = cpu_to_le32(o->trim_percentage);
	top->trim_batch = cpu_to_le32(o->trim_batch);
	top->trim_zero = cpu_to_le32(o->trim_zero);
	top->clat_percentiles = cpu_to_le32(o->clat_percentiles);
	top->lat_percentiles = cpu_to_le32(o->lat_percentiles);
	top->slat_percentiles = cpu_to_le32(o->slat_percentiles);
	top->percentile_precision = cpu_to_le32(o->percentile_precision);
	top->sig_figs = cpu_to_le32(o->sig_figs);
	top->continue_on_error = cpu_to_le32(o->continue_on_error);
	top->cgroup_weight = cpu_to_le32(o->cgroup_weight);
	top->cgroup_nodelete = cpu_to_le32(o->cgroup_nodelete);
	top->uid = cpu_to_le32(o->uid);
	top->gid = cpu_to_le32(o->gid);
	top->flow_id = __cpu_to_le32(o->flow_id);
	top->flow = __cpu_to_le32(o->flow);
	top->flow_watermark = __cpu_to_le32(o->flow_watermark);
	top->flow_sleep = cpu_to_le32(o->flow_sleep);
	top->sync_file_range = cpu_to_le32(o->sync_file_range);
	top->latency_target = __cpu_to_le64(o->latency_target);
	top->latency_window = __cpu_to_le64(o->latency_window);
	top->max_latency = __cpu_to_le64(o->max_latency);
	top->latency_percentile.u.i = __cpu_to_le64(fio_double_to_uint64(o->latency_percentile.u.f));
	top->compress_percentage = cpu_to_le32(o->compress_percentage);
	top->compress_chunk = cpu_to_le32(o->compress_chunk);
	top->dedupe_percentage = cpu_to_le32(o->dedupe_percentage);
	top->block_error_hist = cpu_to_le32(o->block_error_hist);
	top->replay_align = cpu_to_le32(o->replay_align);
	top->replay_scale = cpu_to_le32(o->replay_scale);
	top->replay_time_scale = cpu_to_le32(o->replay_time_scale);
	top->replay_skip = cpu_to_le32(o->replay_skip);
	top->per_job_logs = cpu_to_le32(o->per_job_logs);
	top->write_bw_log = cpu_to_le32(o->write_bw_log);
	top->write_lat_log = cpu_to_le32(o->write_lat_log);
	top->write_iops_log = cpu_to_le32(o->write_iops_log);
	top->write_hist_log = cpu_to_le32(o->write_hist_log);

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		top->bs[i] = __cpu_to_le64(o->bs[i]);
		top->ba[i] = __cpu_to_le64(o->ba[i]);
		top->min_bs[i] = __cpu_to_le64(o->min_bs[i]);
		top->max_bs[i] = __cpu_to_le64(o->max_bs[i]);
		top->bssplit_nr[i] = cpu_to_le32(o->bssplit_nr[i]);

		if (o->bssplit_nr[i]) {
			unsigned int bssplit_nr = o->bssplit_nr[i];

			if (bssplit_nr > BSSPLIT_MAX) {
				log_err("fio: BSSPLIT_MAX is too small\n");
				bssplit_nr = BSSPLIT_MAX;
			}
			for (j = 0; j < bssplit_nr; j++) {
				top->bssplit[i][j].bs = cpu_to_le64(o->bssplit[i][j].bs);
				top->bssplit[i][j].perc = cpu_to_le32(o->bssplit[i][j].perc);
			}
		}

		top->zone_split_nr[i] = cpu_to_le32(o->zone_split_nr[i]);

		if (o->zone_split_nr[i]) {
			unsigned int zone_split_nr = o->zone_split_nr[i];

			if (zone_split_nr > ZONESPLIT_MAX) {
				log_err("fio: ZONESPLIT_MAX is too small\n");
				zone_split_nr = ZONESPLIT_MAX;
			}
			for (j = 0; j < zone_split_nr; j++) {
				top->zone_split[i][j].access_perc = o->zone_split[i][j].access_perc;
				top->zone_split[i][j].size_perc = o->zone_split[i][j].size_perc;
			}
		}

		top->rwmix[i] = cpu_to_le32(o->rwmix[i]);
		top->rate[i] = cpu_to_le64(o->rate[i]);
		top->ratemin[i] = cpu_to_le64(o->ratemin[i]);
		top->rate_iops[i] = cpu_to_le32(o->rate_iops[i]);
		top->rate_iops_min[i] = cpu_to_le32(o->rate_iops_min[i]);

		top->perc_rand[i] = cpu_to_le32(o->perc_rand[i]);
	}

	memcpy(top->verify_pattern, o->verify_pattern, MAX_PATTERN_SIZE);
	memcpy(top->buffer_pattern, o->buffer_pattern, MAX_PATTERN_SIZE);

	top->size = __cpu_to_le64(o->size);
	top->io_size = __cpu_to_le64(o->io_size);
	top->verify_backlog = __cpu_to_le64(o->verify_backlog);
	top->start_delay = __cpu_to_le64(o->start_delay);
	top->start_delay_high = __cpu_to_le64(o->start_delay_high);
	top->timeout = __cpu_to_le64(o->timeout);
	top->ramp_time = __cpu_to_le64(o->ramp_time);
	top->ss_dur = __cpu_to_le64(top->ss_dur);
	top->ss_ramp_time = __cpu_to_le64(top->ss_ramp_time);
	top->ss_state = cpu_to_le32(top->ss_state);
	top->ss_limit.u.i = __cpu_to_le64(fio_double_to_uint64(o->ss_limit.u.f));
	top->zone_range = __cpu_to_le64(o->zone_range);
	top->zone_size = __cpu_to_le64(o->zone_size);
	top->zone_skip = __cpu_to_le64(o->zone_skip);
	top->zone_mode = __cpu_to_le32(o->zone_mode);
	top->lockmem = __cpu_to_le64(o->lockmem);
	top->ddir_seq_add = __cpu_to_le64(o->ddir_seq_add);
	top->file_size_low = __cpu_to_le64(o->file_size_low);
	top->file_size_high = __cpu_to_le64(o->file_size_high);
	top->start_offset = __cpu_to_le64(o->start_offset);
	top->start_offset_align = __cpu_to_le64(o->start_offset_align);
	top->start_offset_percent = __cpu_to_le32(o->start_offset_percent);
	top->trim_backlog = __cpu_to_le64(o->trim_backlog);
	top->offset_increment_percent = __cpu_to_le32(o->offset_increment_percent);
	top->offset_increment = __cpu_to_le64(o->offset_increment);
	top->number_ios = __cpu_to_le64(o->number_ios);
	top->rate_process = cpu_to_le32(o->rate_process);
	top->rate_ign_think = cpu_to_le32(o->rate_ign_think);

	for (i = 0; i < FIO_IO_U_LIST_MAX_LEN; i++)
		top->percentile_list[i].u.i = __cpu_to_le64(fio_double_to_uint64(o->percentile_list[i].u.f));

	for (i = 0; i < FIO_IO_U_LIST_MAX_LEN; i++)
		top->merge_blktrace_scalars[i].u.i = __cpu_to_le64(fio_double_to_uint64(o->merge_blktrace_scalars[i].u.f));

	for (i = 0; i < FIO_IO_U_LIST_MAX_LEN; i++)
		top->merge_blktrace_iters[i].u.i = __cpu_to_le64(fio_double_to_uint64(o->merge_blktrace_iters[i].u.f));
#if 0
	uint8_t cpumask[FIO_TOP_STR_MAX];
	uint8_t verify_cpumask[FIO_TOP_STR_MAX];
	uint8_t log_gz_cpumask[FIO_TOP_STR_MAX];
#endif

}

/*
 * Basic conversion test. We'd really need to fill in more of the options
 * to have a thorough test. Even better, we should auto-generate the
 * converter functions...
 */
int fio_test_cconv(struct thread_options *__o)
{
	struct thread_options o;
	struct thread_options_pack top1, top2;

	memset(&top1, 0, sizeof(top1));
	memset(&top2, 0, sizeof(top2));

	convert_thread_options_to_net(&top1, __o);
	memset(&o, 0, sizeof(o));
	convert_thread_options_to_cpu(&o, &top1);
	convert_thread_options_to_net(&top2, &o);

	free_thread_options_to_cpu(&o);

	return memcmp(&top1, &top2, sizeof(top1));
}
