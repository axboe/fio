#ifndef FIO_STAT_H
#define FIO_STAT_H

extern void add_clat_sample(struct thread_data *, int, unsigned long);
extern void add_slat_sample(struct thread_data *, int, unsigned long);
extern void add_bw_sample(struct thread_data *, int);
extern void show_run_stats(void);
extern void init_disk_util(struct thread_data *);
extern void update_rusage_stat(struct thread_data *);
extern void update_io_ticks(void);
extern void disk_util_timer_arm(void);
#endif
