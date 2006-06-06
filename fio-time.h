#ifndef FIO_TIME_H
#define FIO_TIME_H

extern unsigned long utime_since(struct timeval *, struct timeval *);
extern unsigned long mtime_since(struct timeval *, struct timeval *);
extern unsigned long mtime_since_now(struct timeval *);
extern unsigned long time_since_now(struct timeval *);
extern void usec_sleep(struct thread_data *, unsigned long);

extern void rate_throttle(struct thread_data *, unsigned long, unsigned int);

#endif
