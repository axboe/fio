#ifndef FIO_STEADYSTATE_H
#define FIO_STEADYSTATE_H

extern void steadystate_check(void);
extern void steadystate_setup(void);
extern bool steadystate_deviation(unsigned long, unsigned long, struct thread_data *);
extern bool steadystate_slope(unsigned long, unsigned long, struct thread_data *);
#endif

