#ifndef _SYSLET_H_
#define _SYSLET_H_

#include "kcompat.h"

struct syslet_frame {
	u64 ip;
	u64 sp;
};

struct syslet_args {
	u64 ring_ptr;
	u64 caller_data;
	struct syslet_frame frame;
};

struct syslet_completion {
	u64 status;
	u64 caller_data;
};

struct syslet_ring {
	u32 kernel_head;
	u32 user_tail;
	u32 elements;
	u32 wait_group;
	struct syslet_completion comp[0];
};

#ifdef __x86_64__
#define __NR_syslet_ring_wait	287
#elif defined __i386__
#define __NR_syslet_ring_wait	326
#endif

#define ESYSLETPENDING   132

typedef void (*syslet_return_func_t)(void);

static inline void fill_syslet_args(struct syslet_args *args,
		      struct syslet_ring *ring, uint64_t caller_data,
		      syslet_return_func_t func, void *stack)
{
	args->ring_ptr = (u64)(unsigned long)ring;
	args->caller_data = caller_data;
	args->frame.ip = (u64)(unsigned long)func;
	args->frame.sp = (u64)(unsigned long)stack;
}

#endif
