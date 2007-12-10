#ifndef _INDIRECT_H_
#define _INDIRECT_H_

#include "syslet.h"

union indirect_params {
	struct {
		u32 flags;
	} file_flags;
	struct syslet_args syslet;
};

#ifdef __x86_64__
# define __NR_indirect 286
struct indirect_registers {
	u64 rax;
	u64 rdi;
	u64 rsi;
	u64 rdx;
	u64 r10;
	u64 r8;
	u64 r9;
};
#elif defined __i386__
# define __NR_indirect 325
struct indirect_registers {
	u32 eax;
	u32 ebx;
	u32 ecx;
	u32 edx;
	u32 esi;
	u32 edi;
	u32 ebp;
};
#endif

#define FILL_IN(var, values...) \
	  (var) = (struct indirect_registers) { values, }

#endif
