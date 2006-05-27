#ifndef ARCH_X86_64_h
#define ARCH_X86_64_h

#define ARCH	(arch_x86_64)

#ifndef __NR_ioprio_set
#define __NR_ioprio_set		251
#define __NR_ioprio_get		252
#endif

#ifndef __NR_fadvise64
#define __NR_fadvise64		221
#endif

#ifndef __NR_sys_splice
#define __NR_sys_splice		275
#define __NR_sys_tee		276
#define __NR_sys_vmsplice	278
#endif

#define nop	__asm__ __volatile__("rep;nop": : :"memory")

static inline unsigned long ffz(unsigned long bitmask)
{
	__asm__("bsfq %1,%0" :"=r" (bitmask) :"r" (~bitmask));
	return bitmask;
}


#endif
