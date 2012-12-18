#ifndef FIO_ARCH_X86_COMMON
#define FIO_ARCH_X86_COMMON

static inline void do_cpuid(unsigned int *eax, unsigned int *ebx,
			    unsigned int *ecx, unsigned int *edx)
{
	asm volatile("cpuid"
		: "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
		: "0" (*eax), "2" (*ecx)
		: "memory");
}

#define ARCH_HAVE_INIT
extern int tsc_reliable;
static inline int arch_init(char *envp[])
{
	unsigned int eax, ebx, ecx = 0, edx;

	/*
	 * Check for TSC
	 */
	eax = 1;
	do_cpuid(&eax, &ebx, &ecx, &edx);
	if (!(edx & (1U << 4)))
		return 0;

	/*
	 * Check for constant rate and synced (across cores) TSC
	 */
	eax = 0x80000007;
	do_cpuid(&eax, &ebx, &ecx, &edx);
	tsc_reliable = edx & (1U << 8);
	return 0;
}

#endif
