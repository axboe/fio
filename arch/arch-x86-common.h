#ifndef FIO_ARCH_X86_COMMON
#define FIO_ARCH_X86_COMMON

#include <string.h>

static inline void cpuid(unsigned int op,
			 unsigned int *eax, unsigned int *ebx,
			 unsigned int *ecx, unsigned int *edx)
{
	*eax = op;
	*ecx = 0;
	do_cpuid(eax, ebx, ecx, edx);
}

#define ARCH_HAVE_INIT

extern int tsc_reliable;

static inline int arch_init_intel(unsigned int level)
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
	return edx & (1U << 8);
}

static inline int arch_init_amd(unsigned int level)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(0x80000000, &eax, &ebx, &ecx, &edx);
	if (eax < 0x80000007)
		return 0;

	cpuid(0x80000007, &eax, &ebx, &ecx, &edx);
	if (edx & (1 << 8))
		return 1;

	return 0;
}

static inline int arch_init(char *envp[])
{
	unsigned int level;
	char str[13];

	cpuid(0, &level, (unsigned int *) &str[0],
			 (unsigned int *) &str[8],
			 (unsigned int *) &str[4]);

	str[12] = '\0';
	if (!strcmp(str, "GenuineIntel"))
		tsc_reliable = arch_init_intel(level);
	else if (!strcmp(str, "AuthenticAMD"))
		tsc_reliable = arch_init_amd(level);

	return 0;
}

#endif
