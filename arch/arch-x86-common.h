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

extern bool tsc_reliable;
extern int arch_random;

static inline void arch_init_intel(void)
{
	unsigned int eax, ebx, ecx = 0, edx;

	/*
	 * Check for TSC
	 */
	eax = 1;
	do_cpuid(&eax, &ebx, &ecx, &edx);
	if (!(edx & (1U << 4)))
		return;

	/*
	 * Check for constant rate and synced (across cores) TSC
	 */
	eax = 0x80000007;
	do_cpuid(&eax, &ebx, &ecx, &edx);
	tsc_reliable = (edx & (1U << 8)) != 0;

	/*
	 * Check for FDRAND
	 */
	eax = 0x1;
	do_cpuid(&eax, &ebx, &ecx, &edx);
	arch_random = (ecx & (1U << 30)) != 0;
}

static inline void arch_init_amd(void)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(0x80000000, &eax, &ebx, &ecx, &edx);
	if (eax < 0x80000007)
		return;

	cpuid(0x80000007, &eax, &ebx, &ecx, &edx);
	tsc_reliable = (edx & (1U << 8)) != 0;
}

static inline void arch_init(char *envp[])
{
	unsigned int level;
	char str[13];

	arch_random = tsc_reliable = 0;

	cpuid(0, &level, (unsigned int *) &str[0],
			 (unsigned int *) &str[8],
			 (unsigned int *) &str[4]);

	str[12] = '\0';
	if (!strcmp(str, "GenuineIntel"))
		arch_init_intel();
	else if (!strcmp(str, "AuthenticAMD") || !strcmp(str, "HygonGenuine"))
		arch_init_amd();
}

#endif
