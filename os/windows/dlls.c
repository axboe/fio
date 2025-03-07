#include "os/os.h"

#include <windows.h>

void os_clk_tck(long *clk_tck)
{
	/*
	 * The timer resolution is variable on Windows. Try to query it 
	 * or use 64 Hz, the clock frequency lower bound. See also
	 * https://carpediemsystems.co.uk/2019/07/18/windows-system-timer-granularity/.
	 */
	unsigned long minRes, maxRes, curRes;
	HMODULE lib;
	NTSTATUS NTAPI (*queryTimer)
		(OUT PULONG              MinimumResolution,
		 OUT PULONG              MaximumResolution,
		 OUT PULONG              CurrentResolution);
	NTSTATUS NTAPI (*setTimer)
		(IN ULONG                DesiredResolution,
		 IN BOOLEAN              SetResolution,
		 OUT PULONG              CurrentResolution);

	if (!(lib = LoadLibrary(TEXT("ntdll.dll"))) ||
		!(queryTimer = (void *)GetProcAddress(lib, "NtQueryTimerResolution")) ||
		!(setTimer = (void *)GetProcAddress(lib, "NtSetTimerResolution"))) {
		dprint(FD_HELPERTHREAD, 
			"Failed to load ntdll library, set to lower bound 64 Hz\n");
		*clk_tck = 64;
	} else {
		queryTimer(&minRes, &maxRes, &curRes);
		dprint(FD_HELPERTHREAD, 
			"minRes = %lu, maxRes = %lu, curRes = %lu\n",
			minRes, maxRes, curRes);

		/* Use maximum resolution for most accurate timestamps */
		setTimer(maxRes, 1, &curRes);
		*clk_tck = (long) (10000000L / maxRes);
	}
}
