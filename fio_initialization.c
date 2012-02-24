#include <locale.h>

#include "endian_check.h"
#include "smalloc.h"
#include "fio.h"


unsigned long page_mask;
unsigned long page_size;

int initialize_fio(char *envp[])
{
	long ps;

	if (endian_check()) {
		log_err("fio: endianness settings appear wrong.\n");
		log_err("fio: please report this to fio@vger.kernel.org\n");
		return 1;
	}

	arch_init(envp);

	sinit();

	/*
	 * We need locale for number printing, if it isn't set then just
	 * go with the US format.
	 */
	if (!getenv("LC_NUMERIC"))
		setlocale(LC_NUMERIC, "en_US");

	ps = sysconf(_SC_PAGESIZE);
	if (ps < 0) {
		log_err("Failed to get page size\n");
		return 1;
	}

	page_size = ps;
	page_mask = ps - 1;

	fio_keywords_init();
	return 0;
}
