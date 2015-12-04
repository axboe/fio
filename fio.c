/*
 * fio - the flexible io tester
 *
 * Copyright (C) 2005 Jens Axboe <axboe@suse.de>
 * Copyright (C) 2006-2012 Jens Axboe <axboe@kernel.dk>
 *
 * The license below covers all files distributed with fio unless otherwise
 * noted in the file itself.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */
#include <unistd.h>
#include <locale.h>
#include <time.h>

#include "fio.h"
#include "smalloc.h"

int main(int argc, char *argv[], char *envp[])
{
	int ret = 1;

	if (initialize_fio(envp))
		return 1;

#if !defined(CONFIG_GETTIMEOFDAY) && !defined(CONFIG_CLOCK_GETTIME)
#error "No available clock source!"
#endif

	if (parse_options(argc, argv))
		goto done;

	/*
	 * line buffer stdout to avoid output lines from multiple
	 * threads getting mixed
	 */
	setvbuf(stdout, NULL, _IOLBF, 0);

	fio_time_init();

	if (nr_clients) {
		set_genesis_time();

		if (fio_start_all_clients())
			goto done;
		ret = fio_handle_clients(&fio_client_ops);
	} else
		ret = fio_backend();

done:
	deinitialize_fio();
	return ret;
}
