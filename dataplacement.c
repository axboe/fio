/*
 * Note: This is similar to a very basic setup
 * of ZBD devices
 *
 * Specify fdp=1 (With char devices /dev/ng0n1)
 */

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "fio.h"
#include "file.h"

#include "pshared.h"
#include "dataplacement.h"

static int fdp_ruh_info(struct thread_data *td, struct fio_file *f,
			struct fio_ruhs_info *ruhs)
{
	int ret = -EINVAL;

	if (!td->io_ops) {
		log_err("fio: no ops set in fdp init?!\n");
		return ret;
	}

	if (td->io_ops->fdp_fetch_ruhs) {
		ret = td->io_ops->fdp_fetch_ruhs(td, f, ruhs);
		if (ret < 0) {
			td_verror(td, errno, "fdp fetch ruhs failed");
			log_err("%s: fdp fetch ruhs failed (%d)\n",
				f->file_name, errno);
		}
	} else {
		log_err("%s: engine (%s) lacks fetch ruhs\n",
			f->file_name, td->io_ops->name);
	}

	return ret;
}

static int init_ruh_info(struct thread_data *td, struct fio_file *f)
{
	struct fio_ruhs_info *ruhs, *tmp;
	int i, ret;

	ruhs = scalloc(1, sizeof(*ruhs) + FDP_MAX_RUHS * sizeof(*ruhs->plis));
	if (!ruhs)
		return -ENOMEM;

	/* set up the data structure used for FDP to work with the supplied stream IDs */
	if (td->o.dp_type == FIO_DP_STREAMS) {
		if (!td->o.dp_nr_ids) {
			log_err("fio: stream IDs must be provided for dataplacement=streams\n");
			return -EINVAL;
		}
		ruhs->nr_ruhs = td->o.dp_nr_ids;
		for (int i = 0; i < ruhs->nr_ruhs; i++)
			ruhs->plis[i] = td->o.dp_ids[i];

		f->ruhs_info = ruhs;
		return 0;
	}

	ret = fdp_ruh_info(td, f, ruhs);
	if (ret) {
		log_info("fio: ruh info failed for %s (%d)\n",
			 f->file_name, -ret);
		goto out;
	}

	if (ruhs->nr_ruhs > FDP_MAX_RUHS)
		ruhs->nr_ruhs = FDP_MAX_RUHS;

	if (td->o.dp_nr_ids == 0) {
		f->ruhs_info = ruhs;
		return 0;
	}

	for (i = 0; i < td->o.dp_nr_ids; i++) {
		if (td->o.dp_ids[i] >= ruhs->nr_ruhs) {
			ret = -EINVAL;
			goto out;
		}
	}

	tmp = scalloc(1, sizeof(*tmp) + ruhs->nr_ruhs * sizeof(*tmp->plis));
	if (!tmp) {
		ret = -ENOMEM;
		goto out;
	}

	tmp->nr_ruhs = td->o.dp_nr_ids;
	for (i = 0; i < td->o.dp_nr_ids; i++)
		tmp->plis[i] = ruhs->plis[td->o.dp_ids[i]];
	f->ruhs_info = tmp;
out:
	sfree(ruhs);
	return ret;
}

int dp_init(struct thread_data *td)
{
	struct fio_file *f;
	int i, ret = 0;

	for_each_file(td, f, i) {
		ret = init_ruh_info(td, f);
		if (ret)
			break;
	}
	return ret;
}

void fdp_free_ruhs_info(struct fio_file *f)
{
	if (!f->ruhs_info)
		return;
	sfree(f->ruhs_info);
	f->ruhs_info = NULL;
}

void dp_fill_dspec_data(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	struct fio_ruhs_info *ruhs = f->ruhs_info;
	int dspec;

	if (!ruhs || io_u->ddir != DDIR_WRITE) {
		io_u->dtype = 0;
		io_u->dspec = 0;
		return;
	}

	if (td->o.dp_id_select == FIO_DP_RR) {
		if (ruhs->pli_loc >= ruhs->nr_ruhs)
			ruhs->pli_loc = 0;

		dspec = ruhs->plis[ruhs->pli_loc++];
	} else {
		ruhs->pli_loc = rand_between(&td->fdp_state, 0, ruhs->nr_ruhs - 1);
		dspec = ruhs->plis[ruhs->pli_loc];
	}

	io_u->dtype = td->o.dp_type == FIO_DP_FDP ? FDP_DIR_DTYPE : STREAMS_DIR_DTYPE;
	io_u->dspec = dspec;
	dprint(FD_IO, "dtype set to 0x%x, dspec set to 0x%x\n", io_u->dtype, io_u->dspec);
}
