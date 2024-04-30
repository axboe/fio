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

static int init_ruh_scheme(struct thread_data *td, struct fio_file *f)
{
	struct fio_ruhs_scheme *ruh_scheme;
	FILE *scheme_fp;
	unsigned long long start, end;
	uint16_t pli;
	int ret = 0;

	if (td->o.dp_id_select != FIO_DP_SCHEME)
		return 0;

	/* Get the scheme from the file */
	scheme_fp = fopen(td->o.dp_scheme_file, "r");

	if (!scheme_fp) {
		log_err("fio: ruh scheme failed to open scheme file %s\n",
			 td->o.dp_scheme_file);
		ret = -errno;
		goto out;
	}

	ruh_scheme = scalloc(1, sizeof(*ruh_scheme));
	if (!ruh_scheme) {
		ret = -ENOMEM;
		goto out_with_close_fp;
	}

	for (int i = 0;
		i < DP_MAX_SCHEME_ENTRIES && fscanf(scheme_fp, "%llu,%llu,%hu\n", &start, &end, &pli) == 3;
		i++) {

		ruh_scheme->scheme_entries[i].start_offset = start;
		ruh_scheme->scheme_entries[i].end_offset = end;
		ruh_scheme->scheme_entries[i].pli = pli;
		ruh_scheme->nr_schemes++;
	}

	if (fscanf(scheme_fp, "%llu,%llu,%hu\n", &start, &end, &pli) == 3)
		log_info("fio: too many scheme entries in %s. Only the first %d scheme entries are applied\n",
			 td->o.dp_scheme_file,
			 DP_MAX_SCHEME_ENTRIES);

	f->ruhs_scheme = ruh_scheme;

out_with_close_fp:
	fclose(scheme_fp);
out:
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

		ret = init_ruh_scheme(td, f);
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

	if (!f->ruhs_scheme)
		return;
	sfree(f->ruhs_scheme);
	f->ruhs_scheme = NULL;
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
	} else if (td->o.dp_id_select == FIO_DP_SCHEME) {
		struct fio_ruhs_scheme *ruhs_scheme = f->ruhs_scheme;
		unsigned long long offset = io_u->offset;
		int i;

		for (i = 0; i < ruhs_scheme->nr_schemes; i++) {
			if (offset >= ruhs_scheme->scheme_entries[i].start_offset &&
			    offset < ruhs_scheme->scheme_entries[i].end_offset) {
				dspec = ruhs_scheme->scheme_entries[i].pli;
				break;
			}
		}

		/*
		 * If the write offset is not affected by any scheme entry,
		 * 0(default RUH) will be assigned to dspec
		 */
		if (i == ruhs_scheme->nr_schemes)
			dspec = 0;
	} else {
		ruhs->pli_loc = rand_between(&td->fdp_state, 0, ruhs->nr_ruhs - 1);
		dspec = ruhs->plis[ruhs->pli_loc];
	}

	io_u->dtype = td->o.dp_type == FIO_DP_FDP ? FDP_DIR_DTYPE : STREAMS_DIR_DTYPE;
	io_u->dspec = dspec;
	dprint(FD_IO, "dtype set to 0x%x, dspec set to 0x%x\n", io_u->dtype, io_u->dspec);
}
