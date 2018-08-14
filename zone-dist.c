#include <stdlib.h>
#include "fio.h"
#include "zone-dist.h"

static void __td_zone_gen_index(struct thread_data *td, enum fio_ddir ddir)
{
	unsigned int i, j, sprev, aprev;
	uint64_t sprev_sz;

	td->zone_state_index[ddir] = malloc(sizeof(struct zone_split_index) * 100);

	sprev_sz = sprev = aprev = 0;
	for (i = 0; i < td->o.zone_split_nr[ddir]; i++) {
		struct zone_split *zsp = &td->o.zone_split[ddir][i];

		for (j = aprev; j < aprev + zsp->access_perc; j++) {
			struct zone_split_index *zsi = &td->zone_state_index[ddir][j];

			zsi->size_perc = sprev + zsp->size_perc;
			zsi->size_perc_prev = sprev;

			zsi->size = sprev_sz + zsp->size;
			zsi->size_prev = sprev_sz;
		}

		aprev += zsp->access_perc;
		sprev += zsp->size_perc;
		sprev_sz += zsp->size;
	}
}

static bool has_zones(struct thread_data *td)
{
	int i, zones = 0;

	for (i = 0; i < DDIR_RWDIR_CNT; i++)
		zones += td->o.zone_split_nr[i];

	return zones != 0;
}

/*
 * Generate state table for indexes, so we don't have to do it inline from
 * the hot IO path
 */
void td_zone_gen_index(struct thread_data *td)
{
	int i;

	if (!has_zones(td))
		return;

	td->zone_state_index = malloc(DDIR_RWDIR_CNT *
					sizeof(struct zone_split_index *));

	for (i = 0; i < DDIR_RWDIR_CNT; i++)
		__td_zone_gen_index(td, i);
}

void td_zone_free_index(struct thread_data *td)
{
	int i;

	if (!td->zone_state_index)
		return;

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		free(td->zone_state_index[i]);
		td->zone_state_index[i] = NULL;
	}

	free(td->zone_state_index);
	td->zone_state_index = NULL;
}
