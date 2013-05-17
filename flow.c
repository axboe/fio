#include "fio.h"
#include "mutex.h"
#include "smalloc.h"
#include "flist.h"

struct fio_flow {
	unsigned int refs;
	struct flist_head list;
	unsigned int id;
	long long int flow_counter;
};

static struct flist_head *flow_list;
static struct fio_mutex *flow_lock;

int flow_threshold_exceeded(struct thread_data *td)
{
	struct fio_flow *flow = td->flow;
	int sign;

	if (!flow)
		return 0;

	sign = td->o.flow > 0 ? 1 : -1;
	if (sign * flow->flow_counter > td->o.flow_watermark) {
		if (td->o.flow_sleep) {
			io_u_quiesce(td);
			usleep(td->o.flow_sleep);
		}

		return 1;
	}

	/* No synchronization needed because it doesn't
	 * matter if the flow count is slightly inaccurate */
	flow->flow_counter += td->o.flow;
	return 0;
}

static struct fio_flow *flow_get(unsigned int id)
{
	struct fio_flow *flow = NULL;
	struct flist_head *n;

	if (!flow_lock)
		return NULL;

	fio_mutex_down(flow_lock);

	flist_for_each(n, flow_list) {
		flow = flist_entry(n, struct fio_flow, list);
		if (flow->id == id)
			break;

		flow = NULL;
	}

	if (!flow) {
		flow = smalloc(sizeof(*flow));
		if (!flow) {
			log_err("fio: smalloc pool exhausted\n");
			return NULL;
		}
		flow->refs = 0;
		INIT_FLIST_HEAD(&flow->list);
		flow->id = id;
		flow->flow_counter = 0;

		flist_add_tail(&flow->list, flow_list);
	}

	flow->refs++;
	fio_mutex_up(flow_lock);
	return flow;
}

static void flow_put(struct fio_flow *flow)
{
	if (!flow_lock)
		return;

	fio_mutex_down(flow_lock);

	if (!--flow->refs) {
		flist_del(&flow->list);
		sfree(flow);
	}

	fio_mutex_up(flow_lock);
}

void flow_init_job(struct thread_data *td)
{
	if (td->o.flow)
		td->flow = flow_get(td->o.flow_id);
}

void flow_exit_job(struct thread_data *td)
{
	if (td->flow) {
		flow_put(td->flow);
		td->flow = NULL;
	}
}

void flow_init(void)
{
	flow_list = smalloc(sizeof(*flow_list));
	if (!flow_list) {
		log_err("fio: smalloc pool exhausted\n");
		return;
	}

	flow_lock = fio_mutex_init(FIO_MUTEX_UNLOCKED);
	if (!flow_lock) {
		log_err("fio: failed to allocate flow lock\n");
		sfree(flow_list);
		return;
	}

	INIT_FLIST_HEAD(flow_list);
}

void flow_exit(void)
{
	if (flow_lock)
		fio_mutex_remove(flow_lock);
	if (flow_list)
		sfree(flow_list);
}
