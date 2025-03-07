#include "fio.h"
#include "fio_sem.h"
#include "smalloc.h"
#include "flist.h"

struct fio_flow {
	unsigned int refs;
	unsigned int id;
	struct flist_head list;
	unsigned long flow_counter;
	unsigned int total_weight;
};

static struct flist_head *flow_list;
static struct fio_sem *flow_lock;

int flow_threshold_exceeded(struct thread_data *td)
{
	struct fio_flow *flow = td->flow;
	double flow_counter_ratio, flow_weight_ratio;

	if (!flow)
		return 0;

	flow_counter_ratio = (double)td->flow_counter /
		atomic_load_relaxed(&flow->flow_counter);
	flow_weight_ratio = (double)td->o.flow /
		atomic_load_relaxed(&flow->total_weight);

	/*
	 * each thread/process executing a fio job will stall based on the
	 * expected  user ratio for a given flow_id group. the idea is to keep
	 * 2 counters, flow and job-specific counter to test if the
	 * ratio between them is proportional to other jobs in the same flow_id
	 */
	if (flow_counter_ratio > flow_weight_ratio) {
		if (td->o.flow_sleep) {
			io_u_quiesce(td);
			usleep(td->o.flow_sleep);
		} else if (td->o.zone_mode == ZONE_MODE_ZBD) {
			io_u_quiesce(td);
		}

		return 1;
	}

	/*
	 * increment flow(shared counter, therefore atomically)
	 * and job-specific counter
	 */
	atomic_add(&flow->flow_counter, 1);
	++td->flow_counter;

	return 0;
}

static struct fio_flow *flow_get(unsigned int id)
{
	struct fio_flow *flow = NULL;
	struct flist_head *n;

	if (!flow_lock)
		return NULL;

	fio_sem_down(flow_lock);

	flist_for_each(n, flow_list) {
		flow = flist_entry(n, struct fio_flow, list);
		if (flow->id == id)
			break;

		flow = NULL;
	}

	if (!flow) {
		flow = smalloc(sizeof(*flow));
		if (!flow) {
			fio_sem_up(flow_lock);
			return NULL;
		}
		flow->refs = 0;
		INIT_FLIST_HEAD(&flow->list);
		flow->id = id;
		flow->flow_counter = 1;
		flow->total_weight = 0;

		flist_add_tail(&flow->list, flow_list);
	}

	flow->refs++;
	fio_sem_up(flow_lock);
	return flow;
}

static void flow_put(struct fio_flow *flow, unsigned long flow_counter,
				        unsigned int weight)
{
	if (!flow_lock)
		return;

	fio_sem_down(flow_lock);

	atomic_sub(&flow->flow_counter, flow_counter);
	atomic_sub(&flow->total_weight, weight);

	if (!--flow->refs) {
		assert(flow->flow_counter == 1);
		flist_del(&flow->list);
		sfree(flow);
	}

	fio_sem_up(flow_lock);
}

void flow_init_job(struct thread_data *td)
{
	if (td->o.flow) {
		td->flow = flow_get(td->o.flow_id);
		td->flow_counter = 0;
		atomic_add(&td->flow->total_weight, td->o.flow);
	}
}

void flow_exit_job(struct thread_data *td)
{
	if (td->flow) {
		flow_put(td->flow, td->flow_counter, td->o.flow);
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

	flow_lock = fio_sem_init(FIO_SEM_UNLOCKED);
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
		fio_sem_remove(flow_lock);
	if (flow_list)
		sfree(flow_list);
}
