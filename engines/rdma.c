/*
 * RDMA I/O engine
 *
 * RDMA I/O engine based on the IB verbs and RDMA/CM user space libraries.
 * Supports both RDMA memory semantics and channel semantics
 *   for the InfiniBand, RoCE and iWARP protocols.
 *
 * You will need the Linux RDMA software installed, either
 * from your Linux distributor or directly from openfabrics.org:
 *
 * http://www.openfabrics.org/downloads/OFED/
 *
 * Exchanging steps of RDMA ioengine control messages:
 *	1. client side sends test mode (RDMA_WRITE/RDMA_READ/SEND)
 *	   to server side.
 *	2. server side parses test mode, and sends back confirmation
 *	   to client side. In RDMA WRITE/READ test, this confirmation
 *	   includes memory information, such as rkey, address.
 *	3. client side initiates test loop.
 *	4. In RDMA WRITE/READ test, client side sends a completion
 *	   notification to server side. Server side updates its
 *	   td->done as true.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <pthread.h>
#include <inttypes.h>

#include "../fio.h"
#include "../hash.h"
#include "../optgroup.h"

#include <rdma/rdma_cma.h>
#include <infiniband/arch.h>

#define FIO_RDMA_MAX_IO_DEPTH    512

enum rdma_io_mode {
	FIO_RDMA_UNKNOWN = 0,
	FIO_RDMA_MEM_WRITE,
	FIO_RDMA_MEM_READ,
	FIO_RDMA_CHA_SEND,
	FIO_RDMA_CHA_RECV
};

struct rdmaio_options {
	struct thread_data *td;
	unsigned int port;
	enum rdma_io_mode verb;
};

static int str_hostname_cb(void *data, const char *input)
{
	struct rdmaio_options *o = data;

	if (o->td->o.filename)
		free(o->td->o.filename);
	o->td->o.filename = strdup(input);
	return 0;
}

static struct fio_option options[] = {
	{
		.name	= "hostname",
		.lname	= "rdma engine hostname",
		.type	= FIO_OPT_STR_STORE,
		.cb	= str_hostname_cb,
		.help	= "Hostname for RDMA IO engine",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_RDMA,
	},
	{
		.name	= "port",
		.lname	= "rdma engine port",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct rdmaio_options, port),
		.minval	= 1,
		.maxval	= 65535,
		.help	= "Port to use for RDMA connections",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_RDMA,
	},
	{
		.name	= "verb",
		.lname	= "RDMA engine verb",
		.alias	= "proto",
		.type	= FIO_OPT_STR,
		.off1	= offsetof(struct rdmaio_options, verb),
		.help	= "RDMA engine verb",
		.def	= "write",
		.posval = {
			  { .ival = "write",
			    .oval = FIO_RDMA_MEM_WRITE,
			    .help = "Memory Write",
			  },
			  { .ival = "read",
			    .oval = FIO_RDMA_MEM_READ,
			    .help = "Memory Read",
			  },
			  { .ival = "send",
			    .oval = FIO_RDMA_CHA_SEND,
			    .help = "Posted Send",
			  },
			  { .ival = "recv",
			    .oval = FIO_RDMA_CHA_RECV,
			    .help = "Posted Receive",
			  },
		},
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_RDMA,
	},
	{
		.name	= NULL,
	},
};

struct remote_u {
	uint64_t buf;
	uint32_t rkey;
	uint32_t size;
};

struct rdma_info_blk {
	uint32_t mode;		/* channel semantic or memory semantic */
	uint32_t nr;		/* client: io depth
				   server: number of records for memory semantic
				 */
	uint32_t max_bs;        /* maximum block size */
	struct remote_u rmt_us[FIO_RDMA_MAX_IO_DEPTH];
};

struct rdma_io_u_data {
	uint64_t wr_id;
	struct ibv_send_wr sq_wr;
	struct ibv_recv_wr rq_wr;
	struct ibv_sge rdma_sgl;
};

struct rdmaio_data {
	int is_client;
	enum rdma_io_mode rdma_protocol;
	char host[64];
	struct sockaddr_in addr;

	struct ibv_recv_wr rq_wr;
	struct ibv_sge recv_sgl;
	struct rdma_info_blk recv_buf;
	struct ibv_mr *recv_mr;

	struct ibv_send_wr sq_wr;
	struct ibv_sge send_sgl;
	struct rdma_info_blk send_buf;
	struct ibv_mr *send_mr;

	struct ibv_comp_channel *channel;
	struct ibv_cq *cq;
	struct ibv_pd *pd;
	struct ibv_qp *qp;

	pthread_t cmthread;
	struct rdma_event_channel *cm_channel;
	struct rdma_cm_id *cm_id;
	struct rdma_cm_id *child_cm_id;

	int cq_event_num;

	struct remote_u *rmt_us;
	int rmt_nr;
	struct io_u **io_us_queued;
	int io_u_queued_nr;
	struct io_u **io_us_flight;
	int io_u_flight_nr;
	struct io_u **io_us_completed;
	int io_u_completed_nr;

	struct frand_state rand_state;
};

static int client_recv(struct thread_data *td, struct ibv_wc *wc)
{
	struct rdmaio_data *rd = td->io_ops_data;
	unsigned int max_bs;

	if (wc->byte_len != sizeof(rd->recv_buf)) {
		log_err("Received bogus data, size %d\n", wc->byte_len);
		return 1;
	}

	max_bs = max(td->o.max_bs[DDIR_READ], td->o.max_bs[DDIR_WRITE]);
	if (max_bs > ntohl(rd->recv_buf.max_bs)) {
		log_err("fio: Server's block size (%d) must be greater than or "
			"equal to the client's block size (%d)!\n",
			ntohl(rd->recv_buf.max_bs), max_bs);
		return 1;
	}

	/* store mr info for MEMORY semantic */
	if ((rd->rdma_protocol == FIO_RDMA_MEM_WRITE) ||
	    (rd->rdma_protocol == FIO_RDMA_MEM_READ)) {
		/* struct flist_head *entry; */
		int i = 0;

		rd->rmt_nr = ntohl(rd->recv_buf.nr);

		for (i = 0; i < rd->rmt_nr; i++) {
			rd->rmt_us[i].buf = ntohll(rd->recv_buf.rmt_us[i].buf);
			rd->rmt_us[i].rkey = ntohl(rd->recv_buf.rmt_us[i].rkey);
			rd->rmt_us[i].size = ntohl(rd->recv_buf.rmt_us[i].size);

			dprint(FD_IO,
			       "fio: Received rkey %x addr %" PRIx64
			       " len %d from peer\n", rd->rmt_us[i].rkey,
			       rd->rmt_us[i].buf, rd->rmt_us[i].size);
		}
	}

	return 0;
}

static int server_recv(struct thread_data *td, struct ibv_wc *wc)
{
	struct rdmaio_data *rd = td->io_ops_data;
	unsigned int max_bs;

	if (wc->wr_id == FIO_RDMA_MAX_IO_DEPTH) {
		rd->rdma_protocol = ntohl(rd->recv_buf.mode);

		/* CHANNEL semantic, do nothing */
		if (rd->rdma_protocol == FIO_RDMA_CHA_SEND)
			rd->rdma_protocol = FIO_RDMA_CHA_RECV;

		max_bs = max(td->o.max_bs[DDIR_READ], td->o.max_bs[DDIR_WRITE]);
		if (max_bs < ntohl(rd->recv_buf.max_bs)) {
			log_err("fio: Server's block size (%d) must be greater than or "
				"equal to the client's block size (%d)!\n",
				ntohl(rd->recv_buf.max_bs), max_bs);
			return 1;
		}

	}

	return 0;
}

static int cq_event_handler(struct thread_data *td, enum ibv_wc_opcode opcode)
{
	struct rdmaio_data *rd = td->io_ops_data;
	struct ibv_wc wc;
	struct rdma_io_u_data *r_io_u_d;
	int ret;
	int compevnum = 0;
	int i;

	while ((ret = ibv_poll_cq(rd->cq, 1, &wc)) == 1) {
		ret = 0;
		compevnum++;

		if (wc.status) {
			log_err("fio: cq completion status %d(%s)\n",
				wc.status, ibv_wc_status_str(wc.status));
			return -1;
		}

		switch (wc.opcode) {

		case IBV_WC_RECV:
			if (rd->is_client == 1)
				ret = client_recv(td, &wc);
			else
				ret = server_recv(td, &wc);

			if (ret)
				return -1;

			if (wc.wr_id == FIO_RDMA_MAX_IO_DEPTH)
				break;

			for (i = 0; i < rd->io_u_flight_nr; i++) {
				r_io_u_d = rd->io_us_flight[i]->engine_data;

				if (wc.wr_id == r_io_u_d->rq_wr.wr_id) {
					rd->io_us_flight[i]->resid =
					    rd->io_us_flight[i]->buflen
					    - wc.byte_len;

					rd->io_us_flight[i]->error = 0;

					rd->io_us_completed[rd->
							    io_u_completed_nr]
					    = rd->io_us_flight[i];
					rd->io_u_completed_nr++;
					break;
				}
			}
			if (i == rd->io_u_flight_nr)
				log_err("fio: recv wr %" PRId64 " not found\n",
					wc.wr_id);
			else {
				/* put the last one into middle of the list */
				rd->io_us_flight[i] =
				    rd->io_us_flight[rd->io_u_flight_nr - 1];
				rd->io_u_flight_nr--;
			}

			break;

		case IBV_WC_SEND:
		case IBV_WC_RDMA_WRITE:
		case IBV_WC_RDMA_READ:
			if (wc.wr_id == FIO_RDMA_MAX_IO_DEPTH)
				break;

			for (i = 0; i < rd->io_u_flight_nr; i++) {
				r_io_u_d = rd->io_us_flight[i]->engine_data;

				if (wc.wr_id == r_io_u_d->sq_wr.wr_id) {
					rd->io_us_completed[rd->
							    io_u_completed_nr]
					    = rd->io_us_flight[i];
					rd->io_u_completed_nr++;
					break;
				}
			}
			if (i == rd->io_u_flight_nr)
				log_err("fio: send wr %" PRId64 " not found\n",
					wc.wr_id);
			else {
				/* put the last one into middle of the list */
				rd->io_us_flight[i] =
				    rd->io_us_flight[rd->io_u_flight_nr - 1];
				rd->io_u_flight_nr--;
			}

			break;

		default:
			log_info("fio: unknown completion event %d\n",
				 wc.opcode);
			return -1;
		}
		rd->cq_event_num++;
	}

	if (ret) {
		log_err("fio: poll error %d\n", ret);
		return 1;
	}

	return compevnum;
}

/*
 * Return -1 for error and 'nr events' for a positive number
 * of events
 */
static int rdma_poll_wait(struct thread_data *td, enum ibv_wc_opcode opcode)
{
	struct rdmaio_data *rd = td->io_ops_data;
	struct ibv_cq *ev_cq;
	void *ev_ctx;
	int ret;

	if (rd->cq_event_num > 0) {	/* previous left */
		rd->cq_event_num--;
		return 0;
	}

again:
	if (ibv_get_cq_event(rd->channel, &ev_cq, &ev_ctx) != 0) {
		log_err("fio: Failed to get cq event!\n");
		return -1;
	}
	if (ev_cq != rd->cq) {
		log_err("fio: Unknown CQ!\n");
		return -1;
	}
	if (ibv_req_notify_cq(rd->cq, 0) != 0) {
		log_err("fio: Failed to set notify!\n");
		return -1;
	}

	ret = cq_event_handler(td, opcode);
	if (ret == 0)
		goto again;

	ibv_ack_cq_events(rd->cq, ret);

	rd->cq_event_num--;

	return ret;
}

static int fio_rdmaio_setup_qp(struct thread_data *td)
{
	struct rdmaio_data *rd = td->io_ops_data;
	struct ibv_qp_init_attr init_attr;
	int qp_depth = td->o.iodepth * 2;	/* 2 times of io depth */

	if (rd->is_client == 0)
		rd->pd = ibv_alloc_pd(rd->child_cm_id->verbs);
	else
		rd->pd = ibv_alloc_pd(rd->cm_id->verbs);

	if (rd->pd == NULL) {
		log_err("fio: ibv_alloc_pd fail: %m\n");
		return 1;
	}

	if (rd->is_client == 0)
		rd->channel = ibv_create_comp_channel(rd->child_cm_id->verbs);
	else
		rd->channel = ibv_create_comp_channel(rd->cm_id->verbs);
	if (rd->channel == NULL) {
		log_err("fio: ibv_create_comp_channel fail: %m\n");
		goto err1;
	}

	if (qp_depth < 16)
		qp_depth = 16;

	if (rd->is_client == 0)
		rd->cq = ibv_create_cq(rd->child_cm_id->verbs,
				       qp_depth, rd, rd->channel, 0);
	else
		rd->cq = ibv_create_cq(rd->cm_id->verbs,
				       qp_depth, rd, rd->channel, 0);
	if (rd->cq == NULL) {
		log_err("fio: ibv_create_cq failed: %m\n");
		goto err2;
	}

	if (ibv_req_notify_cq(rd->cq, 0) != 0) {
		log_err("fio: ibv_req_notify_cq failed: %m\n");
		goto err3;
	}

	/* create queue pair */
	memset(&init_attr, 0, sizeof(init_attr));
	init_attr.cap.max_send_wr = qp_depth;
	init_attr.cap.max_recv_wr = qp_depth;
	init_attr.cap.max_recv_sge = 1;
	init_attr.cap.max_send_sge = 1;
	init_attr.qp_type = IBV_QPT_RC;
	init_attr.send_cq = rd->cq;
	init_attr.recv_cq = rd->cq;

	if (rd->is_client == 0) {
		if (rdma_create_qp(rd->child_cm_id, rd->pd, &init_attr) != 0) {
			log_err("fio: rdma_create_qp failed: %m\n");
			goto err3;
		}
		rd->qp = rd->child_cm_id->qp;
	} else {
		if (rdma_create_qp(rd->cm_id, rd->pd, &init_attr) != 0) {
			log_err("fio: rdma_create_qp failed: %m\n");
			goto err3;
		}
		rd->qp = rd->cm_id->qp;
	}

	return 0;

err3:
	ibv_destroy_cq(rd->cq);
err2:
	ibv_destroy_comp_channel(rd->channel);
err1:
	ibv_dealloc_pd(rd->pd);

	return 1;
}

static int fio_rdmaio_setup_control_msg_buffers(struct thread_data *td)
{
	struct rdmaio_data *rd = td->io_ops_data;

	rd->recv_mr = ibv_reg_mr(rd->pd, &rd->recv_buf, sizeof(rd->recv_buf),
				 IBV_ACCESS_LOCAL_WRITE);
	if (rd->recv_mr == NULL) {
		log_err("fio: recv_buf reg_mr failed: %m\n");
		return 1;
	}

	rd->send_mr = ibv_reg_mr(rd->pd, &rd->send_buf, sizeof(rd->send_buf),
				 0);
	if (rd->send_mr == NULL) {
		log_err("fio: send_buf reg_mr failed: %m\n");
		ibv_dereg_mr(rd->recv_mr);
		return 1;
	}

	/* setup work request */
	/* recv wq */
	rd->recv_sgl.addr = (uint64_t) (unsigned long)&rd->recv_buf;
	rd->recv_sgl.length = sizeof(rd->recv_buf);
	rd->recv_sgl.lkey = rd->recv_mr->lkey;
	rd->rq_wr.sg_list = &rd->recv_sgl;
	rd->rq_wr.num_sge = 1;
	rd->rq_wr.wr_id = FIO_RDMA_MAX_IO_DEPTH;

	/* send wq */
	rd->send_sgl.addr = (uint64_t) (unsigned long)&rd->send_buf;
	rd->send_sgl.length = sizeof(rd->send_buf);
	rd->send_sgl.lkey = rd->send_mr->lkey;

	rd->sq_wr.opcode = IBV_WR_SEND;
	rd->sq_wr.send_flags = IBV_SEND_SIGNALED;
	rd->sq_wr.sg_list = &rd->send_sgl;
	rd->sq_wr.num_sge = 1;
	rd->sq_wr.wr_id = FIO_RDMA_MAX_IO_DEPTH;

	return 0;
}

static int get_next_channel_event(struct thread_data *td,
				  struct rdma_event_channel *channel,
				  enum rdma_cm_event_type wait_event)
{
	struct rdmaio_data *rd = td->io_ops_data;
	struct rdma_cm_event *event;
	int ret;

	ret = rdma_get_cm_event(channel, &event);
	if (ret) {
		log_err("fio: rdma_get_cm_event: %d\n", ret);
		return 1;
	}

	if (event->event != wait_event) {
		log_err("fio: event is %s instead of %s\n",
			rdma_event_str(event->event),
			rdma_event_str(wait_event));
		return 1;
	}

	switch (event->event) {
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		rd->child_cm_id = event->id;
		break;
	default:
		break;
	}

	rdma_ack_cm_event(event);

	return 0;
}

static int fio_rdmaio_prep(struct thread_data *td, struct io_u *io_u)
{
	struct rdmaio_data *rd = td->io_ops_data;
	struct rdma_io_u_data *r_io_u_d;

	r_io_u_d = io_u->engine_data;

	switch (rd->rdma_protocol) {
	case FIO_RDMA_MEM_WRITE:
	case FIO_RDMA_MEM_READ:
		r_io_u_d->rdma_sgl.addr = (uint64_t) (unsigned long)io_u->buf;
		r_io_u_d->rdma_sgl.lkey = io_u->mr->lkey;
		r_io_u_d->sq_wr.wr_id = r_io_u_d->wr_id;
		r_io_u_d->sq_wr.send_flags = IBV_SEND_SIGNALED;
		r_io_u_d->sq_wr.sg_list = &r_io_u_d->rdma_sgl;
		r_io_u_d->sq_wr.num_sge = 1;
		break;
	case FIO_RDMA_CHA_SEND:
		r_io_u_d->rdma_sgl.addr = (uint64_t) (unsigned long)io_u->buf;
		r_io_u_d->rdma_sgl.lkey = io_u->mr->lkey;
		r_io_u_d->rdma_sgl.length = io_u->buflen;
		r_io_u_d->sq_wr.wr_id = r_io_u_d->wr_id;
		r_io_u_d->sq_wr.opcode = IBV_WR_SEND;
		r_io_u_d->sq_wr.send_flags = IBV_SEND_SIGNALED;
		r_io_u_d->sq_wr.sg_list = &r_io_u_d->rdma_sgl;
		r_io_u_d->sq_wr.num_sge = 1;
		break;
	case FIO_RDMA_CHA_RECV:
		r_io_u_d->rdma_sgl.addr = (uint64_t) (unsigned long)io_u->buf;
		r_io_u_d->rdma_sgl.lkey = io_u->mr->lkey;
		r_io_u_d->rdma_sgl.length = io_u->buflen;
		r_io_u_d->rq_wr.wr_id = r_io_u_d->wr_id;
		r_io_u_d->rq_wr.sg_list = &r_io_u_d->rdma_sgl;
		r_io_u_d->rq_wr.num_sge = 1;
		break;
	default:
		log_err("fio: unknown rdma protocol - %d\n", rd->rdma_protocol);
		break;
	}

	return 0;
}

static struct io_u *fio_rdmaio_event(struct thread_data *td, int event)
{
	struct rdmaio_data *rd = td->io_ops_data;
	struct io_u *io_u;
	int i;

	io_u = rd->io_us_completed[0];
	for (i = 0; i < rd->io_u_completed_nr - 1; i++)
		rd->io_us_completed[i] = rd->io_us_completed[i + 1];

	rd->io_u_completed_nr--;

	dprint_io_u(io_u, "fio_rdmaio_event");

	return io_u;
}

static int fio_rdmaio_getevents(struct thread_data *td, unsigned int min,
				unsigned int max, const struct timespec *t)
{
	struct rdmaio_data *rd = td->io_ops_data;
	enum ibv_wc_opcode comp_opcode;
	struct ibv_cq *ev_cq;
	void *ev_ctx;
	int ret, r = 0;
	comp_opcode = IBV_WC_RDMA_WRITE;

	switch (rd->rdma_protocol) {
	case FIO_RDMA_MEM_WRITE:
		comp_opcode = IBV_WC_RDMA_WRITE;
		break;
	case FIO_RDMA_MEM_READ:
		comp_opcode = IBV_WC_RDMA_READ;
		break;
	case FIO_RDMA_CHA_SEND:
		comp_opcode = IBV_WC_SEND;
		break;
	case FIO_RDMA_CHA_RECV:
		comp_opcode = IBV_WC_RECV;
		break;
	default:
		log_err("fio: unknown rdma protocol - %d\n", rd->rdma_protocol);
		break;
	}

	if (rd->cq_event_num > 0) {	/* previous left */
		rd->cq_event_num--;
		return 0;
	}

again:
	if (ibv_get_cq_event(rd->channel, &ev_cq, &ev_ctx) != 0) {
		log_err("fio: Failed to get cq event!\n");
		return -1;
	}
	if (ev_cq != rd->cq) {
		log_err("fio: Unknown CQ!\n");
		return -1;
	}
	if (ibv_req_notify_cq(rd->cq, 0) != 0) {
		log_err("fio: Failed to set notify!\n");
		return -1;
	}

	ret = cq_event_handler(td, comp_opcode);
	if (ret < 1)
		goto again;

	ibv_ack_cq_events(rd->cq, ret);

	r += ret;
	if (r < min)
		goto again;

	rd->cq_event_num -= r;

	return r;
}

static int fio_rdmaio_send(struct thread_data *td, struct io_u **io_us,
			   unsigned int nr)
{
	struct rdmaio_data *rd = td->io_ops_data;
	struct ibv_send_wr *bad_wr;
#if 0
	enum ibv_wc_opcode comp_opcode;
	comp_opcode = IBV_WC_RDMA_WRITE;
#endif
	int i;
	long index;
	struct rdma_io_u_data *r_io_u_d;

	r_io_u_d = NULL;

	for (i = 0; i < nr; i++) {
		/* RDMA_WRITE or RDMA_READ */
		switch (rd->rdma_protocol) {
		case FIO_RDMA_MEM_WRITE:
			/* compose work request */
			r_io_u_d = io_us[i]->engine_data;
			index = __rand(&rd->rand_state) % rd->rmt_nr;
			r_io_u_d->sq_wr.opcode = IBV_WR_RDMA_WRITE;
			r_io_u_d->sq_wr.wr.rdma.rkey = rd->rmt_us[index].rkey;
			r_io_u_d->sq_wr.wr.rdma.remote_addr = \
				rd->rmt_us[index].buf;
			r_io_u_d->sq_wr.sg_list->length = io_us[i]->buflen;
			break;
		case FIO_RDMA_MEM_READ:
			/* compose work request */
			r_io_u_d = io_us[i]->engine_data;
			index = __rand(&rd->rand_state) % rd->rmt_nr;
			r_io_u_d->sq_wr.opcode = IBV_WR_RDMA_READ;
			r_io_u_d->sq_wr.wr.rdma.rkey = rd->rmt_us[index].rkey;
			r_io_u_d->sq_wr.wr.rdma.remote_addr = \
				rd->rmt_us[index].buf;
			r_io_u_d->sq_wr.sg_list->length = io_us[i]->buflen;
			break;
		case FIO_RDMA_CHA_SEND:
			r_io_u_d = io_us[i]->engine_data;
			r_io_u_d->sq_wr.opcode = IBV_WR_SEND;
			r_io_u_d->sq_wr.send_flags = IBV_SEND_SIGNALED;
			break;
		default:
			log_err("fio: unknown rdma protocol - %d\n",
				rd->rdma_protocol);
			break;
		}

		if (ibv_post_send(rd->qp, &r_io_u_d->sq_wr, &bad_wr) != 0) {
			log_err("fio: ibv_post_send fail: %m\n");
			return -1;
		}

		dprint_io_u(io_us[i], "fio_rdmaio_send");
	}

	/* wait for completion
	   rdma_poll_wait(td, comp_opcode); */

	return i;
}

static int fio_rdmaio_recv(struct thread_data *td, struct io_u **io_us,
			   unsigned int nr)
{
	struct rdmaio_data *rd = td->io_ops_data;
	struct ibv_recv_wr *bad_wr;
	struct rdma_io_u_data *r_io_u_d;
	int i;

	i = 0;
	if (rd->rdma_protocol == FIO_RDMA_CHA_RECV) {
		/* post io_u into recv queue */
		for (i = 0; i < nr; i++) {
			r_io_u_d = io_us[i]->engine_data;
			if (ibv_post_recv(rd->qp, &r_io_u_d->rq_wr, &bad_wr) !=
			    0) {
				log_err("fio: ibv_post_recv fail: %m\n");
				return 1;
			}
		}
	} else if ((rd->rdma_protocol == FIO_RDMA_MEM_READ)
		   || (rd->rdma_protocol == FIO_RDMA_MEM_WRITE)) {
		/* re-post the rq_wr */
		if (ibv_post_recv(rd->qp, &rd->rq_wr, &bad_wr) != 0) {
			log_err("fio: ibv_post_recv fail: %m\n");
			return 1;
		}

		rdma_poll_wait(td, IBV_WC_RECV);

		dprint(FD_IO, "fio: recv FINISH message\n");
		td->done = 1;
		return 0;
	}

	return i;
}

static int fio_rdmaio_queue(struct thread_data *td, struct io_u *io_u)
{
	struct rdmaio_data *rd = td->io_ops_data;

	fio_ro_check(td, io_u);

	if (rd->io_u_queued_nr == (int)td->o.iodepth)
		return FIO_Q_BUSY;

	rd->io_us_queued[rd->io_u_queued_nr] = io_u;
	rd->io_u_queued_nr++;

	dprint_io_u(io_u, "fio_rdmaio_queue");

	return FIO_Q_QUEUED;
}

static void fio_rdmaio_queued(struct thread_data *td, struct io_u **io_us,
			      unsigned int nr)
{
	struct rdmaio_data *rd = td->io_ops_data;
	struct timeval now;
	unsigned int i;

	if (!fio_fill_issue_time(td))
		return;

	fio_gettime(&now, NULL);

	for (i = 0; i < nr; i++) {
		struct io_u *io_u = io_us[i];

		/* queued -> flight */
		rd->io_us_flight[rd->io_u_flight_nr] = io_u;
		rd->io_u_flight_nr++;

		memcpy(&io_u->issue_time, &now, sizeof(now));
		io_u_queued(td, io_u);
	}
}

static int fio_rdmaio_commit(struct thread_data *td)
{
	struct rdmaio_data *rd = td->io_ops_data;
	struct io_u **io_us;
	int ret;

	if (!rd->io_us_queued)
		return 0;

	io_us = rd->io_us_queued;
	do {
		/* RDMA_WRITE or RDMA_READ */
		if (rd->is_client)
			ret = fio_rdmaio_send(td, io_us, rd->io_u_queued_nr);
		else if (!rd->is_client)
			ret = fio_rdmaio_recv(td, io_us, rd->io_u_queued_nr);
		else
			ret = 0;	/* must be a SYNC */

		if (ret > 0) {
			fio_rdmaio_queued(td, io_us, ret);
			io_u_mark_submit(td, ret);
			rd->io_u_queued_nr -= ret;
			io_us += ret;
			ret = 0;
		} else
			break;
	} while (rd->io_u_queued_nr);

	return ret;
}

static int fio_rdmaio_connect(struct thread_data *td, struct fio_file *f)
{
	struct rdmaio_data *rd = td->io_ops_data;
	struct rdma_conn_param conn_param;
	struct ibv_send_wr *bad_wr;

	memset(&conn_param, 0, sizeof(conn_param));
	conn_param.responder_resources = 1;
	conn_param.initiator_depth = 1;
	conn_param.retry_count = 10;

	if (rdma_connect(rd->cm_id, &conn_param) != 0) {
		log_err("fio: rdma_connect fail: %m\n");
		return 1;
	}

	if (get_next_channel_event
	    (td, rd->cm_channel, RDMA_CM_EVENT_ESTABLISHED) != 0) {
		log_err("fio: wait for RDMA_CM_EVENT_ESTABLISHED\n");
		return 1;
	}

	/* send task request */
	rd->send_buf.mode = htonl(rd->rdma_protocol);
	rd->send_buf.nr = htonl(td->o.iodepth);

	if (ibv_post_send(rd->qp, &rd->sq_wr, &bad_wr) != 0) {
		log_err("fio: ibv_post_send fail: %m\n");
		return 1;
	}

	if (rdma_poll_wait(td, IBV_WC_SEND) < 0)
		return 1;

	/* wait for remote MR info from server side */
	if (rdma_poll_wait(td, IBV_WC_RECV) < 0)
		return 1;

	/* In SEND/RECV test, it's a good practice to setup the iodepth of
	 * of the RECV side deeper than that of the SEND side to
	 * avoid RNR (receiver not ready) error. The
	 * SEND side may send so many unsolicited message before
	 * RECV side commits sufficient recv buffers into recv queue.
	 * This may lead to RNR error. Here, SEND side pauses for a while
	 * during which RECV side commits sufficient recv buffers.
	 */
	usleep(500000);

	return 0;
}

static int fio_rdmaio_accept(struct thread_data *td, struct fio_file *f)
{
	struct rdmaio_data *rd = td->io_ops_data;
	struct rdma_conn_param conn_param;
	struct ibv_send_wr *bad_wr;
	int ret = 0;

	/* rdma_accept() - then wait for accept success */
	memset(&conn_param, 0, sizeof(conn_param));
	conn_param.responder_resources = 1;
	conn_param.initiator_depth = 1;

	if (rdma_accept(rd->child_cm_id, &conn_param) != 0) {
		log_err("fio: rdma_accept: %m\n");
		return 1;
	}

	if (get_next_channel_event
	    (td, rd->cm_channel, RDMA_CM_EVENT_ESTABLISHED) != 0) {
		log_err("fio: wait for RDMA_CM_EVENT_ESTABLISHED\n");
		return 1;
	}

	/* wait for request */
	ret = rdma_poll_wait(td, IBV_WC_RECV) < 0;

	if (ibv_post_send(rd->qp, &rd->sq_wr, &bad_wr) != 0) {
		log_err("fio: ibv_post_send fail: %m\n");
		return 1;
	}

	if (rdma_poll_wait(td, IBV_WC_SEND) < 0)
		return 1;

	return ret;
}

static int fio_rdmaio_open_file(struct thread_data *td, struct fio_file *f)
{
	if (td_read(td))
		return fio_rdmaio_accept(td, f);
	else
		return fio_rdmaio_connect(td, f);
}

static int fio_rdmaio_close_file(struct thread_data *td, struct fio_file *f)
{
	struct rdmaio_data *rd = td->io_ops_data;
	struct ibv_send_wr *bad_wr;

	/* unregister rdma buffer */

	/*
	 * Client sends notification to the server side
	 */
	/* refer to: http://linux.die.net/man/7/rdma_cm */
	if ((rd->is_client == 1) && ((rd->rdma_protocol == FIO_RDMA_MEM_WRITE)
				     || (rd->rdma_protocol ==
					 FIO_RDMA_MEM_READ))) {
		if (ibv_post_send(rd->qp, &rd->sq_wr, &bad_wr) != 0) {
			log_err("fio: ibv_post_send fail: %m\n");
			return 1;
		}

		dprint(FD_IO, "fio: close information sent success\n");
		rdma_poll_wait(td, IBV_WC_SEND);
	}

	if (rd->is_client == 1)
		rdma_disconnect(rd->cm_id);
	else {
		rdma_disconnect(rd->child_cm_id);
#if 0
		rdma_disconnect(rd->cm_id);
#endif
	}

#if 0
	if (get_next_channel_event(td, rd->cm_channel, RDMA_CM_EVENT_DISCONNECTED) != 0) {
		log_err("fio: wait for RDMA_CM_EVENT_DISCONNECTED\n");
		return 1;
	}
#endif

	ibv_destroy_cq(rd->cq);
	ibv_destroy_qp(rd->qp);

	if (rd->is_client == 1)
		rdma_destroy_id(rd->cm_id);
	else {
		rdma_destroy_id(rd->child_cm_id);
		rdma_destroy_id(rd->cm_id);
	}

	ibv_destroy_comp_channel(rd->channel);
	ibv_dealloc_pd(rd->pd);

	return 0;
}

static int fio_rdmaio_setup_connect(struct thread_data *td, const char *host,
				    unsigned short port)
{
	struct rdmaio_data *rd = td->io_ops_data;
	struct ibv_recv_wr *bad_wr;
	int err;

	rd->addr.sin_family = AF_INET;
	rd->addr.sin_port = htons(port);

	if (inet_aton(host, &rd->addr.sin_addr) != 1) {
		struct hostent *hent;

		hent = gethostbyname(host);
		if (!hent) {
			td_verror(td, errno, "gethostbyname");
			return 1;
		}

		memcpy(&rd->addr.sin_addr, hent->h_addr, 4);
	}

	/* resolve route */
	err = rdma_resolve_addr(rd->cm_id, NULL, (struct sockaddr *)&rd->addr, 2000);
	if (err != 0) {
		log_err("fio: rdma_resolve_addr: %d\n", err);
		return 1;
	}

	err = get_next_channel_event(td, rd->cm_channel, RDMA_CM_EVENT_ADDR_RESOLVED);
	if (err != 0) {
		log_err("fio: get_next_channel_event: %d\n", err);
		return 1;
	}

	/* resolve route */
	err = rdma_resolve_route(rd->cm_id, 2000);
	if (err != 0) {
		log_err("fio: rdma_resolve_route: %d\n", err);
		return 1;
	}

	err = get_next_channel_event(td, rd->cm_channel, RDMA_CM_EVENT_ROUTE_RESOLVED);
	if (err != 0) {
		log_err("fio: get_next_channel_event: %d\n", err);
		return 1;
	}

	/* create qp and buffer */
	if (fio_rdmaio_setup_qp(td) != 0)
		return 1;

	if (fio_rdmaio_setup_control_msg_buffers(td) != 0)
		return 1;

	/* post recv buf */
	err = ibv_post_recv(rd->qp, &rd->rq_wr, &bad_wr);
	if (err != 0) {
		log_err("fio: ibv_post_recv fail: %d\n", err);
		return 1;
	}

	return 0;
}

static int fio_rdmaio_setup_listen(struct thread_data *td, short port)
{
	struct rdmaio_data *rd = td->io_ops_data;
	struct ibv_recv_wr *bad_wr;
	int state = td->runstate;

	td_set_runstate(td, TD_SETTING_UP);

	rd->addr.sin_family = AF_INET;
	rd->addr.sin_addr.s_addr = htonl(INADDR_ANY);
	rd->addr.sin_port = htons(port);

	/* rdma_listen */
	if (rdma_bind_addr(rd->cm_id, (struct sockaddr *)&rd->addr) != 0) {
		log_err("fio: rdma_bind_addr fail: %m\n");
		return 1;
	}

	if (rdma_listen(rd->cm_id, 3) != 0) {
		log_err("fio: rdma_listen fail: %m\n");
		return 1;
	}

	log_info("fio: waiting for connection\n");

	/* wait for CONNECT_REQUEST */
	if (get_next_channel_event
	    (td, rd->cm_channel, RDMA_CM_EVENT_CONNECT_REQUEST) != 0) {
		log_err("fio: wait for RDMA_CM_EVENT_CONNECT_REQUEST\n");
		return 1;
	}

	if (fio_rdmaio_setup_qp(td) != 0)
		return 1;

	if (fio_rdmaio_setup_control_msg_buffers(td) != 0)
		return 1;

	/* post recv buf */
	if (ibv_post_recv(rd->qp, &rd->rq_wr, &bad_wr) != 0) {
		log_err("fio: ibv_post_recv fail: %m\n");
		return 1;
	}

	td_set_runstate(td, state);
	return 0;
}

static int check_set_rlimits(struct thread_data *td)
{
#ifdef CONFIG_RLIMIT_MEMLOCK
	struct rlimit rl;

	/* check RLIMIT_MEMLOCK */
	if (getrlimit(RLIMIT_MEMLOCK, &rl) != 0) {
		log_err("fio: getrlimit fail: %d(%s)\n",
			errno, strerror(errno));
		return 1;
	}

	/* soft limit */
	if ((rl.rlim_cur != RLIM_INFINITY)
	    && (rl.rlim_cur < td->orig_buffer_size)) {
		log_err("fio: soft RLIMIT_MEMLOCK is: %" PRId64 "\n",
			rl.rlim_cur);
		log_err("fio: total block size is:    %zd\n",
			td->orig_buffer_size);
		/* try to set larger RLIMIT_MEMLOCK */
		rl.rlim_cur = rl.rlim_max;
		if (setrlimit(RLIMIT_MEMLOCK, &rl) != 0) {
			log_err("fio: setrlimit fail: %d(%s)\n",
				errno, strerror(errno));
			log_err("fio: you may try enlarge MEMLOCK by root\n");
			log_err("# ulimit -l unlimited\n");
			return 1;
		}
	}
#endif

	return 0;
}

static int compat_options(struct thread_data *td)
{
	// The original RDMA engine had an ugly / seperator
	// on the filename for it's options. This function
	// retains backwards compatibility with it.100

	struct rdmaio_options *o = td->eo;
	char *modep, *portp;
	char *filename = td->o.filename;

	if (!filename)
		return 0;

	portp = strchr(filename, '/');
	if (portp == NULL)
		return 0;

	*portp = '\0';
	portp++;

	o->port = strtol(portp, NULL, 10);
	if (!o->port || o->port > 65535)
		goto bad_host;

	modep = strchr(portp, '/');
	if (modep != NULL) {
		*modep = '\0';
		modep++;
	}

	if (modep) {
		if (!strncmp("rdma_write", modep, strlen(modep)) ||
		    !strncmp("RDMA_WRITE", modep, strlen(modep)))
			o->verb = FIO_RDMA_MEM_WRITE;
		else if (!strncmp("rdma_read", modep, strlen(modep)) ||
			 !strncmp("RDMA_READ", modep, strlen(modep)))
			o->verb = FIO_RDMA_MEM_READ;
		else if (!strncmp("send", modep, strlen(modep)) ||
			 !strncmp("SEND", modep, strlen(modep)))
			o->verb = FIO_RDMA_CHA_SEND;
		else
			goto bad_host;
	} else
		o->verb = FIO_RDMA_MEM_WRITE;


	return 0;

bad_host:
	log_err("fio: bad rdma host/port/protocol: %s\n", td->o.filename);
	return 1;
}

static int fio_rdmaio_init(struct thread_data *td)
{
	struct rdmaio_data *rd = td->io_ops_data;
	struct rdmaio_options *o = td->eo;
	unsigned int max_bs;
	int ret, i;

	if (td_rw(td)) {
		log_err("fio: rdma connections must be read OR write\n");
		return 1;
	}
	if (td_random(td)) {
		log_err("fio: RDMA network IO can't be random\n");
		return 1;
	}

	if (compat_options(td))
		return 1;

	if (!o->port) {
		log_err("fio: no port has been specified which is required "
			"for the rdma engine\n");
		return 1;
	}

	if (check_set_rlimits(td))
		return 1;

	rd->rdma_protocol = o->verb;
	rd->cq_event_num = 0;

	rd->cm_channel = rdma_create_event_channel();
	if (!rd->cm_channel) {
		log_err("fio: rdma_create_event_channel fail: %m\n");
		return 1;
	}

	ret = rdma_create_id(rd->cm_channel, &rd->cm_id, rd, RDMA_PS_TCP);
	if (ret) {
		log_err("fio: rdma_create_id fail: %m\n");
		return 1;
	}

	if ((rd->rdma_protocol == FIO_RDMA_MEM_WRITE) ||
	    (rd->rdma_protocol == FIO_RDMA_MEM_READ)) {
		rd->rmt_us =
			malloc(FIO_RDMA_MAX_IO_DEPTH * sizeof(struct remote_u));
		memset(rd->rmt_us, 0,
			FIO_RDMA_MAX_IO_DEPTH * sizeof(struct remote_u));
		rd->rmt_nr = 0;
	}

	rd->io_us_queued = malloc(td->o.iodepth * sizeof(struct io_u *));
	memset(rd->io_us_queued, 0, td->o.iodepth * sizeof(struct io_u *));
	rd->io_u_queued_nr = 0;

	rd->io_us_flight = malloc(td->o.iodepth * sizeof(struct io_u *));
	memset(rd->io_us_flight, 0, td->o.iodepth * sizeof(struct io_u *));
	rd->io_u_flight_nr = 0;

	rd->io_us_completed = malloc(td->o.iodepth * sizeof(struct io_u *));
	memset(rd->io_us_completed, 0, td->o.iodepth * sizeof(struct io_u *));
	rd->io_u_completed_nr = 0;

	if (td_read(td)) {	/* READ as the server */
		rd->is_client = 0;
		td->flags |= TD_F_NO_PROGRESS;
		/* server rd->rdma_buf_len will be setup after got request */
		ret = fio_rdmaio_setup_listen(td, o->port);
	} else {		/* WRITE as the client */
		rd->is_client = 1;
		ret = fio_rdmaio_setup_connect(td, td->o.filename, o->port);
	}

	max_bs = max(td->o.max_bs[DDIR_READ], td->o.max_bs[DDIR_WRITE]);
	rd->send_buf.max_bs = htonl(max_bs);

	/* register each io_u in the free list */
	for (i = 0; i < td->io_u_freelist.nr; i++) {
		struct io_u *io_u = td->io_u_freelist.io_us[i];

		io_u->engine_data = malloc(sizeof(struct rdma_io_u_data));
		memset(io_u->engine_data, 0, sizeof(struct rdma_io_u_data));
		((struct rdma_io_u_data *)io_u->engine_data)->wr_id = i;

		io_u->mr = ibv_reg_mr(rd->pd, io_u->buf, max_bs,
				      IBV_ACCESS_LOCAL_WRITE |
				      IBV_ACCESS_REMOTE_READ |
				      IBV_ACCESS_REMOTE_WRITE);
		if (io_u->mr == NULL) {
			log_err("fio: ibv_reg_mr io_u failed: %m\n");
			return 1;
		}

		rd->send_buf.rmt_us[i].buf =
		    htonll((uint64_t) (unsigned long)io_u->buf);
		rd->send_buf.rmt_us[i].rkey = htonl(io_u->mr->rkey);
		rd->send_buf.rmt_us[i].size = htonl(max_bs);

#if 0
		log_info("fio: Send rkey %x addr %" PRIx64 " len %d to client\n", io_u->mr->rkey, io_u->buf, max_bs); */
#endif
	}

	rd->send_buf.nr = htonl(i);

	return ret;
}

static void fio_rdmaio_cleanup(struct thread_data *td)
{
	struct rdmaio_data *rd = td->io_ops_data;

	if (rd)
		free(rd);
}

static int fio_rdmaio_setup(struct thread_data *td)
{
	struct rdmaio_data *rd;

	if (!td->files_index) {
		add_file(td, td->o.filename ?: "rdma", 0, 0);
		td->o.nr_files = td->o.nr_files ?: 1;
		td->o.open_files++;
	}

	if (!td->io_ops_data) {
		rd = malloc(sizeof(*rd));

		memset(rd, 0, sizeof(*rd));
		init_rand_seed(&rd->rand_state, (unsigned int) GOLDEN_RATIO_PRIME, 0);
		td->io_ops_data = rd;
	}

	return 0;
}

static struct ioengine_ops ioengine_rw = {
	.name			= "rdma",
	.version		= FIO_IOOPS_VERSION,
	.setup			= fio_rdmaio_setup,
	.init			= fio_rdmaio_init,
	.prep			= fio_rdmaio_prep,
	.queue			= fio_rdmaio_queue,
	.commit			= fio_rdmaio_commit,
	.getevents		= fio_rdmaio_getevents,
	.event			= fio_rdmaio_event,
	.cleanup		= fio_rdmaio_cleanup,
	.open_file		= fio_rdmaio_open_file,
	.close_file		= fio_rdmaio_close_file,
	.flags			= FIO_DISKLESSIO | FIO_UNIDIR | FIO_PIPEIO,
	.options		= options,
	.option_struct_size	= sizeof(struct rdmaio_options),
};

static void fio_init fio_rdmaio_register(void)
{
	register_ioengine(&ioengine_rw);
}

static void fio_exit fio_rdmaio_unregister(void)
{
	unregister_ioengine(&ioengine_rw);
}
