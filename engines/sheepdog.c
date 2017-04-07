/*
 * sheepdog engine
 *
 * Sync-IO engine using a distributed object storage "Sheepdog".
 *
 * https://github.com/sheepdog/sheepdog
 */
#include <netdb.h>
#include <ctype.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/un.h>

#include "../fio.h"
#include "../optgroup.h"
#include "../flist.h"

#define READFILE_BLOCK_SIZE 4194304

/******************************************************************************
	sheepdog client's libraries
	taken from a part of fujita/tgt/usr/bs_sheepdog.c (partialy modified)
	https://github.com/fujita/tgt
 *******************************************************************************/
#define min_t(type,x,y) \
        ({ type __x = (x); type __y = (y); __x < __y ? __x: __y; })
#define max_t(type,x,y) \
        ({ type __x = (x); type __y = (y); __x > __y ? __x: __y; })

#define zalloc(size)                    \
        ({                              \
         void *ptr = malloc(size);      \
         if (ptr)                       \
         memset(ptr, 0, size);          \
         else                           \
         log_err("%m\n");               \
         ptr;                           \
         })

#define SD_PROTO_VER 0x01

#define SD_DEFAULT_ADDR "localhost"
#define SD_DEFAULT_PORT 7000

#define SD_OP_CREATE_AND_WRITE_OBJ  0x01
#define SD_OP_READ_OBJ       0x02
#define SD_OP_WRITE_OBJ      0x03
/* 0x04 is used internally by Sheepdog */
#define SD_OP_DISCARD_OBJ    0x05

#define SD_OP_NEW_VDI        0x11
#define SD_OP_LOCK_VDI       0x12
#define SD_OP_RELEASE_VDI    0x13
#define SD_OP_GET_VDI_INFO   0x14
#define SD_OP_READ_VDIS      0x15
#define SD_OP_FLUSH_VDI      0x16
#define SD_OP_DEL_VDI        0x17

#define SD_FLAG_CMD_WRITE    0x01
#define SD_FLAG_CMD_COW      0x02
#define SD_FLAG_CMD_CACHE    0x04 /* Writeback mode for cache */
#define SD_FLAG_CMD_DIRECT   0x08 /* Don't use cache */
/* return something back while sending something to sheep */
#define SD_FLAG_CMD_PIGGYBACK   0x10
#define SD_FLAG_CMD_TGT   0x20

#define SD_RES_SUCCESS       0x00 /* Success */
#define SD_RES_UNKNOWN       0x01 /* Unknown error */
#define SD_RES_NO_OBJ        0x02 /* No object found */
#define SD_RES_EIO           0x03 /* I/O error */
#define SD_RES_VDI_EXIST     0x04 /* Vdi exists already */
#define SD_RES_INVALID_PARMS 0x05 /* Invalid parameters */
#define SD_RES_SYSTEM_ERROR  0x06 /* System error */
#define SD_RES_VDI_LOCKED    0x07 /* Vdi is locked */
#define SD_RES_NO_VDI        0x08 /* No vdi found */
#define SD_RES_NO_BASE_VDI   0x09 /* No base vdi found */
#define SD_RES_VDI_READ      0x0A /* Cannot read requested vdi */
#define SD_RES_VDI_WRITE     0x0B /* Cannot write requested vdi */
#define SD_RES_BASE_VDI_READ 0x0C /* Cannot read base vdi */
#define SD_RES_BASE_VDI_WRITE   0x0D /* Cannot write base vdi */
#define SD_RES_NO_TAG        0x0E /* Requested tag is not found */
#define SD_RES_STARTUP       0x0F /* Sheepdog is on starting up */
#define SD_RES_VDI_NOT_LOCKED   0x10 /* Vdi is not locked */
#define SD_RES_SHUTDOWN      0x11 /* Sheepdog is shutting down */
#define SD_RES_NO_MEM        0x12 /* Cannot allocate memory */
#define SD_RES_FULL_VDI      0x13 /* we already have the maximum vdis */
#define SD_RES_VER_MISMATCH  0x14 /* Protocol version mismatch */
#define SD_RES_NO_SPACE      0x15 /* Server has no room for new objects */
#define SD_RES_WAIT_FOR_FORMAT  0x16 /* Waiting for a format operation */
#define SD_RES_WAIT_FOR_JOIN    0x17 /* Waiting for other nodes joining */
#define SD_RES_JOIN_FAILED   0x18 /* Target node had failed to join sheepdog */
#define SD_RES_HALT          0x19 /* Sheepdog is stopped serving IO request */
#define SD_RES_READONLY      0x1A /* Object is read-only */
#define SD_RES_INCOMPLETE    0x1B /* Object (in kv) is incomplete uploading */
/* sheep is collecting cluster wide status, not ready for operation */
#define SD_RES_COLLECTING_CINFO 0x1C
/* inode object in client is invalidated, refreshing is required */
#define SD_RES_INODE_INVALIDATED 0x1D

/*
 * Object ID rules
 *
 *  0 - 19 (20 bits): data object space
 * 20 - 31 (12 bits): reserved data object space
 * 32 - 55 (24 bits): vdi object space
 * 56 - 59 ( 4 bits): reserved vdi object space
 * 60 - 63 ( 4 bits): object type identifier space
 */

#define VDI_SPACE_SHIFT   32
#define VDI_BIT (UINT64_C(1) << 63)
#define VMSTATE_BIT (UINT64_C(1) << 62)
#define MAX_DATA_OBJS (UINT64_C(1) << 20)
#define MAX_CHILDREN 1024
#define SD_MAX_VDI_LEN 256
#define SD_MAX_VDI_TAG_LEN 256
#define SD_NR_VDIS   (1U << 24)
#define SD_DATA_OBJ_SIZE (UINT64_C(1) << 22)
#define SD_MAX_VDI_SIZE (SD_DATA_OBJ_SIZE * MAX_DATA_OBJS)
#define SECTOR_SIZE 512

#define CURRENT_VDI_ID 0

#define RETRY_OVER 10

struct sheepdog_req {
	uint8_t proto_ver;
	uint8_t opcode;
	uint16_t flags;
	uint32_t epoch;
	uint32_t id;
	uint32_t data_length;
	uint32_t opcode_specific[8];
};

struct sheepdog_rsp {
	uint8_t proto_ver;
	uint8_t opcode;
	uint16_t flags;
	uint32_t epoch;
	uint32_t id;
	uint32_t data_length;
	uint32_t result;
	uint32_t opcode_specific[7];
};

struct sheepdog_obj_req {
	uint8_t proto_ver;
	uint8_t opcode;
	uint16_t flags;
	uint32_t epoch;
	uint32_t id;
	uint32_t data_length;
	uint64_t oid;
	uint64_t cow_oid;
	uint8_t copies;
	uint8_t copy_policy;
	uint8_t ec_index;
	uint8_t reserved;
	uint32_t rsvd;
	uint32_t offset;
	uint32_t pad;
};

struct sheepdog_obj_rsp {
	uint8_t proto_ver;
	uint8_t opcode;
	uint16_t flags;
	uint32_t epoch;
	uint32_t id;
	uint32_t data_length;
	uint32_t result;
	uint8_t copies;
	uint8_t reserved[3];
	uint32_t pad[6];
};

#define LOCK_TYPE_NORMAL 0
#define LOCK_TYPE_SHARED 1      /* for iSCSI multipath */

struct sheepdog_vdi_req {
	uint8_t proto_ver;
	uint8_t opcode;
	uint16_t flags;
	uint32_t epoch;
	uint32_t id;
	uint32_t data_length;
	uint64_t vdi_size;
	uint32_t vdi_id;
	uint8_t copies;
	uint8_t copy_policy;
	uint8_t ec_index;
	uint8_t block_size_shift;
	uint32_t snapid;
	uint32_t type;
	uint32_t pad[2];
};

struct sheepdog_vdi_rsp {
	uint8_t proto_ver;
	uint8_t opcode;
	uint16_t flags;
	uint32_t epoch;
	uint32_t id;
	uint32_t data_length;
	uint32_t result;
	uint32_t rsvd;
	uint32_t vdi_id;
	uint32_t attr_id;
	uint8_t copies;
	uint8_t block_size_shift;
	uint8_t reserved[2];
	uint32_t pad[3];
};

/*
 * Historical notes: previous version of sheepdog (< v0.9.0) has a limit of
 * maximum number of children which can be created from single VDI. So the inode
 * object has an array for storing the IDs of the child VDIs. The constant
 * OLD_MAX_CHILDREN represents it. Current sheepdog doesn't have the limitation,
 * so we are recycling the area (4 * OLD_MAX_CHILDREN = 4KB) for storing new
 * metadata.
 *
 * users of the released area:
 * - uint32_t btree_counter
 */
#define OLD_MAX_CHILDREN 1024U

struct sheepdog_inode {
	char name[SD_MAX_VDI_LEN];
	char tag[SD_MAX_VDI_TAG_LEN];
	uint64_t create_time;
	uint64_t snap_ctime;
	uint64_t vm_clock_nsec;
	uint64_t vdi_size;
	uint64_t vm_state_size;
	uint8_t  copy_policy;
	uint8_t  store_policy;
	uint8_t nr_copies;
	uint8_t block_size_shift;
	uint32_t snap_id;
	uint32_t vdi_id;
	uint32_t parent_vdi_id;

	uint32_t btree_counter;
	uint32_t __unused[OLD_MAX_CHILDREN - 1];

	uint32_t data_vdi_id[MAX_DATA_OBJS];
};

#define SD_INODE_SIZE (sizeof(struct sheepdog_inode))

struct sheepdog_fd_list {
	int fd;
	pthread_t id;

	struct flist_head list;
};

#define UNIX_PATH_MAX 108

struct sheepdog_access_info {
	int is_unix;

	/* tcp */
	char hostname[HOST_NAME_MAX + 1];
	int port;

	/* unix domain socket */
	char uds_path[UNIX_PATH_MAX];

	/*
	 * maximum length of fd_list_head: nr_iothreads + 1
	 * (+ 1 is for main thread)
	 *
	 * TODO: more effective data structure for handling massive parallel
	 * access
	 */
	struct flist_head fd_list_head;
	pthread_rwlock_t fd_list_lock;

	struct sheepdog_inode inode;
	pthread_rwlock_t inode_lock;

	pthread_mutex_t inode_version_mutex;
	uint64_t inode_version;
};

static inline uint64_t vid_to_vdi_oid(uint32_t vid)
{
	return VDI_BIT | ((uint64_t)vid << VDI_SPACE_SHIFT);
}

static inline uint64_t vid_to_data_oid(uint32_t vid, uint32_t idx)
{
	return ((uint64_t)vid << VDI_SPACE_SHIFT) | idx;
}

static const char *sd_strerror(int err)
{
	int i;

	static const struct {
		int err;
		const char *desc;
	} errors[] = {
		{SD_RES_SUCCESS,
			"Success"},
		{SD_RES_UNKNOWN,
			"Unknown error"},
		{SD_RES_NO_OBJ, "No object found"},
		{SD_RES_EIO, "I/O error"},
		{SD_RES_VDI_EXIST, "VDI exists already"},
		{SD_RES_INVALID_PARMS, "Invalid parameters"},
		{SD_RES_SYSTEM_ERROR, "System error"},
		{SD_RES_VDI_LOCKED, "VDI is already locked"},
		{SD_RES_NO_VDI, "No vdi found"},
		{SD_RES_NO_BASE_VDI, "No base VDI found"},
		{SD_RES_VDI_READ, "Failed read the requested VDI"},
		{SD_RES_VDI_WRITE, "Failed to write the requested VDI"},
		{SD_RES_BASE_VDI_READ, "Failed to read the base VDI"},
		{SD_RES_BASE_VDI_WRITE, "Failed to write the base VDI"},
		{SD_RES_NO_TAG, "Failed to find the requested tag"},
		{SD_RES_STARTUP, "The system is still booting"},
		{SD_RES_VDI_NOT_LOCKED, "VDI isn't locked"},
		{SD_RES_SHUTDOWN, "The system is shutting down"},
		{SD_RES_NO_MEM, "Out of memory on the server"},
		{SD_RES_FULL_VDI, "We already have the maximum vdis"},
		{SD_RES_VER_MISMATCH, "Protocol version mismatch"},
		{SD_RES_NO_SPACE, "Server has no space for new objects"},
		{SD_RES_WAIT_FOR_FORMAT, "Sheepdog is waiting for a format operation"},
		{SD_RES_WAIT_FOR_JOIN, "Sheepdog is waiting for other nodes joining"},
		{SD_RES_JOIN_FAILED, "Target node had failed to join sheepdog"},
		{SD_RES_HALT, "Sheepdog is stopped serving IO request"},
		{SD_RES_READONLY, "Object is read-only"},
		{SD_RES_INODE_INVALIDATED, "Inode object is invalidated"},
	};

	for (i = 0; i < ARRAY_SIZE(errors); ++i) {
		if (errors[i].err == err)
			return errors[i].desc;
	}

	return "Invalid error code";
}

static int connect_to_sdog_tcp(const char *addr, int port)
{
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	int fd, ret;
	struct addrinfo hints, *res, *res0;
	char port_s[6];

	if (!addr) {
		addr = SD_DEFAULT_ADDR;
		port = SD_DEFAULT_PORT;
	}

	memset(port_s, 0, 6);
	snprintf(port_s, 5, "%d", port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;

	ret = getaddrinfo(addr, port_s, &hints, &res0);
	if (ret) {
		log_err("unable to get address info %s, %s\n",
				addr, strerror(errno));
		return -1;
	}

	for (res = res0; res; res = res->ai_next) {
		ret = getnameinfo(res->ai_addr, res->ai_addrlen, hbuf,
				sizeof(hbuf), sbuf, sizeof(sbuf),
				NI_NUMERICHOST | NI_NUMERICSERV);
		if (ret)
			continue;

		fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (fd < 0)
			continue;

reconnect:
		ret = connect(fd, res->ai_addr, res->ai_addrlen);
		if (ret < 0) {
			if (errno == EINTR)
				goto reconnect;

			close(fd);
			break;
		}

		goto success;
	}
	fd = -1;
	log_err("failed connect to %s:%d\n", addr, port);
success:
	freeaddrinfo(res0);
	return fd;
}

static int connect_to_sdog_unix(const char *path)
{
	int fd, ret;
	struct sockaddr_un un;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		log_err("socket() failed: %m\n");
		return -1;
	}

	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	strncpy(un.sun_path, path, sizeof(un.sun_path) - 1);

	ret = connect(fd, (const struct sockaddr *)&un, (socklen_t)sizeof(un));
	if (ret < 0) {
		log_err("connect() failed: %m\n");
		close(fd);
		return -1;
	}

	return fd;
}

static int get_my_fd(struct sheepdog_access_info *ai)
{
	pthread_t self_id = pthread_self();
	struct sheepdog_fd_list *p;
	int fd;

	pthread_rwlock_rdlock(&ai->fd_list_lock);
	flist_for_each_entry(p, &ai->fd_list_head, list) {
		if (p->id == self_id) {
			pthread_rwlock_unlock(&ai->fd_list_lock);
			return p->fd;
		}
	}
	pthread_rwlock_unlock(&ai->fd_list_lock);

	if (ai->is_unix)
		fd = connect_to_sdog_unix(ai->uds_path);
	else
		fd = connect_to_sdog_tcp(ai->hostname, ai->port);
	if (fd < 0)
		return -1;

	p = zalloc(sizeof(*p));
	if (!p) {
		close(fd);
		return -1;
	}

	p->id = self_id;
	p->fd = fd;
	INIT_FLIST_HEAD(&p->list);

	pthread_rwlock_wrlock(&ai->fd_list_lock);
	flist_add_tail(&p->list, &ai->fd_list_head);
	pthread_rwlock_unlock(&ai->fd_list_lock);

	return p->fd;
}

static void close_my_fd(struct sheepdog_access_info *ai, int fd)
{
	struct sheepdog_fd_list *p;
	int closed = 0;

	pthread_rwlock_wrlock(&ai->fd_list_lock);
	flist_for_each_entry(p, &ai->fd_list_head, list) {
		if (p->fd == fd) {
			close(fd);
			flist_del(&p->list);
			free(p);
			closed = 1;

			break;
		}
	}
	pthread_rwlock_unlock(&ai->fd_list_lock);

	if (!closed)
		log_err("unknown fd to close: %d\n", fd);
}

static int do_read(int sockfd, void *buf, int len)
{
	int ret;
reread:
	ret = read(sockfd, buf, len);

	if (!ret) {
		log_err("connection is closed (%d bytes left)\n", len);
		return 1;
	}

	if (ret < 0) {
		if (errno == EINTR || errno == EAGAIN)
			goto reread;

		log_err("failed to read from socket: %d, %s\n",
				ret, strerror(errno));

		return 1;
	}

	len -= ret;
	buf = (char *)buf + ret;
	if (len)
		goto reread;

	return 0;
}

static void forward_iov(struct msghdr *msg, int len)
{
	while (msg->msg_iov->iov_len <= len) {
		len -= msg->msg_iov->iov_len;
		msg->msg_iov++;
		msg->msg_iovlen--;
	}

	msg->msg_iov->iov_base = (char *) msg->msg_iov->iov_base + len;
	msg->msg_iov->iov_len -= len;
}


static int do_write(int sockfd, struct msghdr *msg, int len)
{
	int ret;
rewrite:
	ret = sendmsg(sockfd, msg, 0);
	if (ret < 0) {
		if (errno == EINTR || errno == EAGAIN)
			goto rewrite;

		log_err("failed to write to socket: %d, %s\n",
				ret, strerror(errno));
		return 1;
	}

	len -= ret;
	if (len) {
		forward_iov(msg, ret);
		goto rewrite;
	}

	return 0;
}

static int send_req(int sockfd, struct sheepdog_req *hdr, void *data,
		unsigned int *wlen)
{
	int ret;
	struct iovec iov[2];
	struct msghdr msg;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;

	msg.msg_iovlen = 1;
	iov[0].iov_base = hdr;
	iov[0].iov_len = sizeof(*hdr);

	if (*wlen) {
		msg.msg_iovlen++;
		iov[1].iov_base = data;
		iov[1].iov_len = *wlen;
	}

	ret = do_write(sockfd, &msg, sizeof(*hdr) + *wlen);
	if (ret) {
		log_err("failed to send a req, %s\n", strerror(errno));
		ret = -1;
	}

	return ret;
}

static int do_req(struct sheepdog_access_info *ai, struct sheepdog_req *hdr,
		void *data, unsigned int *wlen, unsigned int *rlen)
{
	int ret = 0, sockfd, count = 0;

retry:
	if (count > RETRY_OVER) {
		log_err("connecting to sheep process failed.\n");
		return ret;
	}

	if (count++) {
		log_err("retrying to reconnect (%d)\n", count);
		if (0 <= sockfd)
			close_my_fd(ai, sockfd);

		sleep(1);
	}

	sockfd = get_my_fd(ai);
	if (sockfd < 0)
		goto retry;

	ret = send_req(sockfd, hdr, data, wlen);
	if (ret)
		goto retry;

	ret = do_read(sockfd, hdr, sizeof(*hdr));
	if (ret)
		goto retry;

	if (hdr->data_length < *rlen)
		*rlen = hdr->data_length;

	if (*rlen) {
		ret = do_read(sockfd, data, *rlen);
		if (ret)
			goto retry;
	}

	return 0;
}

static int find_vdi_name(struct sheepdog_access_info *ai, char *filename,
		uint32_t snapid, char *tag, uint32_t *vid,
		int for_snapshot);
static int read_object(struct sheepdog_access_info *ai, char *buf, uint64_t oid,
		int copies, unsigned int datalen, uint32_t offset,
		int *need_reload);

static int reload_inode(struct sheepdog_access_info *ai, int is_snapshot)
{
	int ret = 0, need_reload = 0;
	char tag[SD_MAX_VDI_TAG_LEN];
	uint32_t vid;

	static __thread uint64_t inode_version;

	pthread_mutex_lock(&ai->inode_version_mutex);

	if (inode_version != ai->inode_version) {
		/* some other threads reloaded inode */
		inode_version = ai->inode_version;
		goto ret;
	}

	if (is_snapshot) {
		memset(tag, 0, sizeof(tag));

		ret = find_vdi_name(ai, ai->inode.name, CURRENT_VDI_ID, tag,
				&vid, 0);
		if (ret) {
			ret = -1;
			goto ret;
		}

		ret = read_object(ai, (char *)&ai->inode, vid_to_vdi_oid(vid),
				ai->inode.nr_copies,
				offsetof(struct sheepdog_inode, data_vdi_id),
				0, &need_reload);
		if (ret) {
			ret = -1;
			goto ret;
		}
	} else {
		ret = read_object(ai, (char *)&ai->inode,
				vid_to_vdi_oid(ai->inode.vdi_id),
				ai->inode.nr_copies, SD_INODE_SIZE, 0,
				&need_reload);
		if (ret) {
			ret = -1;
			goto ret;
		}

		if (!!ai->inode.snap_ctime) {
			/*
			 * This is a case like below:
			 * take snapshot -> write something -> failover
			 *
			 * Because invalidated inode is readonly and latest
			 * working VDI can have COWed objects, we need to
			 * resolve VID and reload its entire inode object.
			 */
			memset(tag, 0, sizeof(tag));

			ret = find_vdi_name(ai, ai->inode.name, CURRENT_VDI_ID,
					tag, &vid, 0);
			if (ret) {
				ret = -1;
				goto ret;
			}

			ret = read_object(ai, (char *)&ai->inode,
					vid_to_vdi_oid(vid),
					ai->inode.nr_copies, SD_INODE_SIZE, 0,
					&need_reload);
			if (ret) {
				ret = -1;
				goto ret;
			}
		}
	}

	inode_version++;
	ai->inode_version = inode_version;

ret:
	pthread_mutex_unlock(&ai->inode_version_mutex);
	return ret;
}

static int read_write_object(struct sheepdog_access_info *ai, char *buf,
		uint64_t oid, int copies,
		unsigned int datalen, uint32_t offset,
		int write, int create, uint64_t old_oid,
		uint16_t flags, int *need_reload)
{
	struct sheepdog_obj_req hdr;
	struct sheepdog_obj_rsp *rsp = (struct sheepdog_obj_rsp *)&hdr;
	unsigned int wlen, rlen;
	int ret;

retry:
	memset(&hdr, 0, sizeof(hdr));

	hdr.proto_ver = SD_PROTO_VER;
	hdr.flags = flags;
	if (write) {
		wlen = datalen;
		rlen = 0;
		hdr.flags |= SD_FLAG_CMD_WRITE;
		if (create) {
			hdr.opcode = SD_OP_CREATE_AND_WRITE_OBJ;
			hdr.cow_oid = old_oid;
		} else {
			hdr.opcode = SD_OP_WRITE_OBJ;
		}
	} else {
		wlen = 0;
		rlen = datalen;
		hdr.opcode = SD_OP_READ_OBJ;
	}
	hdr.oid = oid;
	hdr.data_length = datalen;
	hdr.offset = offset;
	hdr.copies = copies;
	hdr.flags |= SD_FLAG_CMD_TGT;

	ret = do_req(ai, (struct sheepdog_req *)&hdr, buf, &wlen, &rlen);
	if (ret) {
		log_err("failed to send a request to the sheep\n");
		return -1;
	}

	switch (rsp->result) {
		case SD_RES_SUCCESS:
			return 0;
		case SD_RES_INODE_INVALIDATED:
			log_info("inode object is invalidated\n");
			*need_reload = 2;
			return 0;
		case SD_RES_READONLY:
			*need_reload = 1;
			return 0;
		case SD_RES_NO_OBJ:
			if (!write && oid & (UINT64_C(1) << 63))
				/*
				 * sheepdog doesn't provide a mechanism of metadata
				 * transaction, so tgt can see an inconsistent state
				 * like this (old working VDI became snapshot already
				 * but an inode object of new working VDI isn't
				 * created yet).
				 */
				goto retry;
			return -1;
		default:
			log_err("%s (oid: %" PRIx64 ", old_oid: %" PRIx64 ")\n",
					sd_strerror(rsp->result), oid, old_oid);
			return -1;
	}
}

static int read_object(struct sheepdog_access_info *ai, char *buf,
		uint64_t oid, int copies,
		unsigned int datalen, uint32_t offset, int *need_reload)
{
	return read_write_object(ai, buf, oid, copies, datalen, offset,
			0, 0, 0, 0, need_reload);
}

static int write_object(struct sheepdog_access_info *ai, char *buf,
		uint64_t oid, int copies,
		unsigned int datalen, uint32_t offset, int create,
		uint64_t old_oid, uint16_t flags, int *need_reload)
{
	return read_write_object(ai, buf, oid, copies, datalen, offset, 1,
			create, old_oid, flags, need_reload);
}

static int update_inode(struct sheepdog_access_info *ai, uint32_t min, uint32_t max)
{
	int ret = 0, need_reload_inode = 0;
	uint64_t oid = vid_to_vdi_oid(ai->inode.vdi_id);
	uint32_t offset, data_len;

	if (max < min)
		goto end;

	goto update;

reload:
	reload_inode(ai, 0);
	need_reload_inode = 0;

update:
	offset = sizeof(ai->inode) - sizeof(ai->inode.data_vdi_id) +
		min * sizeof(ai->inode.data_vdi_id[0]);
	data_len = (max - min + 1) * sizeof(ai->inode.data_vdi_id[0]);

	ret = write_object(ai, (char *)&ai->inode + offset, oid,
			ai->inode.nr_copies, data_len, offset,
			0, 0, 0, &need_reload_inode);
	if (ret < 0)
		log_err("sync inode failed\n");

	if (need_reload_inode) {
		log_info("reloading inode is required in the path"
				" of update_inode()\n");
		goto reload;
	}

end:

	return ret;
}

static int is_refresh_required(struct sheepdog_access_info *ai)
	/*
	 * 0: refresh isn't required
	 * 1: refresh is required
	 */
{
	uint64_t inode_oid = vid_to_vdi_oid(ai->inode.vdi_id);
	char dummy;
	int need_reload_inode = 0;

	read_object(ai, &dummy, inode_oid, ai->inode.nr_copies, sizeof(dummy),
			0, &need_reload_inode);

	return need_reload_inode;
}

static int sd_io(struct sheepdog_access_info *ai, int write, char *buf, int len,
		uint64_t offset)
{
	uint32_t vid;
	uint32_t object_size = (UINT32_C(1) << ai->inode.block_size_shift);
	unsigned long idx = offset / object_size;
	unsigned long max =
		(offset + len + (object_size - 1)) / object_size;
	unsigned obj_offset = offset % object_size;
	size_t orig_size, size, rest = len;
	int ret = 0, create;
	uint64_t oid, old_oid;
	uint16_t flags = 0;
	int need_update_inode = 0, need_reload_inode;
	int nr_copies = ai->inode.nr_copies;
	int need_write_lock, check_idx;
	int read_reload_snap = 0;
	uint32_t min_dirty_data_idx = UINT32_MAX, max_dirty_data_idx = 0;
	goto do_req;

reload_in_read_path:
	pthread_rwlock_unlock(&ai->inode_lock); /* unlock current read lock */

	pthread_rwlock_wrlock(&ai->inode_lock);
	ret = reload_inode(ai, read_reload_snap);
	if (ret) {
		log_err("failed to reload in read path\n");
		goto out;
	}
	pthread_rwlock_unlock(&ai->inode_lock);

do_req:
	need_write_lock = 0;
	vid = ai->inode.vdi_id;

	for (check_idx = idx; check_idx < max; check_idx++) {
		if (ai->inode.data_vdi_id[check_idx] == vid)
			continue;

		need_write_lock = 1;
		break;
	}

	if (need_write_lock)
		pthread_rwlock_wrlock(&ai->inode_lock);
	else
		pthread_rwlock_rdlock(&ai->inode_lock);

	for (; idx < max; idx++) {
		orig_size = size;
		size = object_size - obj_offset;
		size = min_t(size_t, size, rest);

retry:
		vid = ai->inode.vdi_id;
		oid = vid_to_data_oid(ai->inode.data_vdi_id[idx], idx);
		old_oid = 0;

		if (write) {
			flags = SD_FLAG_CMD_DIRECT;
			create = 0;

			if (ai->inode.data_vdi_id[idx] != vid) {
				create = 1;

				if (ai->inode.data_vdi_id[idx]) {
					old_oid = oid;
					flags |= SD_FLAG_CMD_COW;
				}

				oid = vid_to_data_oid(ai->inode.vdi_id, idx);

			}

			need_reload_inode = 0;
			ret = write_object(ai, buf + (len - rest),
					oid, nr_copies, size,
					obj_offset, create,
					old_oid, flags, &need_reload_inode);
			if (!ret) {
				if (need_reload_inode) {
					ret = reload_inode(ai,
							need_reload_inode == 1);
					if (!ret)
						goto retry;
				}

				if (create) {
					min_dirty_data_idx =
						min_t(uint32_t, idx,
								min_dirty_data_idx);
					max_dirty_data_idx =
						max_t(uint32_t, idx,
								max_dirty_data_idx);
					ai->inode.data_vdi_id[idx] = vid;

					need_update_inode = 1;
					create = 0;
				}
			}
		} else {
			if (!ai->inode.data_vdi_id[idx]) {
				int check = is_refresh_required(ai);
				if (!check) {
					memset(buf, 0, size);
					goto done;
				} else {
					log_info("reload in read path for not"\
							" written area\n");
					size = orig_size;
					read_reload_snap =
						need_reload_inode == 1;
					goto reload_in_read_path;
				}
			}
			need_reload_inode = 0;
			ret = read_object(ai, buf + (len - rest),
					oid, nr_copies, size,
					obj_offset, &need_reload_inode);
			if (need_reload_inode) {
				log_info("reload in ordinal read path\n");
				size = orig_size;
				read_reload_snap = need_reload_inode == 1;
				goto reload_in_read_path;
			}
		}

		if (ret) {
			log_err("%lu %d\n", idx, ret);
			goto out;
		}

done:
		rest -= size;
		obj_offset = 0;
	}

	if (need_update_inode)
		ret = update_inode(ai, min_dirty_data_idx, max_dirty_data_idx);

out:
	pthread_rwlock_unlock(&ai->inode_lock);

	return ret;
}

static int find_vdi_name(struct sheepdog_access_info *ai, char *filename,
		uint32_t snapid, char *tag, uint32_t *vid,
		int for_snapshot)
{
	int ret;
	struct sheepdog_vdi_req hdr;
	struct sheepdog_vdi_rsp *rsp = (struct sheepdog_vdi_rsp *)&hdr;
	unsigned int wlen, rlen = 0;
	char buf[SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN];

	memset(buf, 0, sizeof(buf));
	strncpy(buf, filename, SD_MAX_VDI_LEN - 1);
	strncpy(buf + SD_MAX_VDI_LEN, tag, SD_MAX_VDI_TAG_LEN - 1);

	memset(&hdr, 0, sizeof(hdr));
	if (for_snapshot)
		hdr.opcode = SD_OP_GET_VDI_INFO;
	else
		hdr.opcode = SD_OP_LOCK_VDI;
	hdr.type = LOCK_TYPE_SHARED;

	wlen = SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN;
	hdr.proto_ver = SD_PROTO_VER;
	hdr.data_length = wlen;
	hdr.snapid = snapid;
	hdr.flags = SD_FLAG_CMD_WRITE;

	ret = do_req(ai, (struct sheepdog_req *)&hdr, buf, &wlen, &rlen);
	if (ret) {
		ret = -1;
		goto out;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		log_err("cannot get vdi info, %s, %s %d %s\n",
				sd_strerror(rsp->result), filename, snapid, tag);
		ret = -1;
		goto out;
	}
	*vid = rsp->vdi_id;

	ret = 0;

out:
	return ret;
}

static int sd_open(struct sheepdog_access_info *ai, char *filename, int flags)
{
	int ret = 0, i, len, fd, need_reload = 0;
	uint32_t vid = 0;
	char *orig_filename;
	char tag[] = "";

	char vdi_name[SD_MAX_VDI_LEN + 1];
	char *saveptr = NULL, *result;
	enum {
		EXPECT_PROTO,
		EXPECT_PATH,
		EXPECT_HOST,
		EXPECT_PORT,
		EXPECT_VDI,
		EXPECT_NOTHING,
	} parse_state = EXPECT_PROTO;

	memset(vdi_name, 0, sizeof(vdi_name));

	orig_filename = strdup(filename);
	if (!orig_filename) {
		log_err("saving original filename failed\n");
		return -1;
	}

	/*
	 * expected form of filename:
	 *
	 * unix:<path_of_unix_domain_socket>:<vdi>
	 * tcp:<host>:<port>:<vdi>
	 */

	result = strtok_r(filename, ":", &saveptr);

	do {
		switch (parse_state) {
			case EXPECT_PROTO:
				if (!strcmp("unix", result)) {
					ai->is_unix = 1;
					parse_state = EXPECT_PATH;
				} else if (!strcmp("tcp", result)) {
					ai->is_unix = 0;
					parse_state = EXPECT_HOST;
				} else {
					log_err("unknown protocol of sheepdog vdi:"\
							" %s\n", result);
					ret = -1;
					goto out;
				}
				break;
			case EXPECT_PATH:
				strncpy(ai->uds_path, result, UNIX_PATH_MAX - 1);
				parse_state = EXPECT_VDI;
				break;
			case EXPECT_HOST:
				strncpy(ai->hostname, result, HOST_NAME_MAX);
				parse_state = EXPECT_PORT;
				break;
			case EXPECT_PORT:
				len = strlen(result);
				for (i = 0; i < len; i++) {
					if (!isdigit(result[i])) {
						log_err("invalid tcp port number:"\
								" %s\n", result);
						ret = -1;
						goto out;
					}
				}

				ai->port = atoi(result);
				parse_state = EXPECT_VDI;
				break;
			case EXPECT_VDI:
				strncpy(vdi_name, result, SD_MAX_VDI_LEN);
				parse_state = EXPECT_NOTHING;
				break;
			case EXPECT_NOTHING:
				log_err("invalid VDI path of sheepdog, unexpected"\
						" token: %s (entire: %s)\n",
						result, orig_filename);
				ret = -1;
				goto out;
			default:
				log_err("BUG: invalid state of parser: %d\n",
						parse_state);
				exit(1);
		}
	} while ((result = strtok_r(NULL, ":", &saveptr)) != NULL);

	if (parse_state != EXPECT_NOTHING) {
		log_err("invalid VDI path of sheepdog: %s (state: %d)\n",
				orig_filename, parse_state);
		ret = -1;
		goto out;
	}

	/*
	 * test connection for validating command line option
	 */
	fd = ai->is_unix ?
		connect_to_sdog_unix(ai->uds_path) :
		connect_to_sdog_tcp(ai->hostname, ai->port);

	if (fd < 0) {
		log_err("connecting to sheep process failed, "\
				"please verify the -target option: %s",
				orig_filename);
		ret = -1;
		goto out;
	}

	close(fd);		/* we don't need this connection */

	ret = find_vdi_name(ai, vdi_name, 0, tag, &vid, 0);
	if (ret)
		goto out;

	ret = read_object(ai, (char *)&ai->inode, vid_to_vdi_oid(vid),
			0, SD_INODE_SIZE, 0, &need_reload);
	if (ret)
		goto out;

	ret = 0;

out:
	strcpy(filename, orig_filename);
	free(orig_filename);

	return ret;
}

static void sd_close(struct sheepdog_access_info *ai)
{
	struct sheepdog_vdi_req hdr;
	struct sheepdog_vdi_rsp *rsp = (struct sheepdog_vdi_rsp *)&hdr;
	unsigned int wlen = 0, rlen = 0;
	int ret;

	memset(&hdr, 0, sizeof(hdr));

	hdr.opcode = SD_OP_RELEASE_VDI;
	hdr.type = LOCK_TYPE_SHARED;
	hdr.vdi_id = ai->inode.vdi_id;

	ret = do_req(ai, (struct sheepdog_req *)&hdr, NULL, &wlen, &rlen);

	if (!ret && rsp->result != SD_RES_SUCCESS &&
			rsp->result != SD_RES_VDI_NOT_LOCKED)
		log_err("%s, %s", sd_strerror(rsp->result), ai->inode.name);
}

/******************************************************************************
  END of sheepdog client's libraries
 *******************************************************************************/

struct sheepdog_data {
	struct sheepdog_access_info *ai;
};

struct sheepdog_options {
	void *pad;
	char *target;
};

static struct fio_option options[] = {
	{
		.name           = "target",
		.lname          = "sheepdog target",
		.type           = FIO_OPT_STR_STORE,
		.help           = "String of sheepdog access information including protocol, hostname, port and vdiname",
		.off1           = offsetof(struct sheepdog_options, target),
		.category       = FIO_OPT_C_ENGINE,
		.group          = FIO_OPT_G_SHEEPDOG,
	},
	{
		.name = NULL,
	},
};

static int fio_sheepdog_queue(struct thread_data *td, struct io_u *io_u)
{
	struct sheepdog_data *sd = td->io_ops_data;
	int ret = 0;

	dprint(FD_IO, "%s op %s\n", __FUNCTION__, io_ddir_name(io_u->ddir));

	fio_ro_check(td, io_u);

	if (io_u->ddir == DDIR_READ)
		ret = sd_io(sd->ai, 0, io_u->xfer_buf, io_u->xfer_buflen, io_u->offset);
	else if (io_u->ddir == DDIR_WRITE)
		ret = sd_io(sd->ai, 1, io_u->xfer_buf, io_u->xfer_buflen, io_u->offset);
	else {
		log_err("unsupported operation.\n");
		io_u->error = EINVAL;
		goto out;
	}

	if (ret) {
		log_err("sheepdog queue failed.\n");
		io_u->error = ret;
		td_verror(td, io_u->error, "xfer");
		goto out;
	}

out:
	return FIO_Q_COMPLETED;
}

static int fio_sheepdog_init(struct thread_data *td)
{
	struct sheepdog_data *sd;
	struct sheepdog_options *opt = td->eo;
	int ret = 0;

	if (td->io_ops_data)
		return 0;

	sd = calloc(1, sizeof(*sd));
	if (!sd) {
		log_err("malloc failed.\n");
		return -ENOMEM;
	} 

	sd->ai = malloc(sizeof(struct sheepdog_access_info));
	if (!sd->ai) {
		log_err("malloc failed.\n");
		free(sd);
		return -ENOMEM;
	}

	INIT_FLIST_HEAD(&sd->ai->fd_list_head);
	pthread_rwlock_init(&sd->ai->fd_list_lock, NULL);
	pthread_rwlock_init(&sd->ai->inode_lock, NULL);
	pthread_mutex_init(&sd->ai->inode_version_mutex, NULL);

	ret = sd_open(sd->ai, opt->target, 0);

	if (ret) {
		sd_close(sd->ai);
		free(sd->ai);
		free(sd);
		return ret;
	} else {
		log_info("Job No.%d, connected to target: %s\n", td->thread_number, opt->target);
	}

	td->io_ops_data = sd;

	sd_close(sd->ai);

	return ret;
}

static void fio_sheepdog_cleanup(struct thread_data *td)
{
	struct sheepdog_data *sd = td->io_ops_data;
	struct sheepdog_fd_list *p, *next;

	flist_for_each_entry_safe(p, next, &sd->ai->fd_list_head, list) {
		close(p->fd);
		flist_del(&p->list);
		free(p);
	}

	pthread_rwlock_destroy(&sd->ai->fd_list_lock);
	pthread_rwlock_destroy(&sd->ai->inode_lock);


	sd_close(sd->ai);

	free(sd->ai);
	free(sd);

	td->io_ops_data = NULL;
}

static int fio_sheepdog_open(struct thread_data *td, struct fio_file *f)
{
	struct sheepdog_data *sd = td->io_ops_data;
	unsigned long long left, offset;
	unsigned int bs;
	char *b;
	int ret;

	if (td_read(td)) {
		bs = READFILE_BLOCK_SIZE;
		b = malloc(bs);
		left = f->real_file_size;
		offset = 0;		

		while(left && !td->terminate) {
			if(bs > left)
				bs = left;
			fill_io_buffer(td, b, bs, bs);
			ret = sd_io(sd->ai, 1, b, bs, offset);
			if(ret)
				return ret;
			offset += bs;
			left -= bs;
		}
		free(b);
		fio_time_init();
	}

	return 0;
}

static int fio_sheepdog_close(struct thread_data *td, struct fio_file *f)
{
	return 0;
}

struct ioengine_ops ioengine = {
	.name		= "sheepdog",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_sheepdog_init,
	.queue		= fio_sheepdog_queue,
	.cleanup	= fio_sheepdog_cleanup,
	.open_file	= fio_sheepdog_open,
	.close_file	= fio_sheepdog_close,
	.options                = options,
	.option_struct_size     = sizeof(struct sheepdog_options),
	.flags = FIO_SYNCIO | FIO_DISKLESSIO,
};

static void fio_init fio_sheepdog_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_sheepdog_unregister(void)
{
	unregister_ioengine(&ioengine);
}
