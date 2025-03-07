#ifndef SYS_SHM_H
#define SYS_SHM_H

#define IPC_RMID	0x1
#define IPC_CREAT	0x2
#define IPC_PRIVATE	0x4

typedef int uid_t;
typedef int gid_t;

typedef int shmatt_t;
typedef int key_t;

struct ipc_perm
{
	uid_t    uid;    /* owner's user ID */
	gid_t    gid;    /* owner's group ID */
	uid_t    cuid;   /* creator's user ID */
	gid_t    cgid;   /* creator's group ID */
	mode_t   mode;   /* read/write permission */
};


struct shmid_ds
{
	struct ipc_perm shm_perm;   /* operation permission structure */
	size_t          shm_segsz;  /* size of segment in bytes */
	pid_t           shm_lpid;   /* process ID of last shared memory operation */
	pid_t           shm_cpid;   /* process ID of creator */
	shmatt_t        shm_nattch; /* number of current attaches */
	time_t          shm_atime;  /* time of last shmat() */
	time_t          shm_dtime;  /* time of last shmdt() */
	time_t          shm_ctime;  /* time of last change by shmctl() */
};

int shmctl(int shmid, int cmd, struct shmid_ds *buf);
int shmget(key_t key, size_t size, int shmflg);
void *shmat(int shmid, const void *shmaddr, int shmflg);
int shmdt(const void *shmaddr);

#endif /* SYS_SHM_H */
