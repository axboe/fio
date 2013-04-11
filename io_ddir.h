#ifndef FIO_DDIR_H
#define FIO_DDIR_H

enum fio_ddir {
	DDIR_READ = 0,
	DDIR_WRITE = 1,
	DDIR_TRIM = 2,
	DDIR_RWDIR_CNT = 3,
	DDIR_SYNC = 3,
	DDIR_DATASYNC,
	DDIR_SYNC_FILE_RANGE,
	DDIR_WAIT,
	DDIR_INVAL = -1,
};

enum td_ddir {
	TD_DDIR_READ		= 1 << 0,
	TD_DDIR_WRITE		= 1 << 1,
	TD_DDIR_RAND		= 1 << 2,
	TD_DDIR_TRIM		= 1 << 3,
	TD_DDIR_RW		= TD_DDIR_READ | TD_DDIR_WRITE,
	TD_DDIR_RANDREAD	= TD_DDIR_READ | TD_DDIR_RAND,
	TD_DDIR_RANDWRITE	= TD_DDIR_WRITE | TD_DDIR_RAND,
	TD_DDIR_RANDRW		= TD_DDIR_RW | TD_DDIR_RAND,
	TD_DDIR_RANDTRIM	= TD_DDIR_TRIM | TD_DDIR_RAND,
};

#define td_read(td)		((td)->o.td_ddir & TD_DDIR_READ)
#define td_write(td)		((td)->o.td_ddir & TD_DDIR_WRITE)
#define td_trim(td)		((td)->o.td_ddir & TD_DDIR_TRIM)
#define td_rw(td)		(((td)->o.td_ddir & TD_DDIR_RW) == TD_DDIR_RW)
#define td_random(td)		((td)->o.td_ddir & TD_DDIR_RAND)
#define file_randommap(td, f)	(!(td)->o.norandommap && (f)->io_axmap)

static inline int ddir_sync(enum fio_ddir ddir)
{
	return ddir == DDIR_SYNC || ddir == DDIR_DATASYNC ||
	       ddir == DDIR_SYNC_FILE_RANGE;
}

static inline int ddir_rw(enum fio_ddir ddir)
{
	return ddir == DDIR_READ || ddir == DDIR_WRITE || ddir == DDIR_TRIM;
}

static inline const char *ddir_str(enum td_ddir ddir)
{
	const char *ddir_str[] = { NULL, "read", "write", "rw", NULL,
				   "randread", "randwrite", "randrw",
				   "trim", NULL, NULL, NULL, "randtrim" };

	return ddir_str[ddir];
}

#define ddir_trim(ddir) ((ddir) == DDIR_TRIM)

#define ddir_rw_sum(arr)	\
	((arr)[DDIR_READ] + (arr)[DDIR_WRITE] + (arr)[DDIR_TRIM])

#endif
