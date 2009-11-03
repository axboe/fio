#ifndef FIO_DDIR_H
#define FIO_DDIR_H

enum fio_ddir {
	DDIR_READ = 0,
	DDIR_WRITE,
	DDIR_SYNC,
	DDIR_DATASYNC,
	DDIR_WAIT,
	DDIR_INVAL = -1,
};

enum td_ddir {
	TD_DDIR_READ		= 1 << 0,
	TD_DDIR_WRITE		= 1 << 1,
	TD_DDIR_RAND		= 1 << 2,
	TD_DDIR_RW		= TD_DDIR_READ | TD_DDIR_WRITE,
	TD_DDIR_RANDREAD	= TD_DDIR_READ | TD_DDIR_RAND,
	TD_DDIR_RANDWRITE	= TD_DDIR_WRITE | TD_DDIR_RAND,
	TD_DDIR_RANDRW		= TD_DDIR_RW | TD_DDIR_RAND,
};

#define td_read(td)		((td)->o.td_ddir & TD_DDIR_READ)
#define td_write(td)		((td)->o.td_ddir & TD_DDIR_WRITE)
#define td_rw(td)		(((td)->o.td_ddir & TD_DDIR_RW) == TD_DDIR_RW)
#define td_random(td)		((td)->o.td_ddir & TD_DDIR_RAND)
#define file_randommap(td, f)	(!(td)->o.norandommap && (f)->file_map)

static inline int ddir_sync(enum fio_ddir ddir)
{
	return ddir == DDIR_SYNC || ddir == DDIR_DATASYNC;
}

#endif
