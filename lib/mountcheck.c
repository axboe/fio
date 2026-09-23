#include <stdio.h>
#include <string.h>

#ifdef CONFIG_GETMNTENT
#include <mntent.h>

#include "mountcheck.h"

#define MTAB	"/etc/mtab"

int device_is_mounted(const char *dev)
{
	FILE *mtab;
	struct mntent *mnt;
	int ret = 0;

	mtab = setmntent(MTAB, "r");
	if (!mtab)
		return 0;

	while ((mnt = getmntent(mtab)) != NULL) {
		if (!mnt->mnt_fsname)
			continue;
		if (!strcmp(mnt->mnt_fsname, dev)) {
			ret = 1;
			break;
		}
	}

	endmntent(mtab);
	return ret;
}

#elif defined(CONFIG_GETMNTINFO)
/* for most BSDs */
#include <sys/param.h>
#include <sys/mount.h>

int device_is_mounted(const char *dev)
{
	struct statfs *st;
	int i, ret;

	ret = getmntinfo(&st, MNT_NOWAIT);
	if (ret <= 0)
		return 0;

	for (i = 0; i < ret; i++) {
		if (!strcmp(st[i].f_mntfromname, dev))
			return 1;
	}

	return 0;
}

#elif defined(CONFIG_GETMNTINFO_STATVFS)
/* for NetBSD */
#include <sys/statvfs.h>

int device_is_mounted(const char *dev)
{
	struct statvfs *st;
	int i, ret;

	ret = getmntinfo(&st, MNT_NOWAIT);
	if (ret <= 0)
		return 0;

	for (i = 0; i < ret; i++) {
		if (!strcmp(st[i].f_mntfromname, dev))
			return 1;
	}

	return 0;
}

#else
/* others */

int device_is_mounted(const char *dev)
{
	return 0;
}

#endif

#ifdef CONFIG_BLKID
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <blkid/blkid.h>

/*
 * Human-readable descriptions for the signatures libblkid reports on a
 * block device fio is about to overwrite. Partition table types come
 * from the PTTYPE value, the rest from TYPE.
 */
static const struct content_type_description {
	const char *type;
	const char *desc;
} content_type_descriptions[] = {
	{ "LVM2_member",	"an LVM physical volume" },
	{ "LUKS",		"a LUKS encrypted volume" },
	{ "LUKS2",		"a LUKS encrypted volume" },
	{ "swap",		"a swap area" },
	{ "linux_raid_member",	"a Linux RAID member device" },
	{ "ext2",		"an ext2 file system" },
	{ "ext3",		"an ext3 file system" },
	{ "ext4",		"an ext4 file system" },
	{ "xfs",		"an XFS file system" },
	{ "btrfs",		"a btrfs file system" },
	{ "vfat",		"a FAT file system" },
	{ "exfat",		"an exFAT file system" },
	{ "ntfs",		"an NTFS file system" },
	{ "f2fs",		"an F2FS file system" },
	{ "jfs",		"a JFS file system" },
	{ "reiserfs",		"a ReiserFS file system" },
	{ "iso9660",		"an ISO 9660 file system" },
	{ "udf",		"a UDF file system" },
	{ "zfs",		"a ZFS file system" },
	{ "zfs_member",	"a ZFS member device" },
	{ "dos",		"an MBR partition table" },
	{ "gpt",		"a GPT partition table" },
	{ "sun",		"a Sun partition table" },
	{ "sgi",		"an SGI partition table" },
	{ "mac",		"a Mac partition table" },
	{ "amiga",		"an Amiga partition table" },
	{ "bsd",		"a BSD partition table" },
	{ "aix",		"an AIX partition table" },
	{ NULL, NULL },
};

/*
 * Return a description of what libblkid identified on the device, given
 * the TYPE it reported (a libblkid TYPE or PTTYPE value). Unknown types
 * still deserve a warning; report the raw type.
 */
static const char *describe_content_type(const char *type)
{
	const struct content_type_description *t;
	static char desc[128];

	for (t = content_type_descriptions; t->type; t++)
		if (!strcmp(t->type, type))
			return t->desc;

	snprintf(desc, sizeof(desc), "data of type '%s'", type);
	return desc;
}

/*
 * Return what the block device 'dev' contains, judging from libblkid's
 * superblock and partition-table signatures, or NULL if nothing is
 * recognized. A partition table is reported in preference to a file
 * system. Every probing failure counts as "nothing detected", so this
 * check can never make fio fail on its own. Read-only probe, it cannot
 * alter the device.
 */
const char *blkdev_probe_content(const char *dev)
{
	struct stat st;
	const char *found = NULL;
	blkid_probe pr;
	int fd;

	if (stat(dev, &st) || !S_ISBLK(st.st_mode))
		return NULL;

	/*
	 * The device is opened read-only on a separate descriptor, so
	 * probing does not disturb the descriptors fio writes to;
	 * O_NONBLOCK guards against the file having changed type in
	 * the race after the stat call above.
	 */
	fd = open(dev, O_RDONLY | O_NONBLOCK);
	if (fd < 0)
		return NULL;

	if (fstat(fd, &st) == 0 && S_ISBLK(st.st_mode)) {
		pr = blkid_new_probe();
		if (pr) {
			/*
			 * Probing results are compared against plain
			 * integers rather than the BLKID_PROBE_* macros,
			 * as those macros are only available in
			 * libblkid >= 2.39 while the return-value
			 * semantics (0 = signature found) are stable
			 * across versions.
			 */
			if (blkid_probe_set_device(pr, fd, 0, 0) == 0 &&
			    blkid_probe_enable_superblocks(pr, 1) == 0 &&
			    blkid_probe_enable_partitions(pr, 1) == 0 &&
			    blkid_do_safeprobe(pr) == 0) {
				const char *type = NULL;

				if (blkid_probe_lookup_value(pr, "PTTYPE", &type, NULL) != 0)
					blkid_probe_lookup_value(pr, "TYPE", &type, NULL);
				found = type ? describe_content_type(type) : NULL;
			}

			/* the probe does not own fd, closing it is safe */
			blkid_free_probe(pr);
		}
	}

	close(fd);
	return found;
}

#else /* no libblkid: fail open */

const char *blkdev_probe_content(const char *dev)
{
	return NULL;
}

#endif
