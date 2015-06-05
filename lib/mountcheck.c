#include <stdio.h>
#include <string.h>

#ifdef CONFIG_GETMNTENT
#include <mntent.h>

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
/* for BSDs */
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

#else
/* others */

int device_is_mounted(const char *dev)
{
	return 0;
}

#endif
