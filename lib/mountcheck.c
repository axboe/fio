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

#else

int device_is_mounted(const char *dev)
{
	return 0;
}

#endif
