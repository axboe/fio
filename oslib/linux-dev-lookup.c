#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "linux-dev-lookup.h"

int blktrace_lookup_device(const char *redirect, char *path, unsigned int maj,
			   unsigned int min)
{
	struct dirent *dir;
	struct stat st;
	int found = 0;
	DIR *D;

	D = opendir(path);
	if (!D)
		return 0;

	while ((dir = readdir(D)) != NULL) {
		char full_path[256];

		if (!strcmp(dir->d_name, ".") || !strcmp(dir->d_name, ".."))
			continue;

		sprintf(full_path, "%s/%s", path, dir->d_name);
		if (lstat(full_path, &st) == -1) {
			perror("lstat");
			break;
		}

		if (S_ISDIR(st.st_mode)) {
			found = blktrace_lookup_device(redirect, full_path,
								maj, min);
			if (found) {
				strcpy(path, full_path);
				break;
			}
		}

		if (!S_ISBLK(st.st_mode))
			continue;

		/*
		 * If replay_redirect is set then always return this device
		 * upon lookup which overrides the device lookup based on
		 * major minor in the actual blktrace
		 */
		if (redirect) {
			strcpy(path, redirect);
			found = 1;
			break;
		}

		if (maj == major(st.st_rdev) && min == minor(st.st_rdev)) {
			strcpy(path, full_path);
			found = 1;
			break;
		}
	}

	closedir(D);
	return found;
}
