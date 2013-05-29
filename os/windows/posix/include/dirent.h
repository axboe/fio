#ifndef DIRENT_H
#define DIRENT_H

#include <winsock2.h>

struct dirent
{
	ino_t  d_ino;     /*  File serial number */
	char   d_name[MAX_PATH];  /* Name of entry */
};

struct dirent_ctx
{
	HANDLE find_handle;
	char dirname[MAX_PATH];
};

typedef struct dirent_ctx DIR;

DIR *opendir(const char *dirname);
struct dirent *readdir(DIR *dirp);
int closedir(DIR *dirp);

#endif /* DIRENT_H */
