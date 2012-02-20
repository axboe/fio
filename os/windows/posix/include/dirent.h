#ifndef DIRENT_H
#define DIRENT_H

struct dirent
{
	ino_t  d_ino;     //  File serial number. 
	char   d_name[];   // Name of entry. 
};

typedef int DIR;

DIR *opendir(const char *dirname);
struct dirent *readdir(DIR *dirp);
int closedir(DIR *dirp);

#endif /* DIRENT_H */
