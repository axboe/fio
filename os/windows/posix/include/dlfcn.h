#ifndef DLFCN_H
#define DLFCN_H

#define RTLD_LAZY 1

void *dlopen(const char *file, int mode);
int dlclose(void *handle);
void *dlsym(void *restrict handle, const char *restrict name);
char *dlerror(void);

#endif /* DLFCN_H */
