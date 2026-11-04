#ifndef FIO_MOUNT_CHECK_H
#define FIO_MOUNT_CHECK_H

extern int device_is_mounted(const char *);
extern const char *blkdev_probe_content(const char *dev);

#endif
