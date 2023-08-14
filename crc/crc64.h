#ifndef CRC64_H
#define CRC64_H

unsigned long long fio_crc64(const unsigned char *, unsigned long);

unsigned long long fio_crc64_nvme(unsigned long long crc, const void *p,
				  unsigned int len);

#endif
