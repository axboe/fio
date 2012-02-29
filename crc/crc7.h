#ifndef CRC7_H
#define CRC7_H

extern const unsigned char crc7_syndrome_table[256];

static inline unsigned char crc7_byte(unsigned char crc, unsigned char data)
{
	return crc7_syndrome_table[(crc << 1) ^ data];
}

extern unsigned char fio_crc7(const unsigned char *buffer, unsigned int len);

#endif
