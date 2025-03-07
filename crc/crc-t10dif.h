/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __CRC_T10DIF_H
#define __CRC_T10DIF_H

extern unsigned short fio_crc_t10dif(unsigned short crc,
				     const unsigned char *buffer,
				     unsigned int len);

#endif
