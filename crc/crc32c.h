/* crc32c -- calculate and POSIX.2 checksum 
   Copyright (C) 92, 1995-1999 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#ifndef CRC32C_H
#define CRC32C_H

#include "../arch/arch.h"

extern uint32_t crc32c_sw(unsigned char const *, unsigned long);
extern int crc32c_intel_available;

#ifdef ARCH_HAVE_SSE4_2
extern uint32_t crc32c_intel(unsigned char const *, unsigned long);
extern void crc32c_intel_probe(void);
#else
#define crc32c_intel crc32c_sw
static inline void crc32c_intel_probe(void)
{
}
#endif

static inline uint32_t fio_crc32c(unsigned char const *buf, unsigned long len)
{
	if (crc32c_intel_available)
		return crc32c_intel(buf, len);

	return crc32c_sw(buf, len);
}

#endif
