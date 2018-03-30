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
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.  */

#ifndef CRC32C_H
#define CRC32C_H

#include <inttypes.h>

#include "../arch/arch.h"
#include "../lib/types.h"

extern uint32_t crc32c_sw(unsigned char const *, unsigned long);
extern bool crc32c_arm64_available;
extern bool crc32c_intel_available;

#ifdef ARCH_HAVE_CRC_CRYPTO
extern uint32_t crc32c_arm64(unsigned char const *, unsigned long);
extern void crc32c_arm64_probe(void);
#else
#define crc32c_arm64 crc32c_sw
static inline void crc32c_arm64_probe(void)
{
}
#endif /* ARCH_HAVE_CRC_CRYPTO */

#ifdef ARCH_HAVE_SSE4_2
extern uint32_t crc32c_intel(unsigned char const *, unsigned long);
extern void crc32c_intel_probe(void);
#else
#define crc32c_intel crc32c_sw
static inline void crc32c_intel_probe(void)
{
}
#endif /* ARCH_HAVE_SSE4_2 */

static inline uint32_t fio_crc32c(unsigned char const *buf, unsigned long len)
{
	if (crc32c_arm64_available)
		return crc32c_arm64(buf, len);

	if (crc32c_intel_available)
		return crc32c_intel(buf, len);

	return crc32c_sw(buf, len);
}

#endif
