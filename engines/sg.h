/*
 * Shared inline helpers for SCSI byte-order accessors, used by both the
 * sg and bsg/io_uring_cmd engines.
 */

#ifndef FIO_SG_H
#define FIO_SG_H

#include "../fio.h"

static inline uint16_t sgio_get_be16(uint8_t *buf)
{
	return be16_to_cpu(*((uint16_t *) buf));
}

static inline uint32_t sgio_get_be32(uint8_t *buf)
{
	return be32_to_cpu(*((uint32_t *) buf));
}

static inline uint64_t sgio_get_be64(uint8_t *buf)
{
	return be64_to_cpu(*((uint64_t *) buf));
}

static inline void sgio_set_be16(uint16_t val, uint8_t *buf)
{
	uint16_t t = cpu_to_be16(val);

	memcpy(buf, &t, sizeof(uint16_t));
}

static inline void sgio_set_be32(uint32_t val, uint8_t *buf)
{
	uint32_t t = cpu_to_be32(val);

	memcpy(buf, &t, sizeof(uint32_t));
}

static inline void sgio_set_be64(uint64_t val, uint8_t *buf)
{
	uint64_t t = cpu_to_be64(val);

	memcpy(buf, &t, sizeof(uint64_t));
}

#endif /* FIO_SG_H */
