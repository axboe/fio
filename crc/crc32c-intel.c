#include "crc32c.h"

/*
 * Based on a posting to lkml by Austin Zhang <austin.zhang@intel.com>
 *
 * Using hardware provided CRC32 instruction to accelerate the CRC32 disposal.
 * CRC32C polynomial:0x1EDC6F41(BE)/0x82F63B78(LE)
 * CRC32 is a new instruction in Intel SSE4.2, the reference can be found at:
 * http://www.intel.com/products/processor/manuals/
 * Intel(R) 64 and IA-32 Architectures Software Developer's Manual
 * Volume 2A: Instruction Set Reference, A-M
 */

bool crc32c_intel_available = false;

#ifdef ARCH_HAVE_SSE4_2

#if BITS_PER_LONG == 64
#define REX_PRE "0x48, "
#define SCALE_F 8
#else
#define REX_PRE
#define SCALE_F 4
#endif

static bool crc32c_probed;

static uint32_t crc32c_intel_le_hw_byte(uint32_t crc, unsigned char const *data,
					unsigned long length)
{
	while (length--) {
		__asm__ __volatile__(
			".byte 0xf2, 0xf, 0x38, 0xf0, 0xf1"
			:"=S"(crc)
			:"0"(crc), "c"(*data)
		);
		data++;
	}

	return crc;
}

/*
 * Steps through buffer one byte at at time, calculates reflected 
 * crc using table.
 */
uint32_t crc32c_intel(unsigned char const *data, unsigned long length)
{
	unsigned int iquotient = length / SCALE_F;
	unsigned int iremainder = length % SCALE_F;
#if BITS_PER_LONG == 64
	uint64_t *ptmp = (uint64_t *) data;
#else
	uint32_t *ptmp = (uint32_t *) data;
#endif
	uint32_t crc = ~0;

	while (iquotient--) {
		__asm__ __volatile__(
			".byte 0xf2, " REX_PRE "0xf, 0x38, 0xf1, 0xf1;"
			:"=S"(crc)
			:"0"(crc), "c"(*ptmp)
		);
		ptmp++;
	}

	if (iremainder)
		crc = crc32c_intel_le_hw_byte(crc, (unsigned char *)ptmp,
				 iremainder);

	return crc;
}

void crc32c_intel_probe(void)
{
	if (!crc32c_probed) {
		unsigned int eax, ebx, ecx = 0, edx;

		eax = 1;

		do_cpuid(&eax, &ebx, &ecx, &edx);
		crc32c_intel_available = (ecx & (1 << 20)) != 0;
		crc32c_probed = true;
	}
}

#endif /* ARCH_HAVE_SSE4_2 */
