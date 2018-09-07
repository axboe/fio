#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../compiler/compiler.h"
#include "num2str.h"

#define ARRAY_SIZE(x)    (sizeof((x)) / (sizeof((x)[0])))

/**
 * num2str() - Cheesy number->string conversion, complete with carry rounding error.
 * @num: quantity (e.g., number of blocks, bytes or bits)
 * @maxlen: max number of digits in the output string (not counting prefix and units, but counting .)
 * @base: multiplier for num (e.g., if num represents Ki, use 1024)
 * @pow2: select unit prefix - 0=power-of-10 decimal SI, nonzero=power-of-2 binary IEC
 * @units: select units - N2S_* constants defined in num2str.h
 * @returns a malloc'd buffer containing "number[<unit prefix>][<units>]"
 */
char *num2str(uint64_t num, int maxlen, int base, int pow2, enum n2s_unit units)
{
	const char *sistr[] = { "", "k", "M", "G", "T", "P" };
	const char *iecstr[] = { "", "Ki", "Mi", "Gi", "Ti", "Pi" };
	const char **unitprefix;
	static const char *const unitstr[] = {
		[N2S_NONE]	= "",
		[N2S_PERSEC]	= "/s",
		[N2S_BYTE]	= "B",
		[N2S_BIT]	= "bit",
		[N2S_BYTEPERSEC]= "B/s",
		[N2S_BITPERSEC]	= "bit/s"
	};
	const unsigned int thousand = pow2 ? 1024 : 1000;
	unsigned int modulo;
	int post_index, carry = 0;
	char tmp[32], fmt[32];
	char *buf;

	compiletime_assert(sizeof(sistr) == sizeof(iecstr), "unit prefix arrays must be identical sizes");
	assert(units < ARRAY_SIZE(unitstr));

	buf = malloc(128);
	if (!buf)
		return NULL;

	if (pow2)
		unitprefix = iecstr;
	else
		unitprefix = sistr;

	for (post_index = 0; base > 1; post_index++)
		base /= thousand;

	switch (units) {
	case N2S_NONE:
		break;
	case N2S_PERSEC:
		break;
	case N2S_BYTE:
		break;
	case N2S_BIT:
		num *= 8;
		break;
	case N2S_BYTEPERSEC:
		break;
	case N2S_BITPERSEC:
		num *= 8;
		break;
	}

	/*
	 * Divide by K/Ki until string length of num <= maxlen.
	 */
	modulo = -1U;
	while (post_index < ARRAY_SIZE(sistr)) {
		sprintf(tmp, "%llu", (unsigned long long) num);
		if (strlen(tmp) <= maxlen)
			break;

		modulo = num % thousand;
		num /= thousand;
		carry = modulo >= thousand / 2;
		post_index++;
	}

	/*
	 * If no modulo, then we're done.
	 */
	if (modulo == -1U) {
done:
		if (post_index >= ARRAY_SIZE(sistr))
			post_index = 0;

		sprintf(buf, "%llu%s%s", (unsigned long long) num,
			unitprefix[post_index], unitstr[units]);
		return buf;
	}

	/*
	 * If no room for decimals, then we're done.
	 */
	sprintf(tmp, "%llu", (unsigned long long) num);
	if ((int)(maxlen - strlen(tmp)) <= 1) {
		if (carry)
			num++;
		goto done;
	}

	/*
	 * Fill in everything and return the result.
	 */
	assert(maxlen - strlen(tmp) - 1 > 0);
	assert(modulo < thousand);
	sprintf(fmt, "%%.%df", (int)(maxlen - strlen(tmp) - 1));
	sprintf(tmp, fmt, (double)modulo / (double)thousand);

	sprintf(buf, "%llu.%s%s%s", (unsigned long long) num, &tmp[2],
			unitprefix[post_index], unitstr[units]);
	return buf;
}
