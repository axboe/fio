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
 * @units: select units - N2S_* macros defined in num2str.h
 * @returns a malloc'd buffer containing "number[<unit prefix>][<units>]"
 */
char *num2str(uint64_t num, int maxlen, int base, int pow2, int units)
{
	const char *sistr[] = { "", "k", "M", "G", "T", "P" };
	const char *iecstr[] = { "", "Ki", "Mi", "Gi", "Ti", "Pi" };
	const char **unitprefix;
	const char *unitstr[] = { "", "/s", "B", "bit", "B/s", "bit/s" };
	const unsigned int thousand[] = { 1000, 1024 };
	unsigned int modulo;
	int unit_index = 0, post_index, carry = 0;
	char tmp[32], fmt[32];
	char *buf;

	compiletime_assert(sizeof(sistr) == sizeof(iecstr), "unit prefix arrays must be identical sizes");

	buf = malloc(128);
	if (!buf)
		return NULL;

	if (pow2)
		unitprefix = iecstr;
	else
		unitprefix = sistr;

	for (post_index = 0; base > 1; post_index++)
		base /= thousand[!!pow2];

	switch (units) {
	case N2S_PERSEC:
		unit_index = 1;
		break;
	case N2S_BYTE:
		unit_index = 2;
		break;
	case N2S_BIT:
		unit_index = 3;
		num *= 8;
		break;
	case N2S_BYTEPERSEC:
		unit_index = 4;
		break;
	case N2S_BITPERSEC:
		unit_index = 5;
		num *= 8;
		break;
	}

	/*
	 * Divide by K/Ki until string length of num <= maxlen.
	 */
	modulo = -1U;
	while (post_index < sizeof(sistr)) {
		sprintf(tmp, "%llu", (unsigned long long) num);
		if (strlen(tmp) <= maxlen)
			break;

		modulo = num % thousand[!!pow2];
		num /= thousand[!!pow2];
		carry = modulo >= thousand[!!pow2] / 2;
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
			unitprefix[post_index], unitstr[unit_index]);
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
	assert(modulo < thousand[!!pow2]);
	sprintf(fmt, "%%.%df", (int)(maxlen - strlen(tmp) - 1));
	sprintf(tmp, fmt, (double)modulo / (double)thousand[!!pow2]);

	sprintf(buf, "%llu.%s%s%s", (unsigned long long) num, &tmp[2],
			unitprefix[post_index], unitstr[unit_index]);
	return buf;
}
