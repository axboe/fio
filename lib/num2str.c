#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../fio.h"

#define ARRAY_LENGTH(arr)	sizeof(arr) / sizeof((arr)[0])

/*
 * Cheesy number->string conversion, complete with carry rounding error.
 */
char *num2str(unsigned long num, int maxlen, int base, int pow2, int unit_base)
{
	const char *postfix[] = { "", "K", "M", "G", "P", "E" };
	const char *byte_postfix[] = { "", "B", "bit" };
	const unsigned int thousand[] = { 1000, 1024 };
	unsigned int modulo, decimals;
	int byte_post_index = 0, post_index, carry = 0;
	char tmp[32];
	char *buf;

	buf = malloc(128);

	for (post_index = 0; base > 1; post_index++)
		base /= thousand[!!pow2];

	switch (unit_base) {
	case 1:
		byte_post_index = 2;
		num *= 8;
		break;
	case 8:
		byte_post_index = 1;
		break;
	}

	modulo = -1U;
	while (post_index < sizeof(postfix)) {
		sprintf(tmp, "%lu", num);
		if (strlen(tmp) <= maxlen)
			break;

		modulo = num % thousand[!!pow2];
		num /= thousand[!!pow2];
		carry = modulo >= thousand[!!pow2] / 2;
		post_index++;
	}

	if (modulo == -1U) {
done:
		if (post_index >= ARRAY_LENGTH(postfix))
			post_index = 0;

		sprintf(buf, "%lu%s%s", num, postfix[post_index],
			byte_postfix[byte_post_index]);
		return buf;
	}

	sprintf(tmp, "%lu", num);
	decimals = maxlen - strlen(tmp);
	if (decimals <= 1) {
		if (carry)
			num++;
		goto done;
	}

	do {
		sprintf(tmp, "%u", modulo);
		if (strlen(tmp) <= decimals - 1)
			break;

		modulo = (modulo + 9) / 10;
	} while (1);

	sprintf(buf, "%lu.%u%s%s", num, modulo, postfix[post_index],
		byte_postfix[byte_post_index]);
	return buf;
}
