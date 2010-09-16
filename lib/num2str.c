#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*
 * Cheesy number->string conversion, complete with carry rounding error.
 */
char *num2str(unsigned long num, int maxlen, int base, int pow2)
{
	char postfix[] = { ' ', 'K', 'M', 'G', 'P', 'E' };
	unsigned int thousand[] = { 1000, 1024 };
	unsigned int modulo, decimals;
	int post_index;
	char tmp[32], fmt[8];
	char *buf;

	buf = malloc(128);

	for (post_index = 0; base > 1; post_index++)
		base /= thousand[!!pow2];

	modulo = -1U;
	while (post_index < sizeof(postfix)) {
		sprintf(tmp, "%lu", num);
		if (strlen(tmp) <= maxlen)
			break;

		modulo = num % thousand[!!pow2];
		num /= thousand[!!pow2];
		post_index++;
	}

	if (modulo == -1U) {
done:
		sprintf(buf, "%lu%c", num, postfix[post_index]);
		return buf;
	}

	sprintf(tmp, "%lu", num);
	decimals = maxlen - strlen(tmp);
	if (decimals <= 1)
		goto done;

	sprintf(fmt, "%%.%uu", decimals - 1);
	sprintf(tmp, fmt, modulo);
	sprintf(buf, "%lu.%s%c", num, tmp, postfix[post_index]);
	return buf;
}
