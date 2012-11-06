#include <stdio.h>
#include "../lib/ieee754.h"

static double values[] = { -17.23, 17.23, 123.4567, 98765.4321, 0.0 };

int main(int argc, char *argv[])
{
	uint64_t i;
	double f;
	int j;

	j = 0;
	do {
		i = fio_double_to_uint64(values[j]);
		f = fio_uint64_to_double(i);
		printf("%f -> %f\n", values[j], f);
		j++;
	} while (values[j] != 0.0);

	return 0;
}
