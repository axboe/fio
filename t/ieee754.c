#include <stdio.h>
#include "../lib/ieee754.h"

static double values[] = { -17.23, 17.23, 123.4567, 98765.4321,
	3.14159265358979323, 0.0 };

int main(int argc, char *argv[])
{
	uint64_t i;
	double f, delta;
	int j, differences = 0;

	j = 0;
	do {
		i = fio_double_to_uint64(values[j]);
		f = fio_uint64_to_double(i);
		delta = values[j] - f;
		printf("%26.20lf -> %26.20lf, delta = %26.20lf\n", values[j],
			f, delta);
		if (f != values[j])
			differences++;
		j++;
	} while (values[j] != 0.0);

	return differences;
}
