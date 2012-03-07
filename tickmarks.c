#include <stdio.h>
#include <math.h>
#include <malloc.h>

/* 
 * adapted from Paul Heckbert's algorithm on p 657-659 of
 * Andrew S. Glassner's book, "Graphics Gems"
 * ISBN 0-12-286166-3
 *
 */

#include "tickmarks.h"

#define MAX(a, b) (((a) < (b)) ? (b) : (a))

static double nicenum(double x, int round)
{
	int exp;	/* exponent of x */
	double f;	/* fractional part of x */

	exp = floor(log10(x));
	f = x / pow(10.0, exp);
	if (round) {
		if (f < 1.5)
			return 1.0 * pow(10.0, exp);
		if (f < 3.0)
			return 2.0 * pow(10.0, exp);
		if (f < 7.0)
			return 5.0 * pow(10.0, exp);
		return 10.0 * pow(10.0, exp);
	}
	if (f <= 1.0)
		return 1.0 * pow(10.0, exp);
	if (f <= 2.0)
		return 2.0 * pow(10.0, exp);
	if (f <= 5.0)
		return 5.0 * pow(10.0, exp);
	return 10.0 * pow(10.0, exp);
}

int calc_tickmarks(double min, double max, int nticks, struct tickmark **tm)
{
	char str[100];
	int nfrac;
	double d;	/* tick mark spacing */
	double graphmin, graphmax;	/* graph range min and max */
	double range, x;
	int count, i;

	/* we expect min != max */
	range = nicenum(max - min, 0);
	d = nicenum(range / (nticks - 1), 1);
	graphmin = floor(min / d) * d;
	graphmax = ceil(max / d) * d;
	nfrac = MAX(-floor(log10(d)), 0);
	snprintf(str, sizeof(str)-1, "%%.%df", nfrac);

	count = ((graphmax + 0.5 * d) - graphmin) / d + 1;
	*tm = malloc(sizeof(**tm) * count);

	i = 0;
	for (x = graphmin; x < graphmax + 0.5 * d; x += d) {
		(*tm)[i].value = x;
		sprintf((*tm)[i].string, str, x);
		i++;
	}
	return i;
}

#if 0

static void test_range(double x, double y)
{
	int nticks, i;

	struct tickmark *tm = NULL;
	printf("Testing range %g - %g\n", x, y);
	nticks = calc_tickmarks(x, y, 10, &tm);

	for (i = 0; i < nticks; i++) {
		printf("   (%s) %g\n", tm[i].string, tm[i].value);
	}
	printf("\n\n");
	free(tm);
}

int main(int argc, char *argv[])
{
	test_range(0.0005, 0.008);	
	test_range(0.5, 0.8);	
	test_range(5.5, 8.8);	
	test_range(50.5, 80.8);	
	test_range(-20, 20.8);	
	test_range(-30, 700.8);	
}
#endif
