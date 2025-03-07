#ifndef TICKMARKS_H
#define TICKMARKS_H

struct tickmark {
	double value;
	char string[20];
};

int calc_tickmarks(double min, double max, int nticks, struct tickmark **tm,
			int *power_of_ten, int use_KMG_symbols, int base_off);

#endif
