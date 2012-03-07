#ifndef TICKMARKS_H
#define TICKMARKS_H

struct tickmark {
	double value;
	char string[20];
};

int calc_tickmarks(double min, double max, int nticks, struct tickmark **tm);

#endif
