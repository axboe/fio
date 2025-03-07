#!/usr/bin/env python3
# Note: this script is python2 and python 3 compatible.
#
# fiologparser.py
#
# This tool lets you parse multiple fio log files and look at interaval
# statistics even when samples are non-uniform.  For instance:
#
# fiologparser.py -s *bw*
#
# to see per-interval sums for all bandwidth logs or:
#
# fiologparser.py -a *clat*
#
# to see per-interval average completion latency.

from __future__ import absolute_import
from __future__ import print_function
import argparse
import math
from functools import reduce

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interval', required=False, type=int, default=1000, help='interval of time in seconds.')
    parser.add_argument('-d', '--divisor', required=False, type=int, default=1, help='divide the results by this value.')
    parser.add_argument('-f', '--full', dest='full', action='store_true', default=False, help='print full output.')
    parser.add_argument('-A', '--all', dest='allstats', action='store_true', default=False, 
                        help='print all stats for each interval.')
    parser.add_argument('-a', '--average', dest='average', action='store_true', default=False, help='print the average for each interval.')
    parser.add_argument('-s', '--sum', dest='sum', action='store_true', default=False, help='print the sum for each interval.')
    parser.add_argument("FILE", help="collectl log output files to parse", nargs="+")
    args = parser.parse_args()

    return args

def get_ftime(series):
    ftime = 0
    for ts in series:
        if ftime == 0 or ts.last.end < ftime:
            ftime = ts.last.end
    return ftime

def print_full(ctx, series):
    ftime = get_ftime(series)
    start = 0 
    end = ctx.interval

    while (start < ftime):
        end = ftime if ftime < end else end
        results = [ts.get_value(start, end) for ts in series]
        print("%s, %s" % (end, ', '.join(["%0.3f" % i for i in results])))
        start += ctx.interval
        end += ctx.interval

def print_sums(ctx, series):
    ftime = get_ftime(series)
    start = 0
    end = ctx.interval

    while (start < ftime):
        end = ftime if ftime < end else end
        results = [ts.get_value(start, end) for ts in series]
        print("%s, %0.3f" % (end, sum(results)))
        start += ctx.interval
        end += ctx.interval

def print_averages(ctx, series):
    ftime = get_ftime(series)
    start = 0
    end = ctx.interval

    while (start < ftime):
        end = ftime if ftime < end else end
        results = [ts.get_value(start, end) for ts in series]
        print("%s, %0.3f" % (end, float(sum(results))/len(results)))
        start += ctx.interval
        end += ctx.interval

# FIXME: this routine is computationally inefficient
# and has O(N^2) behavior
# it would be better to make one pass through samples
# to segment them into a series of time intervals, and
# then compute stats on each time interval instead.
# to debug this routine, use
#   # sort -n -t ',' -k 2 small.log
# on your input.

def my_extend( vlist, val ):
    vlist.extend(val)
    return vlist

array_collapser = lambda vlist, val:  my_extend(vlist, val) 

def print_all_stats(ctx, series):
    ftime = get_ftime(series)
    start = 0 
    end = ctx.interval
    print('start-time, samples, min, avg, median, 90%, 95%, 99%, max')
    while (start < ftime):  # for each time interval
        end = ftime if ftime < end else end
        sample_arrays = [ s.get_samples(start, end) for s in series ]
        samplevalue_arrays = []
        for sample_array in sample_arrays:
            samplevalue_arrays.append( 
                [ sample.value for sample in sample_array ] )
        # collapse list of lists of sample values into list of sample values
        samplevalues = reduce( array_collapser, samplevalue_arrays, [] )
        # compute all stats and print them
        mymin = min(samplevalues)
        myavg = sum(samplevalues) / float(len(samplevalues))
        mymedian = median(samplevalues)
        my90th = percentile(samplevalues, 0.90) 
        my95th = percentile(samplevalues, 0.95)
        my99th = percentile(samplevalues, 0.99)
        mymax = max(samplevalues)
        print( '%f, %d, %f, %f, %f, %f, %f, %f, %f' % (
            start, len(samplevalues), 
            mymin, myavg, mymedian, my90th, my95th, my99th, mymax))

        # advance to next interval
        start += ctx.interval
        end += ctx.interval

def median(values):
    s=sorted(values)
    return float(s[(len(s)-1)/2]+s[(len(s)/2)])/2

def percentile(values, p):
    s = sorted(values)
    k = (len(s)-1) * p
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return s[int(k)]
    return (s[int(f)] * (c-k)) + (s[int(c)] * (k-f))

def print_default(ctx, series):
    ftime = get_ftime(series)
    start = 0
    end = ctx.interval
    averages = []
    weights = []

    while (start < ftime):
        end = ftime if ftime < end else end
        results = [ts.get_value(start, end) for ts in series]
        averages.append(sum(results)) 
        weights.append(end-start)
        start += ctx.interval
        end += ctx.interval

    total = 0
    for i in range(0, len(averages)):
        total += averages[i]*weights[i]
    print('%0.3f' % (total/sum(weights)))
 
class TimeSeries(object):
    def __init__(self, ctx, fn):
        self.ctx = ctx
        self.last = None 
        self.samples = []
        self.read_data(fn)

    def read_data(self, fn):
        f = open(fn, 'r')
        p_time = 0
        for line in f:
            (time, value) = line.rstrip('\r\n').rsplit(', ')[:2]
            self.add_sample(p_time, int(time), int(value))
            p_time = int(time)
 
    def add_sample(self, start, end, value):
        sample = Sample(ctx, start, end, value)
        if not self.last or self.last.end < end:
            self.last = sample
        self.samples.append(sample)

    def get_samples(self, start, end):
        sample_list = []
        for s in self.samples:
            if s.start >= start and s.end <= end:
                sample_list.append(s)
        return sample_list

    def get_value(self, start, end):
        value = 0
        for sample in self.samples:
            value += sample.get_contribution(start, end)
        return value

class Sample(object):
    def __init__(self, ctx, start, end, value):
       self.ctx = ctx
       self.start = start
       self.end = end
       self.value = value

    def get_contribution(self, start, end):
       # short circuit if not within the bound
       if (end < self.start or start > self.end):
           return 0 

       sbound = self.start if start < self.start else start
       ebound = self.end if end > self.end else end
       ratio = float(ebound-sbound) / (end-start) 
       return self.value*ratio/ctx.divisor


if __name__ == '__main__':
    ctx = parse_args()
    series = []
    for fn in ctx.FILE:
       series.append(TimeSeries(ctx, fn)) 
    if ctx.sum:
        print_sums(ctx, series)
    elif ctx.average:
        print_averages(ctx, series)
    elif ctx.full:
        print_full(ctx, series)
    elif ctx.allstats:
        print_all_stats(ctx, series)
    else:
        print_default(ctx, series)
