#!/usr/bin/env python

# module to parse fio histogram log files, not using pandas
# runs in python v2 or v3
# to get help with the CLI: $ python fio-histo-log-pctiles.py -h
# this can be run standalone as a script but is callable
# assumes all threads run for same time duration
# assumes all threads are doing the same thing for the entire run

# percentiles:
#  0 - min latency
#  50 - median
#  100 - max latency

# TO-DO: 
#   separate read and write stats for randrw mixed workload
#   report average latency if needed
#   prove that it works (partially done with unit tests)

# to run unit tests, set UNITTEST environment variable to anything
# if you do this, don't pass normal CLI parameters to it
# otherwise it runs the CLI

import sys, os, math, copy, time
from copy import deepcopy
import argparse

unittest2_imported = True
try:
    import unittest2
except ImportError:
    unittest2_imported = False

msec_per_sec = 1000
nsec_per_usec = 1000
direction_read = 0
direction_write = 1

class FioHistoLogExc(Exception):
    pass

# if there is an error, print message, and exit with error status

def myabort(msg):
    print('ERROR: ' + msg)
    sys.exit(1)

# convert histogram log file into a list of
# (time_ms, direction, bsz, buckets) tuples where
# - time_ms is the time in msec at which the log record was written
# - direction is 0 (read) or 1 (write)
# - bsz is block size (not used)
# - buckets is a CSV list of counters that make up the histogram
# caller decides if the expected number of counters are present


def exception_suffix( record_num, pathname ):
    return 'in histogram record %d file %s' % (record_num+1, pathname)

# log file parser raises FioHistoLogExc exceptions
# it returns histogram buckets in whatever unit fio uses
# inputs:
#  logfn: pathname to histogram log file
#  buckets_per_interval - how many histogram buckets to expect
#  log_hist_msec - if not None, expected time interval between histogram records

def parse_hist_file(logfn, buckets_per_interval, log_hist_msec):
    previous_ts_ms_read = -1
    previous_ts_ms_write = -1
 
    with open(logfn, 'r') as f:
        records = [ l.strip() for l in f.readlines() ]
    intervals = []
    last_time_ms = -1
    last_direction = -1
    for k, r in enumerate(records):
        if r == '':
            continue
        tokens = r.split(',')
        try:
            int_tokens = [ int(t) for t in tokens ]
        except ValueError as e:
            raise FioHistoLogExc('non-integer value %s' % exception_suffix(k+1, logfn))

        neg_ints = list(filter( lambda tk : tk < 0, int_tokens ))
        if len(neg_ints) > 0:
            raise FioHistoLogExc('negative integer value %s' % exception_suffix(k+1, logfn))

        if len(int_tokens) < 3:
            raise FioHistoLogExc('too few numbers %s' % exception_suffix(k+1, logfn))

        direction = int_tokens[1]
        if direction != direction_read and direction != direction_write:
            raise FioHistoLogExc('invalid I/O direction %s' % exception_suffix(k+1, logfn))

        time_ms = int_tokens[0]
        if direction == direction_read:
            if time_ms < previous_ts_ms_read:
                raise FioHistoLogExc('read timestamp in column 1 decreased %s' % exception_suffix(k+1, logfn))
            previous_ts_ms_read = time_ms
        elif direction == direction_write:
            if time_ms < previous_ts_ms_write:
                raise FioHistoLogExc('write timestamp in column 1 decreased %s' % exception_suffix(k+1, logfn))
            previous_ts_ms_write = time_ms

        bsz = int_tokens[2]
        if bsz > (1 << 24):
            raise FioHistoLogExc('block size too large %s' % exception_suffix(k+1, logfn))

        buckets = int_tokens[3:]
        if len(buckets) != buckets_per_interval:
            raise FioHistoLogExc('%d buckets per interval but %d expected in %s' % 
                    (len(buckets), buckets_per_interval, exception_suffix(k+1, logfn)))

        # hack to filter out records with the same timestamp
        # we should not have to do this if fio logs histogram records correctly

        if time_ms == last_time_ms and direction == last_direction:
            continue
        last_time_ms = time_ms
        last_direction = direction

        intervals.append((time_ms, direction, bsz, buckets))
    if len(intervals) == 0:
        raise FioHistoLogExc('no records in %s' % logfn)
    (first_timestamp, _, _, _) = intervals[0]
    if first_timestamp < 1000000:
        start_time = 0    # assume log_unix_epoch = 0
    elif log_hist_msec != None:
        start_time = first_timestamp - log_hist_msec
    elif len(intervals) > 1:
        (second_timestamp, _, _, _) = intervals[1]
        start_time = first_timestamp - (second_timestamp - first_timestamp)
    else:
        raise FioHistoLogExc('no way to estimate test start time')
    (end_timestamp, _, _, _) = intervals[-1]

    return (intervals, start_time, end_timestamp)


# compute time range for each bucket index in histogram record
# see comments in https://github.com/axboe/fio/blob/master/stat.h
# for description of bucket groups and buckets
# fio v3 bucket ranges are in nanosec (since response times are measured in nanosec)
# but we convert fio v3 nanosecs to floating-point microseconds

def time_ranges(groups, counters_per_group, fio_version=3):
    bucket_width = 1
    bucket_base = 0
    bucket_intervals = []
    for g in range(0, groups):
        for b in range(0, counters_per_group):
            rmin = float(bucket_base)
            rmax = rmin + bucket_width
            if fio_version == 3:
                rmin /= nsec_per_usec
                rmax /= nsec_per_usec
            bucket_intervals.append( [rmin, rmax] )
            bucket_base += bucket_width
        if g != 0:
            bucket_width *= 2
    return bucket_intervals


# compute number of time quantum intervals in the test

def get_time_intervals(time_quantum, min_timestamp_ms, max_timestamp_ms):
    # round down to nearest second
    max_timestamp = max_timestamp_ms // msec_per_sec
    min_timestamp = min_timestamp_ms // msec_per_sec
    # round up to nearest whole multiple of time_quantum
    time_interval_count = ((max_timestamp - min_timestamp) + time_quantum) // time_quantum
    end_time = min_timestamp + (time_interval_count * time_quantum)
    return (end_time, time_interval_count)

# align raw histogram log data to time quantum so 
# we can then combine histograms from different threads with addition
# for randrw workload we count both reads and writes in same output bucket
# but we separate reads and writes for purposes of calculating
# end time for histogram record.
# this requires us to weight a raw histogram bucket by the 
# fraction of time quantum that the bucket overlaps the current
# time quantum interval
# for example, if we have a bucket with 515 samples for time interval
# [ 1010, 2014 ] msec since start of test, and time quantum is 1 sec, then
# for time quantum interval [ 1000, 2000 ] msec, the overlap is
# (2000 - 1010) / (2000 - 1000) = 0.99
# so the contribution of this bucket to this time quantum is
# 515 x 0.99 = 509.85

def align_histo_log(raw_histogram_log, time_quantum, bucket_count, min_timestamp_ms, max_timestamp_ms):

    # slice up test time int intervals of time_quantum seconds

    (end_time, time_interval_count) = get_time_intervals(time_quantum, min_timestamp_ms, max_timestamp_ms)
    time_qtm_ms = time_quantum * msec_per_sec
    end_time_ms = end_time * msec_per_sec
    aligned_intervals = []
    for j in range(0, time_interval_count):
        aligned_intervals.append((
            min_timestamp_ms + (j * time_qtm_ms),
            [ 0.0 for j in range(0, bucket_count) ] ))

    log_record_count = len(raw_histogram_log)
    for k, record in enumerate(raw_histogram_log):

        # find next record with same direction to get end-time
        # have to avoid going past end of array
        # for fio randrw workload, 
        # we have read and write records on same time interval
        # sometimes read and write records are in opposite order
        # assertion checks that next read/write record 
        # can be separated by at most 2 other records

        (time_msec, direction, sz, interval_buckets) = record
        if k+1 < log_record_count:
            (time_msec_end, direction2, _, _) = raw_histogram_log[k+1]
            if direction2 != direction:
                if k+2 < log_record_count:
                    (time_msec_end, direction2, _, _) = raw_histogram_log[k+2]
                    if direction2 != direction:
                        if k+3 < log_record_count:
                            (time_msec_end, direction2, _, _) = raw_histogram_log[k+3]
                            assert direction2 == direction
                        else:
                            time_msec_end = end_time_ms
                else:
                    time_msec_end = end_time_ms
        else:
            time_msec_end = end_time_ms

        # calculate first quantum that overlaps this histogram record 

        offset_from_min_ts = time_msec - min_timestamp_ms
        qtm_start_ms = min_timestamp_ms + (offset_from_min_ts // time_qtm_ms) * time_qtm_ms
        qtm_end_ms = min_timestamp_ms + ((offset_from_min_ts + time_qtm_ms) // time_qtm_ms) * time_qtm_ms
        qtm_index = offset_from_min_ts // time_qtm_ms

        # for each quantum that overlaps this histogram record's time interval

        while qtm_start_ms < time_msec_end:  # while quantum overlaps record

            # some histogram logs may be longer than others

            if len(aligned_intervals) <= qtm_index:
                break

            # calculate fraction of time that this quantum 
            # overlaps histogram record's time interval
            
            overlap_start = max(qtm_start_ms, time_msec)
            overlap_end = min(qtm_end_ms, time_msec_end)
            weight = float(overlap_end - overlap_start)
            weight /= (time_msec_end - time_msec)
            (_,aligned_histogram) = aligned_intervals[qtm_index]
            for bx, b in enumerate(interval_buckets):
                weighted_bucket = weight * b
                aligned_histogram[bx] += weighted_bucket

            # advance to the next time quantum

            qtm_start_ms += time_qtm_ms
            qtm_end_ms += time_qtm_ms
            qtm_index += 1

    return aligned_intervals

# add histogram in "source" to histogram in "target"
# it is assumed that the 2 histograms are precisely time-aligned

def add_to_histo_from( target, source ):
    for b in range(0, len(source)):
        target[b] += source[b]


# calculate total samples in the histogram buckets

def get_samples(buckets):
    return reduce( lambda x,y: x + y, buckets)


# compute percentiles
# inputs:
#   buckets: histogram bucket array 
#   wanted: list of floating-pt percentiles to calculate
#   time_ranges: [tmin,tmax) time interval for each bucket
# returns None if no I/O reported.
# otherwise we would be dividing by zero
# think of buckets as probability distribution function
# and this loop is integrating to get cumulative distribution function

def get_pctiles(buckets, wanted, time_ranges):

    # get total of IO requests done
    total_ios = 0
    for io_count in buckets:
        total_ios += io_count

    # don't return percentiles if no I/O was done during interval
    if total_ios == 0.0:
        return None

    pctile_count = len(wanted)

    # results returned as dictionary keyed by percentile
    pctile_result = {}

    # index of next percentile in list
    pctile_index = 0

    # next percentile
    next_pctile = wanted[pctile_index]

    # no one is interested in percentiles bigger than this but not 100.0
    # this prevents floating-point error from preventing loop exit
    almost_100 = 99.9999

    # pct is the percentile corresponding to 
    # all I/O requests up through bucket b
    pct = 0.0
    total_so_far = 0
    for b, io_count in enumerate(buckets):
        if io_count == 0:
            continue
        total_so_far += io_count
        # last_pct_lt is the percentile corresponding to 
        # all I/O requests up to, but not including, bucket b
        last_pct = pct
        pct = 100.0 * float(total_so_far) / total_ios
        # a single bucket could satisfy multiple pctiles
        # so this must be a while loop
        # for 100-percentile (max latency) case, no bucket exceeds it 
        # so we must stop there.
        while ((next_pctile == 100.0 and pct >= almost_100) or
               (next_pctile < 100.0  and pct > next_pctile)):
            # interpolate between min and max time for bucket time interval
            # we keep the time_ranges access inside this loop, 
            # even though it could be above the loop,
            # because in many cases we will not be even entering 
            # the loop so we optimize out these accesses
            range_max_time = time_ranges[b][1]
            range_min_time = time_ranges[b][0]
            offset_frac = (next_pctile - last_pct)/(pct - last_pct)
            interpolation = range_min_time + (offset_frac*(range_max_time - range_min_time))
            pctile_result[next_pctile] = interpolation
            pctile_index += 1
            if pctile_index == pctile_count:
                break
            next_pctile = wanted[pctile_index]
        if pctile_index == pctile_count:
            break
    assert pctile_index == pctile_count
    return pctile_result


# this is really the main program

def compute_percentiles_from_logs():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fio-version", dest="fio_version", 
        default="3", choices=[2,3], type=int, 
        help="fio version (default=3)")
    parser.add_argument("--bucket-groups", dest="bucket_groups", default="29", type=int, 
        help="fio histogram bucket groups (default=29)")
    parser.add_argument("--bucket-bits", dest="bucket_bits", 
        default="6", type=int, 
        help="fio histogram buckets-per-group bits (default=6 means 64 buckets/group)")
    parser.add_argument("--percentiles", dest="pctiles_wanted", 
        default=[ 0., 50., 95., 99., 100.], type=float, nargs='+',
        help="fio histogram buckets-per-group bits (default=6 means 64 buckets/group)")
    parser.add_argument("--time-quantum", dest="time_quantum", 
        default="1", type=int,
        help="time quantum in seconds (default=1)")
    parser.add_argument("--log-hist-msec", dest="log_hist_msec", 
        type=int, default=None,
        help="log_hist_msec value in fio job file")
    parser.add_argument("--output-unit", dest="output_unit", 
        default="usec", type=str,
        help="Latency percentile output unit: msec|usec|nsec (default usec)")
    parser.add_argument("file_list", nargs='+', 
        help='list of files, preceded by " -- " if necessary')
    args = parser.parse_args()

    # default changes based on fio version
    if args.fio_version == 2:
        args.bucket_groups = 19

    # print parameters

    print('fio version = %d' % args.fio_version)
    print('bucket groups = %d' % args.bucket_groups)
    print('bucket bits = %d' % args.bucket_bits)
    print('time quantum = %d sec' % args.time_quantum)
    print('percentiles = %s' % ','.join([ str(p) for p in args.pctiles_wanted ]))
    buckets_per_group = 1 << args.bucket_bits
    print('buckets per group = %d' % buckets_per_group)
    buckets_per_interval = buckets_per_group * args.bucket_groups
    print('buckets per interval = %d ' % buckets_per_interval)
    bucket_index_range = range(0, buckets_per_interval)
    if args.log_hist_msec != None:
        print('log_hist_msec = %d' % args.log_hist_msec)
    if args.time_quantum == 0:
        print('ERROR: time-quantum must be a positive number of seconds')
    print('output unit = ' + args.output_unit)
    if args.output_unit == 'msec':
        time_divisor = float(msec_per_sec)
    elif args.output_unit == 'usec':
        time_divisor = 1.0

    # construct template for each histogram bucket array with buckets all zeroes
    # we just copy this for each new histogram

    zeroed_buckets = [ 0.0 for r in bucket_index_range ]

    # calculate response time interval associated with each histogram bucket

    bucket_times = time_ranges(args.bucket_groups, buckets_per_group, fio_version=args.fio_version)

    # parse the histogram logs
    # assumption: each bucket has a monotonically increasing time
    # assumption: time ranges do not overlap for a single thread's records
    # (exception: if randrw workload, then there is a read and a write 
    # record for the same time interval)

    test_start_time = 0
    test_end_time = 1.0e18
    hist_files = {}
    for fn in args.file_list:
        try:
            (hist_files[fn], log_start_time, log_end_time)  = parse_hist_file(fn, buckets_per_interval, args.log_hist_msec)
        except FioHistoLogExc as e:
            myabort(str(e))
        # we consider the test started when all threads have started logging
        test_start_time = max(test_start_time, log_start_time)
        # we consider the test over when one of the logs has ended
        test_end_time = min(test_end_time, log_end_time)

    if test_start_time >= test_end_time:
        raise FioHistoLogExc('no time interval when all threads logs overlapped')
    if test_start_time > 0:
        print('all threads running as of unix epoch time %d = %s' % (
               test_start_time/float(msec_per_sec), 
               time.ctime(test_start_time/1000.0)))

    (end_time, time_interval_count) = get_time_intervals(args.time_quantum, test_start_time, test_end_time)
    all_threads_histograms = [ ((j*args.time_quantum*msec_per_sec), deepcopy(zeroed_buckets))
                               for j in range(0, time_interval_count) ]

    for logfn in hist_files.keys():
        aligned_per_thread = align_histo_log(hist_files[logfn], 
                                             args.time_quantum, 
                                             buckets_per_interval, 
                                             test_start_time,
                                             test_end_time)
        for t in range(0, time_interval_count):
            (_, all_threads_histo_t) = all_threads_histograms[t]
            (_, log_histo_t) = aligned_per_thread[t]
            add_to_histo_from( all_threads_histo_t, log_histo_t )

    # calculate percentiles across aggregate histogram for all threads
    # print CSV header just like fiologparser_hist does

    header = 'msec-since-start, samples, '
    for p in args.pctiles_wanted:
        if p == 0.:
            next_pctile_header = 'min'
        elif p == 100.:
            next_pctile_header = 'max'
        elif p == 50.:
            next_pctile_header = 'median'
        else:
            next_pctile_header = '%3.1f' % p
        header += '%s, ' % next_pctile_header

    print('time (millisec), percentiles in increasing order with values in ' + args.output_unit)
    print(header)

    for (t_msec, all_threads_histo_t) in all_threads_histograms:
        samples = get_samples(all_threads_histo_t)
        record = '%8d, %8d, ' % (t_msec, samples)
        pct = get_pctiles(all_threads_histo_t, args.pctiles_wanted, bucket_times)
        if not pct:
            for w in args.pctiles_wanted:
                record += ', '
        else:
            pct_keys = [ k for k in pct.keys() ]
            pct_values = [ str(pct[wanted]/time_divisor) for wanted in sorted(pct_keys) ]
            record += ', '.join(pct_values)
        print(record)



#end of MAIN PROGRAM


##### below are unit tests ##############

if unittest2_imported:
  import tempfile, shutil
  from os.path import join
  should_not_get_here = False

  class Test(unittest2.TestCase):
    tempdir = None

    # a little less typing please
    def A(self, boolean_val):
        self.assertTrue(boolean_val)

    # initialize unit test environment

    @classmethod
    def setUpClass(cls):
        d = tempfile.mkdtemp()
        Test.tempdir = d

    # remove anything left by unit test environment
    # unless user sets UNITTEST_LEAVE_FILES environment variable

    @classmethod
    def tearDownClass(cls):
        if not os.getenv("UNITTEST_LEAVE_FILES"):
            shutil.rmtree(cls.tempdir)

    def setUp(self):
        self.fn = join(Test.tempdir, self.id())

    def test_a_add_histos(self):
        a = [ 1.0, 2.0 ]
        b = [ 1.5, 2.5 ]
        add_to_histo_from( a, b )
        self.A(a == [2.5, 4.5])
        self.A(b == [1.5, 2.5])

    def test_b1_parse_log(self):
        with open(self.fn, 'w') as f:
            f.write('1234, 0, 4096, 1, 2, 3, 4\n')
            f.write('5678,1,16384,5,6,7,8 \n')
        (raw_histo_log, min_timestamp, max_timestamp) = parse_hist_file(self.fn, 4, None) # 4 buckets per interval
        # if not log_unix_epoch=1, then min_timestamp will always be set to zero
        self.A(len(raw_histo_log) == 2 and min_timestamp == 0 and max_timestamp == 5678)
        (time_ms, direction, bsz, histo) = raw_histo_log[0]
        self.A(time_ms == 1234 and direction == 0 and bsz == 4096 and histo == [ 1, 2, 3, 4 ])
        (time_ms, direction, bsz, histo) = raw_histo_log[1]
        self.A(time_ms == 5678 and direction == 1 and bsz == 16384 and histo == [ 5, 6, 7, 8 ])

    def test_b2_parse_empty_log(self):
        with open(self.fn, 'w') as f:
            pass
        try:
            (raw_histo_log, _, _) = parse_hist_file(self.fn, 4, None)
            self.A(should_not_get_here)
        except FioHistoLogExc as e:
            self.A(str(e).startswith('no records'))

    def test_b3_parse_empty_records(self):
        with open(self.fn, 'w') as f:
            f.write('\n')
            f.write('1234, 0, 4096, 1, 2, 3, 4\n')
            f.write('5678,1,16384,5,6,7,8 \n')
            f.write('\n')
        (raw_histo_log, _, max_timestamp_ms) = parse_hist_file(self.fn, 4, None)
        self.A(len(raw_histo_log) == 2 and max_timestamp_ms == 5678)
        (time_ms, direction, bsz, histo) = raw_histo_log[0]
        self.A(time_ms == 1234 and direction == 0 and bsz == 4096 and histo == [ 1, 2, 3, 4 ])
        (time_ms, direction, bsz, histo) = raw_histo_log[1]
        self.A(time_ms == 5678 and direction == 1 and bsz == 16384 and histo == [ 5, 6, 7, 8 ])

    def test_b4_parse_non_int(self):
        with open(self.fn, 'w') as f:
            f.write('12, 0, 4096, 1a, 2, 3, 4\n')
        try:
            (raw_histo_log, _, _) = parse_hist_file(self.fn, 4, None)
            self.A(False)
        except FioHistoLogExc as e:
            self.A(str(e).startswith('non-integer'))

    def test_b5_parse_neg_int(self):
        with open(self.fn, 'w') as f:
            f.write('-12, 0, 4096, 1, 2, 3, 4\n')
        try:
            (raw_histo_log, _, _) = parse_hist_file(self.fn, 4, None)
            self.A(False)
        except FioHistoLogExc as e:
            self.A(str(e).startswith('negative integer'))

    def test_b6_parse_too_few_int(self):
        with open(self.fn, 'w') as f:
            f.write('0, 0\n')
        try:
            (raw_histo_log, _, _) = parse_hist_file(self.fn, 4, None)
            self.A(False)
        except FioHistoLogExc as e:
            self.A(str(e).startswith('too few numbers'))

    def test_b7_parse_invalid_direction(self):
        with open(self.fn, 'w') as f:
            f.write('100, 2, 4096, 1, 2, 3, 4\n')
        try:
            (raw_histo_log, _, _) = parse_hist_file(self.fn, 4, None)
            self.A(False)
        except FioHistoLogExc as e:
            self.A(str(e).startswith('invalid I/O direction'))

    def test_b8_parse_bsz_too_big(self):
        with open(self.fn+'_good', 'w') as f:
            f.write('100, 1, %d, 1, 2, 3, 4\n' % (1<<24))
        (raw_histo_log, _, _) = parse_hist_file(self.fn+'_good', 4, None)
        with open(self.fn+'_bad', 'w') as f:
            f.write('100, 1, 20000000, 1, 2, 3, 4\n')
        try:
            (raw_histo_log, _, _) = parse_hist_file(self.fn+'_bad', 4, None)
            self.A(False)
        except FioHistoLogExc as e:
            self.A(str(e).startswith('block size too large'))

    def test_b9_parse_wrong_bucket_count(self):
        with open(self.fn, 'w') as f:
            f.write('100, 1, %d, 1, 2, 3, 4, 5\n' % (1<<24))
        try:
            (raw_histo_log, _, _) = parse_hist_file(self.fn, 4, None)
            self.A(False)
        except FioHistoLogExc as e:
            self.A(str(e).__contains__('buckets per interval'))

    def test_c1_time_ranges(self):
        ranges = time_ranges(3, 2)  # fio_version defaults to 3
        expected_ranges = [ # fio_version 3 is in nanoseconds
                [0.000, 0.001], [0.001, 0.002],   # first group
                [0.002, 0.003], [0.003, 0.004],   # second group same width
                [0.004, 0.006], [0.006, 0.008]]   # subsequent groups double width
        self.A(ranges == expected_ranges)
        ranges = time_ranges(3, 2, fio_version=3)
        self.A(ranges == expected_ranges)
        ranges = time_ranges(3, 2, fio_version=2)
        expected_ranges_v2 = [ [ 1000.0 * min_or_max for min_or_max in time_range ] 
                               for time_range in expected_ranges ]
        self.A(ranges == expected_ranges_v2)
        # see fio V3 stat.h for why 29 groups and 2^6 buckets/group
        normal_ranges_v3 = time_ranges(29, 64)
        # for v3, bucket time intervals are measured in nanoseconds
        self.A(len(normal_ranges_v3) == 29 * 64 and normal_ranges_v3[-1][1] == 64*(1<<(29-1))/1000.0)
        normal_ranges_v2 = time_ranges(19, 64, fio_version=2)
        # for v2, bucket time intervals are measured in microseconds so we have fewer buckets
        self.A(len(normal_ranges_v2) == 19 * 64 and normal_ranges_v2[-1][1] == 64*(1<<(19-1)))

    def test_d1_align_histo_log_1_quantum(self):
        with open(self.fn, 'w') as f:
            f.write('100, 1, 4096, 1, 2, 3, 4')
        (raw_histo_log, min_timestamp_ms, max_timestamp_ms) = parse_hist_file(self.fn, 4, None)
        self.A(min_timestamp_ms == 0 and max_timestamp_ms == 100)
        aligned_log = align_histo_log(raw_histo_log, 5, 4, min_timestamp_ms, max_timestamp_ms)
        self.A(len(aligned_log) == 1)
        (time_ms0, h) = aligned_log[0]
        self.A(time_ms0 == 0 and h == [1., 2., 3., 4.])

    # handle case with log_unix_epoch=1 timestamps, 1-second time quantum
    # here both records will be separated into 2 aligned intervals

    def test_d1a_align_2rec_histo_log_epoch_1_quantum_1sec(self):
        with open(self.fn, 'w') as f:
            f.write('1536504002123, 1, 4096, 1, 2, 3, 4\n')
            f.write('1536504003123, 1, 4096, 4, 3, 2, 1\n')
        (raw_histo_log, min_timestamp_ms, max_timestamp_ms) = parse_hist_file(self.fn, 4, None)
        self.A(min_timestamp_ms == 1536504001123 and max_timestamp_ms == 1536504003123)
        aligned_log = align_histo_log(raw_histo_log, 1, 4, min_timestamp_ms, max_timestamp_ms)
        self.A(len(aligned_log) == 3)
        (time_ms0, h) = aligned_log[0]
        self.A(time_ms0 == 1536504001123 and h == [0., 0., 0., 0.])
        (time_ms1, h) = aligned_log[1]
        self.A(time_ms1 == 1536504002123 and h == [1., 2., 3., 4.])
        (time_ms2, h) = aligned_log[2]
        self.A(time_ms2 == 1536504003123 and h == [4., 3., 2., 1.])

    # handle case with log_unix_epoch=1 timestamps, 5-second time quantum
    # here both records will be merged into a single aligned time interval

    def test_d1b_align_2rec_histo_log_epoch_1_quantum_5sec(self):
        with open(self.fn, 'w') as f:
            f.write('1536504002123, 1, 4096, 1, 2, 3, 4\n')
            f.write('1536504003123, 1, 4096, 4, 3, 2, 1\n')
        (raw_histo_log, min_timestamp_ms, max_timestamp_ms) = parse_hist_file(self.fn, 4, None)
        self.A(min_timestamp_ms == 1536504001123 and max_timestamp_ms == 1536504003123)
        aligned_log = align_histo_log(raw_histo_log, 5, 4, min_timestamp_ms, max_timestamp_ms)
        self.A(len(aligned_log) == 1)
        (time_ms0, h) = aligned_log[0]
        self.A(time_ms0 == 1536504001123 and h == [5., 5., 5., 5.])

    # we need this to compare 2 lists of floating point numbers for equality
    # because of floating-point imprecision

    def compare_2_floats(self, x, y):
        if x == 0.0 or y == 0.0:
            return (x+y) < 0.0000001
        else:
            return (math.fabs(x-y)/x) < 0.00001
                
    def is_close(self, buckets, buckets_expected):
        if len(buckets) != len(buckets_expected):
            return False
        compare_buckets = lambda k: self.compare_2_floats(buckets[k], buckets_expected[k])
        indices_close = list(filter(compare_buckets, range(0, len(buckets))))
        return len(indices_close) == len(buckets)

    def test_d2_align_histo_log_2_quantum(self):
        with open(self.fn, 'w') as f:
            f.write('2000, 1, 4096, 1, 2, 3, 4\n')
            f.write('7000, 1, 4096, 1, 2, 3, 4\n')
        (raw_histo_log, min_timestamp_ms, max_timestamp_ms) = parse_hist_file(self.fn, 4, None)
        self.A(min_timestamp_ms == 0 and max_timestamp_ms == 7000)
        (_, _, _, raw_buckets1) = raw_histo_log[0]
        (_, _, _, raw_buckets2) = raw_histo_log[1]
        aligned_log = align_histo_log(raw_histo_log, 5, 4, min_timestamp_ms, max_timestamp_ms)
        self.A(len(aligned_log) == 2)
        (time_ms1, h1) = aligned_log[0]
        (time_ms2, h2) = aligned_log[1]
        # because first record is from time interval [2000, 7000]
        # we weight it according
        expect1 = [float(b) * 0.6 for b in raw_buckets1]
        expect2 = [float(b) * 0.4 for b in raw_buckets1]
        for e in range(0, len(expect2)):
            expect2[e] += raw_buckets2[e]
        self.A(time_ms1 == 0    and self.is_close(h1, expect1))
        self.A(time_ms2 == 5000 and self.is_close(h2, expect2))

    # what to expect if histogram buckets are all equal
    def test_e1_get_pctiles_flat_histo(self):
        with open(self.fn, 'w') as f:
            buckets = [ 100 for j in range(0, 128) ]
            f.write('9000, 1, 4096, %s\n' % ', '.join([str(b) for b in buckets]))
        (raw_histo_log, min_timestamp_ms, max_timestamp_ms) = parse_hist_file(self.fn, 128, None)
        self.A(min_timestamp_ms == 0 and max_timestamp_ms == 9000)
        aligned_log = align_histo_log(raw_histo_log, 5, 128, min_timestamp_ms, max_timestamp_ms)
        time_intervals = time_ranges(4, 32)
        # since buckets are all equal, then median is halfway through time_intervals
        # and max latency interval is at end of time_intervals
        self.A(time_intervals[64][1] == 0.066 and time_intervals[127][1] == 0.256)
        pctiles_wanted = [ 0, 50, 100 ]
        pct_vs_time = []
        for (time_ms, histo) in aligned_log:
            pct_vs_time.append(get_pctiles(histo, pctiles_wanted, time_intervals))
        self.A(pct_vs_time[0] == None)  # no I/O in this time interval
        expected_pctiles = { 0:0.000, 50:0.064, 100:0.256 }
        self.A(pct_vs_time[1] == expected_pctiles)

    # what to expect if just the highest histogram bucket is used
    def test_e2_get_pctiles_highest_pct(self):
        fio_v3_bucket_count = 29 * 64
        with open(self.fn, 'w') as f:
            # make a empty fio v3 histogram
            buckets = [ 0 for j in range(0, fio_v3_bucket_count) ]
            # add one I/O request to last bucket
            buckets[-1] = 1
            f.write('9000, 1, 4096, %s\n' % ', '.join([str(b) for b in buckets]))
        (raw_histo_log, min_timestamp_ms, max_timestamp_ms) = parse_hist_file(self.fn, fio_v3_bucket_count, None)
        self.A(min_timestamp_ms == 0 and max_timestamp_ms == 9000)
        aligned_log = align_histo_log(raw_histo_log, 5, fio_v3_bucket_count, min_timestamp_ms, max_timestamp_ms)
        (time_ms, histo) = aligned_log[1]
        time_intervals = time_ranges(29, 64)
        expected_pctiles = { 100.0:(64*(1<<28))/1000.0 }
        pct = get_pctiles( histo, [ 100.0 ], time_intervals )
        self.A(pct == expected_pctiles)

# we are using this module as a standalone program

if __name__ == '__main__':
    if os.getenv('UNITTEST'):
        if unittest2_imported:
            sys.exit(unittest2.main())
        else:
            raise Exception('you must install unittest2 module to run unit test')
    else:
        compute_percentiles_from_logs()

