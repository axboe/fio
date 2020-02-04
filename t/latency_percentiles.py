#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2020 Western Digital Corporation or its affiliates.
#
"""
# latency_percentiles.py
#
# Test the code that produces latency percentiles
# This is mostly to test the code changes to allow reporting
# of slat, clat, and lat percentiles
#
# USAGE
# python3 latency-tests.py [-f fio-path] [-a artifact-root] [--debug]
#
#
# Test scenarios:
#
# - DONE json
#   unified rw reporting
#   compare with latency log
#   try various combinations of the ?lat_percentile options
#   null, aio
#   r, w, t
# - DONE json+
#   check presence of latency bins
#   if the json percentiles match those from the raw data
#   then the latency bin values and counts are probably ok
# - DONE terse
#   produce both terse, JSON output and confirm that they match
#   lat only; both lat and clat
# - DONE sync_lat
#   confirm that sync_lat data appears
# - MANUAL TESTING normal output:
#       null ioengine
#           enable all, but only clat and lat appear
#           enable subset of latency types
#           read, write, trim, unified
#       libaio ioengine
#           enable all latency types
#           enable subset of latency types
#           read, write, trim, unified
# ./fio/fio --name=test --randrepeat=0 --norandommap --time_based --runtime=2s --size=512M \
#       --ioengine=null --slat_percentiles=1 --clat_percentiles=1 --lat_percentiles=1
# echo confirm that clat and lat percentiles appear
# ./fio/fio --name=test --randrepeat=0 --norandommap --time_based --runtime=2s --size=512M \
#       --ioengine=null --slat_percentiles=0 --clat_percentiles=0 --lat_percentiles=1
# echo confirm that only lat percentiles appear
# ./fio/fio --name=test --randrepeat=0 --norandommap --time_based --runtime=2s --size=512M \
#       --ioengine=null --slat_percentiles=0 --clat_percentiles=1 --lat_percentiles=0
# echo confirm that only clat percentiles appear
# ./fio/fio --name=test --randrepeat=0 --norandommap --time_based --runtime=2s --size=512M \
#       --ioengine=libaio --slat_percentiles=1 --clat_percentiles=1 --lat_percentiles=1
# echo confirm that slat, clat, lat percentiles appear
# ./fio/fio --name=test --randrepeat=0 --norandommap --time_based --runtime=2s --size=512M \
#       --ioengine=libaio --slat_percentiles=0 --clat_percentiles=1 --lat_percentiles=1
# echo confirm that clat and lat percentiles appear
# ./fio/fio --name=test --randrepeat=0 --norandommap --time_based --runtime=2s --size=512M \
#       --ioengine=libaio -rw=randrw
# echo confirm that clat percentiles appear for reads and writes
# ./fio/fio --name=test --randrepeat=0 --norandommap --time_based --runtime=2s --size=512M \
#       --ioengine=libaio --slat_percentiles=1 --clat_percentiles=0 --lat_percentiles=0 --rw=randrw
# echo confirm that slat percentiles appear for both reads and writes
# ./fio/fio --name=test --randrepeat=0 --norandommap --time_based --runtime=2s --size=512M \
#       --ioengine=libaio --slat_percentiles=1 --clat_percentiles=1 --lat_percentiles=1 \
#       --rw=randrw --unified_rw_reporting=1
# echo confirm that slat, clat, and lat percentiles appear for 'mixed' IOs
#./fio/fio --name=test --randrepeat=0 --norandommap --time_based --runtime=2s --size=512M \
#       --ioengine=null --slat_percentiles=1 --clat_percentiles=1 --lat_percentiles=1 \
#       --rw=randrw --fsync=32
# echo confirm that fsync latencies appear
"""

import os
import csv
import sys
import json
import math
import time
import argparse
import platform
import subprocess
from pathlib import Path


class FioLatTest():
    """fio latency percentile test."""

    def __init__(self, artifact_root, test_options, debug):
        """
        artifact_root   root directory for artifacts (subdirectory will be created under here)
        test            test specification
        """
        self.artifact_root = artifact_root
        self.test_options = test_options
        self.debug = debug
        self.filename = None
        self.json_data = None
        self.terse_data = None

        self.test_dir = os.path.join(self.artifact_root,
                                     "{:03d}".format(self.test_options['test_id']))
        if not os.path.exists(self.test_dir):
            os.mkdir(self.test_dir)

        self.filename = "latency{:03d}".format(self.test_options['test_id'])

    def run_fio(self, fio_path):
        """Run a test."""

        fio_args = [
            "--name=latency",
            "--randrepeat=0",
            "--norandommap",
            "--time_based",
            "--size=16M",
            "--rwmixread=50",
            "--group_reporting=1",
            "--write_lat_log={0}".format(self.filename),
            "--output={0}.out".format(self.filename),
            "--ioengine={ioengine}".format(**self.test_options),
            "--rw={rw}".format(**self.test_options),
            "--runtime={runtime}".format(**self.test_options),
            "--output-format={output-format}".format(**self.test_options),
        ]
        for opt in ['slat_percentiles', 'clat_percentiles', 'lat_percentiles',
                    'unified_rw_reporting', 'fsync', 'fdatasync', 'numjobs', 'cmdprio_percentage']:
            if opt in self.test_options:
                option = '--{0}={{{0}}}'.format(opt)
                fio_args.append(option.format(**self.test_options))

        command = [fio_path] + fio_args
        with open(os.path.join(self.test_dir, "{0}.command".format(self.filename)), "w+") as \
                command_file:
            command_file.write("%s\n" % command)

        passed = True
        stdout_file = open(os.path.join(self.test_dir, "{0}.stdout".format(self.filename)), "w+")
        stderr_file = open(os.path.join(self.test_dir, "{0}.stderr".format(self.filename)), "w+")
        exitcode_file = open(os.path.join(self.test_dir,
                                          "{0}.exitcode".format(self.filename)), "w+")
        try:
            proc = None
            # Avoid using subprocess.run() here because when a timeout occurs,
            # fio will be stopped with SIGKILL. This does not give fio a
            # chance to clean up and means that child processes may continue
            # running and submitting IO.
            proc = subprocess.Popen(command,
                                    stdout=stdout_file,
                                    stderr=stderr_file,
                                    cwd=self.test_dir,
                                    universal_newlines=True)
            proc.communicate(timeout=300)
            exitcode_file.write('{0}\n'.format(proc.returncode))
            passed &= (proc.returncode == 0)
        except subprocess.TimeoutExpired:
            proc.terminate()
            proc.communicate()
            assert proc.poll()
            print("Timeout expired")
            passed = False
        except Exception:
            if proc:
                if not proc.poll():
                    proc.terminate()
                    proc.communicate()
            print("Exception: %s" % sys.exc_info())
            passed = False
        finally:
            stdout_file.close()
            stderr_file.close()
            exitcode_file.close()

        if passed:
            if 'json' in self.test_options['output-format']:
                if not self.get_json():
                    print('Unable to decode JSON data')
                    passed = False
            if 'terse' in self.test_options['output-format']:
                if not self.get_terse():
                    print('Unable to decode terse data')
                    passed = False

        return passed

    def get_json(self):
        """Convert fio JSON output into a python JSON object"""

        filename = os.path.join(self.test_dir, "{0}.out".format(self.filename))
        with open(filename, 'r') as file:
            file_data = file.read()

        #
        # Sometimes fio informational messages are included at the top of the
        # JSON output, especially under Windows. Try to decode output as JSON
        # data, lopping off up to the first four lines
        #
        lines = file_data.splitlines()
        for i in range(5):
            file_data = '\n'.join(lines[i:])
            try:
                self.json_data = json.loads(file_data)
            except json.JSONDecodeError:
                continue
            else:
                return True

        return False

    def get_terse(self):
        """Read fio output and return terse format data."""

        filename = os.path.join(self.test_dir, "{0}.out".format(self.filename))
        with open(filename, 'r') as file:
            file_data = file.read()

        #
        # Read the first few lines and see if any of them begin with '3;fio-'
        # If so, the line is probably terse output. Obviously, this only
        # works for fio terse version 3 and it does not work for
        # multi-line terse output
        #
        lines = file_data.splitlines()
        for i in range(8):
            file_data = lines[i]
            if file_data.startswith('3;fio-'):
                self.terse_data = file_data.split(';')
                return True

        return False

    def check_latencies(self, jsondata, ddir, slat=True, clat=True, tlat=True, plus=False,
                        unified=False):
        """Check fio latency data.

        ddir                data direction to check (0=read, 1=write, 2=trim)
        slat                True if submission latency data available to check
        clat                True if completion latency data available to check
        tlat                True of total latency data available to check
        plus                True if we actually have json+ format data where additional checks can
                            be carried out
        unified             True if fio is reporting unified r/w data
        """

        types = {
            'slat': slat,
            'clat': clat,
            'lat': tlat
        }

        retval = True

        for lat in ['slat', 'clat', 'lat']:
            this_iter = True
            if not types[lat]:
                if 'percentile' in jsondata[lat+'_ns']:
                    this_iter = False
                    print('unexpected %s percentiles found' % lat)
                else:
                    print("%s percentiles skipped" % lat)
                continue
            else:
                if 'percentile' not in jsondata[lat+'_ns']:
                    this_iter = False
                    print('%s percentiles not found in fio output' % lat)

            #
            # Check only for the presence/absence of json+
            # latency bins. Future work can check the
            # accurracy of the bin values and counts.
            #
            # Because the latency percentiles are based on
            # the bins, we can be confident that the bin
            # values and counts are correct if fio's
            # latency percentiles match what we compute
            # from the raw data.
            #
            if plus:
                if 'bins' not in jsondata[lat+'_ns']:
                    print('bins not found with json+ output format')
                    this_iter = False
                else:
                    if not self.check_jsonplus(jsondata[lat+'_ns']):
                        this_iter = False
            else:
                if 'bins' in jsondata[lat+'_ns']:
                    print('json+ bins found with json output format')
                    this_iter = False

            latencies = []
            for i in range(10):
                lat_file = os.path.join(self.test_dir, "%s_%s.%s.log" % (self.filename, lat, i+1))
                if not os.path.exists(lat_file):
                    break
                with open(lat_file, 'r', newline='') as file:
                    reader = csv.reader(file)
                    for line in reader:
                        if unified or int(line[2]) == ddir:
                            latencies.append(int(line[1]))

            if int(jsondata['total_ios']) != len(latencies):
                this_iter = False
                print('%s: total_ios = %s, latencies logged = %d' % \
                        (lat, jsondata['total_ios'], len(latencies)))
            elif self.debug:
                print("total_ios %s match latencies logged" % jsondata['total_ios'])

            latencies.sort()
            ptiles = jsondata[lat+'_ns']['percentile']

            for percentile in ptiles.keys():
                #
                # numpy.percentile(latencies, float(percentile),
                #       interpolation='higher')
                # produces values that mostly match what fio reports
                # however, in the tails of the distribution, the values produced
                # by fio's and numpy.percentile's algorithms are occasionally off
                # by one latency measurement. So instead of relying on the canned
                # numpy.percentile routine, implement here fio's algorithm
                #
                rank = math.ceil(float(percentile)/100 * len(latencies))
                if rank > 0:
                    index = rank - 1
                else:
                    index = 0
                value = latencies[int(index)]
                fio_val = int(ptiles[percentile])
                # The theory in stat.h says that the proportional error will be
                # less than 1/128
                if not self.similar(fio_val, value):
                    delta = abs(fio_val - value) / value
                    print("Error with %s %sth percentile: "
                          "fio: %d, expected: %d, proportional delta: %f" %
                          (lat, percentile, fio_val, value, delta))
                    print("Rank: %d, index: %d" % (rank, index))
                    this_iter = False
                elif self.debug:
                    print('%s %sth percentile values match: %d, %d' %
                          (lat, percentile, fio_val, value))

            if this_iter:
                print("%s percentiles match" % lat)
            else:
                retval = False

        return retval

    @staticmethod
    def check_empty(job):
        """
        Make sure JSON data is empty.

        Some data structures should be empty. This function makes sure that they are.

        job         JSON object that we need to check for emptiness
        """

        return job['total_ios'] == 0 and \
                job['slat_ns']['N'] == 0 and \
                job['clat_ns']['N'] == 0 and \
                job['lat_ns']['N'] == 0

    def check_nocmdprio_lat(self, job):
        """
        Make sure no high/low priority latencies appear.

        job         JSON object to check
        """

        for ddir in ['read', 'write', 'trim']:
            if ddir in job:
                if 'lat_high_prio' in job[ddir] or 'lat_low_prio' in job[ddir] or \
                    'clat_high_prio' in job[ddir] or 'clat_low_prio' in job[ddir]:
                    print("Unexpected high/low priority latencies found in %s output" % ddir)
                    return False

        if self.debug:
            print("No high/low priority latencies found")

        return True

    @staticmethod
    def similar(approximation, actual):
        """
        Check whether the approximate values recorded by fio are within the theoretical bound.

        Since it is impractical to store exact latency measurements for each and every IO, fio
        groups similar latency measurements into variable-sized bins. The theory in stat.h says
        that the proportional error will be less than 1/128. This function checks whether this
        is true.

        TODO This test will fail when comparing a value from the largest latency bin against its
        actual measurement. Find some way to detect this and avoid failing.

        approximation   value of the bin used by fio to store a given latency
        actual          actual latency value
        """
        delta = abs(approximation - actual) / actual
        return delta <= 1/128

    def check_jsonplus(self, jsondata):
        """Check consistency of json+ data

        When we have json+ data we can check the min value, max value, and
        sample size reported by fio

        jsondata            json+ data that we need to check
        """

        retval = True

        keys = [int(k) for k in jsondata['bins'].keys()]
        values = [int(jsondata['bins'][k]) for k in jsondata['bins'].keys()]
        smallest = min(keys)
        biggest = max(keys)
        sampsize = sum(values)

        if not self.similar(jsondata['min'], smallest):
            retval = False
            print('reported min %d does not match json+ min %d' % (jsondata['min'], smallest))
        elif self.debug:
            print('json+ min values match: %d' % jsondata['min'])

        if not self.similar(jsondata['max'], biggest):
            retval = False
            print('reported max %d does not match json+ max %d' % (jsondata['max'], biggest))
        elif self.debug:
            print('json+ max values match: %d' % jsondata['max'])

        if sampsize != jsondata['N']:
            retval = False
            print('reported sample size %d does not match json+ total count %d' % \
                    (jsondata['N'], sampsize))
        elif self.debug:
            print('json+ sample sizes match: %d' % sampsize)

        return retval

    def check_sync_lat(self, jsondata, plus=False):
        """Check fsync latency percentile data.

        All we can check is that some percentiles are reported, unless we have json+ data.
        If we actually have json+ data then we can do more checking.

        jsondata        JSON data for fsync operations
        plus            True if we actually have json+ data
        """
        retval = True

        if 'percentile' not in jsondata['lat_ns']:
            print("Sync percentile data not found")
            return False

        if int(jsondata['total_ios']) != int(jsondata['lat_ns']['N']):
            retval = False
            print('Mismatch between total_ios and lat_ns sample size')
        elif self.debug:
            print('sync sample sizes match: %d' % jsondata['total_ios'])

        if not plus:
            if 'bins' in jsondata['lat_ns']:
                print('Unexpected json+ bin data found')
                return False

        if not self.check_jsonplus(jsondata['lat_ns']):
            retval = False

        return retval

    def check_terse(self, terse, jsondata):
        """Compare terse latencies with JSON latencies.

        terse           terse format data for checking
        jsondata        JSON format data for checking
        """

        retval = True

        for lat in terse:
            split = lat.split('%')
            pct = split[0]
            terse_val = int(split[1][1:])
            json_val = math.floor(jsondata[pct]/1000)
            if terse_val != json_val:
                retval = False
                print('Mismatch with %sth percentile: json value=%d,%d terse value=%d' % \
                        (pct, jsondata[pct], json_val, terse_val))
            elif self.debug:
                print('Terse %sth percentile matches JSON value: %d' % (pct, terse_val))

        return retval

    def check_prio_latencies(self, jsondata, clat=True, plus=False):
        """Check consistency of high/low priority latencies.

        clat                True if we should check clat data; other check lat data
        plus                True if we have json+ format data where additional checks can
                            be carried out
        unified             True if fio is reporting unified r/w data
        """

        if clat:
            high = 'clat_high_prio'
            low = 'clat_low_prio'
            combined = 'clat_ns'
        else:
            high = 'lat_high_prio'
            low = 'lat_low_prio'
            combined = 'lat_ns'

        if not high in jsondata or not low in jsondata or not combined in jsondata:
            print("Error identifying high/low priority latencies")
            return False

        if jsondata[high]['N'] + jsondata[low]['N'] != jsondata[combined]['N']:
            print("High %d + low %d != combined sample size %d" % \
                    (jsondata[high]['N'], jsondata[low]['N'], jsondata[combined]['N']))
            return False
        elif self.debug:
            print("High %d + low %d == combined sample size %d" % \
                    (jsondata[high]['N'], jsondata[low]['N'], jsondata[combined]['N']))

        if min(jsondata[high]['min'], jsondata[low]['min']) != jsondata[combined]['min']:
            print("Min of high %d, low %d min latencies does not match min %d from combined data" % \
                    (jsondata[high]['min'], jsondata[low]['min'], jsondata[combined]['min']))
            return False
        elif self.debug:
            print("Min of high %d, low %d min latencies matches min %d from combined data" % \
                    (jsondata[high]['min'], jsondata[low]['min'], jsondata[combined]['min']))

        if max(jsondata[high]['max'], jsondata[low]['max']) != jsondata[combined]['max']:
            print("Max of high %d, low %d max latencies does not match max %d from combined data" % \
                    (jsondata[high]['max'], jsondata[low]['max'], jsondata[combined]['max']))
            return False
        elif self.debug:
            print("Max of high %d, low %d max latencies matches max %d from combined data" % \
                    (jsondata[high]['max'], jsondata[low]['max'], jsondata[combined]['max']))

        weighted_avg = (jsondata[high]['mean'] * jsondata[high]['N'] + \
                        jsondata[low]['mean'] * jsondata[low]['N']) / jsondata[combined]['N']
        delta = abs(weighted_avg - jsondata[combined]['mean'])
        if (delta / jsondata[combined]['mean']) > 0.0001:
            print("Difference between weighted average %f of high, low means "
                  "and actual mean %f exceeds 0.01%%" % (weighted_avg, jsondata[combined]['mean']))
            return False
        elif self.debug:
            print("Weighted average %f of high, low means matches actual mean %f" % \
                    (weighted_avg, jsondata[combined]['mean']))

        if plus:
            if not self.check_jsonplus(jsondata[high]):
                return False
            if not self.check_jsonplus(jsondata[low]):
                return False

            bins = {**jsondata[high]['bins'], **jsondata[low]['bins']}
            for duration in bins.keys():
                if duration in jsondata[high]['bins'] and duration in jsondata[low]['bins']:
                    bins[duration] = jsondata[high]['bins'][duration] + \
                            jsondata[low]['bins'][duration]

            if len(bins) != len(jsondata[combined]['bins']):
                print("Number of combined high/low bins does not match number of overall bins")
                return False
            elif self.debug:
                print("Number of bins from merged high/low data matches number of overall bins")

            for duration in bins.keys():
                if bins[duration] != jsondata[combined]['bins'][duration]:
                    print("Merged high/low count does not match overall count for duration %d" \
                            % duration)
                    return False

        print("Merged high/low priority latency data match combined latency data")
        return True

    def check(self):
        """Check test output."""

        raise NotImplementedError()


class Test001(FioLatTest):
    """Test object for Test 1."""

    def check(self):
        """Check Test 1 output."""

        job = self.json_data['jobs'][0]

        retval = True
        if not self.check_empty(job['write']):
            print("Unexpected write data found in output")
            retval = False
        if not self.check_empty(job['trim']):
            print("Unexpected trim data found in output")
            retval = False
        if not self.check_nocmdprio_lat(job):
            print("Unexpected high/low priority latencies found")
            retval = False

        retval &= self.check_latencies(job['read'], 0, slat=False)

        return retval


class Test002(FioLatTest):
    """Test object for Test 2."""

    def check(self):
        """Check Test 2 output."""

        job = self.json_data['jobs'][0]

        retval = True
        if not self.check_empty(job['read']):
            print("Unexpected read data found in output")
            retval = False
        if not self.check_empty(job['trim']):
            print("Unexpected trim data found in output")
            retval = False
        if not self.check_nocmdprio_lat(job):
            print("Unexpected high/low priority latencies found")
            retval = False

        retval &= self.check_latencies(job['write'], 1, slat=False, clat=False)

        return retval


class Test003(FioLatTest):
    """Test object for Test 3."""

    def check(self):
        """Check Test 3 output."""

        job = self.json_data['jobs'][0]

        retval = True
        if not self.check_empty(job['read']):
            print("Unexpected read data found in output")
            retval = False
        if not self.check_empty(job['write']):
            print("Unexpected write data found in output")
            retval = False
        if not self.check_nocmdprio_lat(job):
            print("Unexpected high/low priority latencies found")
            retval = False

        retval &= self.check_latencies(job['trim'], 2, slat=False, tlat=False)

        return retval


class Test004(FioLatTest):
    """Test object for Tests 4, 13."""

    def check(self):
        """Check Test 4, 13 output."""

        job = self.json_data['jobs'][0]

        retval = True
        if not self.check_empty(job['write']):
            print("Unexpected write data found in output")
            retval = False
        if not self.check_empty(job['trim']):
            print("Unexpected trim data found in output")
            retval = False
        if not self.check_nocmdprio_lat(job):
            print("Unexpected high/low priority latencies found")
            retval = False

        retval &= self.check_latencies(job['read'], 0, plus=True)

        return retval


class Test005(FioLatTest):
    """Test object for Test 5."""

    def check(self):
        """Check Test 5 output."""

        job = self.json_data['jobs'][0]

        retval = True
        if not self.check_empty(job['read']):
            print("Unexpected read data found in output")
            retval = False
        if not self.check_empty(job['trim']):
            print("Unexpected trim data found in output")
            retval = False
        if not self.check_nocmdprio_lat(job):
            print("Unexpected high/low priority latencies found")
            retval = False

        retval &= self.check_latencies(job['write'], 1, slat=False, plus=True)

        return retval


class Test006(FioLatTest):
    """Test object for Test 6."""

    def check(self):
        """Check Test 6 output."""

        job = self.json_data['jobs'][0]

        retval = True
        if not self.check_empty(job['write']):
            print("Unexpected write data found in output")
            retval = False
        if not self.check_empty(job['trim']):
            print("Unexpected trim data found in output")
            retval = False
        if not self.check_nocmdprio_lat(job):
            print("Unexpected high/low priority latencies found")
            retval = False

        retval &= self.check_latencies(job['read'], 0, slat=False, tlat=False, plus=True)

        return retval


class Test007(FioLatTest):
    """Test object for Test 7."""

    def check(self):
        """Check Test 7 output."""

        job = self.json_data['jobs'][0]

        retval = True
        if not self.check_empty(job['trim']):
            print("Unexpected trim data found in output")
            retval = False
        if not self.check_nocmdprio_lat(job):
            print("Unexpected high/low priority latencies found")
            retval = False

        retval &= self.check_latencies(job['read'], 0, clat=False, tlat=False, plus=True)
        retval &= self.check_latencies(job['write'], 1, clat=False, tlat=False, plus=True)

        return retval


class Test008(FioLatTest):
    """Test object for Tests 8, 14."""

    def check(self):
        """Check Test 8, 14 output."""

        job = self.json_data['jobs'][0]

        retval = True
        if 'read' in job or 'write'in job or 'trim' in job:
            print("Unexpected data direction found in fio output")
            retval = False
        if not self.check_nocmdprio_lat(job):
            print("Unexpected high/low priority latencies found")
            retval = False

        retval &= self.check_latencies(job['mixed'], 0, plus=True, unified=True)

        return retval


class Test009(FioLatTest):
    """Test object for Test 9."""

    def check(self):
        """Check Test 9 output."""

        job = self.json_data['jobs'][0]

        retval = True
        if not self.check_empty(job['read']):
            print("Unexpected read data found in output")
            retval = False
        if not self.check_empty(job['trim']):
            print("Unexpected trim data found in output")
            retval = False
        if not self.check_sync_lat(job['sync'], plus=True):
            print("Error checking fsync latency data")
            retval = False
        if not self.check_nocmdprio_lat(job):
            print("Unexpected high/low priority latencies found")
            retval = False

        retval &= self.check_latencies(job['write'], 1, slat=False, plus=True)

        return retval


class Test010(FioLatTest):
    """Test object for Test 10."""

    def check(self):
        """Check Test 10 output."""

        job = self.json_data['jobs'][0]

        retval = True
        if not self.check_empty(job['trim']):
            print("Unexpected trim data found in output")
            retval = False
        if not self.check_nocmdprio_lat(job):
            print("Unexpected high/low priority latencies found")
            retval = False

        retval &= self.check_latencies(job['read'], 0, plus=True)
        retval &= self.check_latencies(job['write'], 1, plus=True)
        retval &= self.check_terse(self.terse_data[17:34], job['read']['lat_ns']['percentile'])
        retval &= self.check_terse(self.terse_data[58:75], job['write']['lat_ns']['percentile'])
        # Terse data checking only works for default percentiles.
        # This needs to be changed if something other than the default is ever used.

        return retval


class Test011(FioLatTest):
    """Test object for Test 11."""

    def check(self):
        """Check Test 11 output."""

        job = self.json_data['jobs'][0]

        retval = True
        if not self.check_empty(job['trim']):
            print("Unexpected trim data found in output")
            retval = False
        if not self.check_nocmdprio_lat(job):
            print("Unexpected high/low priority latencies found")
            retval = False

        retval &= self.check_latencies(job['read'], 0, slat=False, clat=False, plus=True)
        retval &= self.check_latencies(job['write'], 1, slat=False, clat=False, plus=True)
        retval &= self.check_terse(self.terse_data[17:34], job['read']['lat_ns']['percentile'])
        retval &= self.check_terse(self.terse_data[58:75], job['write']['lat_ns']['percentile'])
        # Terse data checking only works for default percentiles.
        # This needs to be changed if something other than the default is ever used.

        return retval


class Test015(FioLatTest):
    """Test object for Test 15."""

    def check(self):
        """Check Test 15 output."""

        job = self.json_data['jobs'][0]

        retval = True
        if not self.check_empty(job['write']):
            print("Unexpected write data found in output")
            retval = False
        if not self.check_empty(job['trim']):
            print("Unexpected trim data found in output")
            retval = False

        retval &= self.check_latencies(job['read'], 0, plus=True)
        retval &= self.check_prio_latencies(job['read'], clat=False, plus=True)

        return retval


class Test016(FioLatTest):
    """Test object for Test 16."""

    def check(self):
        """Check Test 16 output."""

        job = self.json_data['jobs'][0]

        retval = True
        if not self.check_empty(job['read']):
            print("Unexpected read data found in output")
            retval = False
        if not self.check_empty(job['trim']):
            print("Unexpected trim data found in output")
            retval = False

        retval &= self.check_latencies(job['write'], 1, slat=False, plus=True)
        retval &= self.check_prio_latencies(job['write'], clat=False, plus=True)

        return retval


class Test017(FioLatTest):
    """Test object for Test 17."""

    def check(self):
        """Check Test 17 output."""

        job = self.json_data['jobs'][0]

        retval = True
        if not self.check_empty(job['write']):
            print("Unexpected write data found in output")
            retval = False
        if not self.check_empty(job['trim']):
            print("Unexpected trim data found in output")
            retval = False

        retval &= self.check_latencies(job['read'], 0, slat=False, tlat=False, plus=True)
        retval &= self.check_prio_latencies(job['read'], plus=True)

        return retval


class Test018(FioLatTest):
    """Test object for Test 18."""

    def check(self):
        """Check Test 18 output."""

        job = self.json_data['jobs'][0]

        retval = True
        if not self.check_empty(job['trim']):
            print("Unexpected trim data found in output")
            retval = False

        retval &= self.check_latencies(job['read'], 0, clat=False, tlat=False, plus=True)
        retval &= self.check_latencies(job['write'], 1, clat=False, tlat=False, plus=True)

        # We actually have json+ data but setting plus=False below avoids checking the
        # json+ bins which did not exist for clat and lat because this job is run with
        # clat_percentiles=0, lat_percentiles=0, However, we can still check the summary
        # statistics
        retval &= self.check_prio_latencies(job['write'], plus=False)
        retval &= self.check_prio_latencies(job['read'], plus=False)

        return retval


class Test019(FioLatTest):
    """Test object for Tests 19, 20."""

    def check(self):
        """Check Test 19, 20 output."""

        job = self.json_data['jobs'][0]

        retval = True
        if 'read' in job or 'write'in job or 'trim' in job:
            print("Unexpected data direction found in fio output")
            retval = False

        retval &= self.check_latencies(job['mixed'], 0, plus=True, unified=True)
        retval &= self.check_prio_latencies(job['mixed'], clat=False, plus=True)

        return retval


def parse_args():
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--fio', help='path to file executable (e.g., ./fio)')
    parser.add_argument('-a', '--artifact-root', help='artifact root directory')
    parser.add_argument('-d', '--debug', help='enable debug output', action='store_true')
    parser.add_argument('-s', '--skip', nargs='+', type=int,
                        help='list of test(s) to skip')
    parser.add_argument('-o', '--run-only', nargs='+', type=int,
                        help='list of test(s) to run, skipping all others')
    args = parser.parse_args()

    return args


def main():
    """Run tests of fio latency percentile reporting"""

    args = parse_args()

    artifact_root = args.artifact_root if args.artifact_root else \
        "latency-test-{0}".format(time.strftime("%Y%m%d-%H%M%S"))
    os.mkdir(artifact_root)
    print("Artifact directory is %s" % artifact_root)

    if args.fio:
        fio = str(Path(args.fio).absolute())
    else:
        fio = 'fio'
    print("fio path is %s" % fio)

    if platform.system() == 'Linux':
        aio = 'libaio'
    elif platform.system() == 'Windows':
        aio = 'windowsaio'
    else:
        aio = 'posixaio'

    test_list = [
        {
            # randread, null
            # enable slat, clat, lat
            # only clat and lat will appear because
            # because the null ioengine is syncrhonous
            "test_id": 1,
            "runtime": 2,
            "output-format": "json",
            "slat_percentiles": 1,
            "clat_percentiles": 1,
            "lat_percentiles": 1,
            "ioengine": 'null',
            'rw': 'randread',
            "test_obj": Test001,
        },
        {
            # randwrite, null
            # enable lat only
            "test_id": 2,
            "runtime": 2,
            "output-format": "json",
            "slat_percentiles": 0,
            "clat_percentiles": 0,
            "lat_percentiles": 1,
            "ioengine": 'null',
            'rw': 'randwrite',
            "test_obj": Test002,
        },
        {
            # randtrim, null
            # enable clat only
            "test_id": 3,
            "runtime": 2,
            "output-format": "json",
            "slat_percentiles": 0,
            "clat_percentiles": 1,
            "lat_percentiles": 0,
            "ioengine": 'null',
            'rw': 'randtrim',
            "test_obj": Test003,
        },
        {
            # randread, aio
            # enable slat, clat, lat
            # all will appear because liaio is asynchronous
            "test_id": 4,
            "runtime": 5,
            "output-format": "json+",
            "slat_percentiles": 1,
            "clat_percentiles": 1,
            "lat_percentiles": 1,
            "ioengine": aio,
            'rw': 'randread',
            "test_obj": Test004,
        },
        {
            # randwrite, aio
            # enable only clat, lat
            "test_id": 5,
            "runtime": 5,
            "output-format": "json+",
            "slat_percentiles": 0,
            "clat_percentiles": 1,
            "lat_percentiles": 1,
            "ioengine": aio,
            'rw': 'randwrite',
            "test_obj": Test005,
        },
        {
            # randread, aio
            # by default only clat should appear
            "test_id": 6,
            "runtime": 5,
            "output-format": "json+",
            "ioengine": aio,
            'rw': 'randread',
            "test_obj": Test006,
        },
        {
            # 50/50 r/w, aio
            # enable only slat
            "test_id": 7,
            "runtime": 5,
            "output-format": "json+",
            "slat_percentiles": 1,
            "clat_percentiles": 0,
            "lat_percentiles": 0,
            "ioengine": aio,
            'rw': 'randrw',
            "test_obj": Test007,
        },
        {
            # 50/50 r/w, aio, unified_rw_reporting
            # enable slat, clat, lat
            "test_id": 8,
            "runtime": 5,
            "output-format": "json+",
            "slat_percentiles": 1,
            "clat_percentiles": 1,
            "lat_percentiles": 1,
            "ioengine": aio,
            'rw': 'randrw',
            'unified_rw_reporting': 1,
            "test_obj": Test008,
        },
        {
            # randwrite, null
            # enable slat, clat, lat
            # fsync
            "test_id": 9,
            "runtime": 2,
            "output-format": "json+",
            "slat_percentiles": 1,
            "clat_percentiles": 1,
            "lat_percentiles": 1,
            "ioengine": 'null',
            'rw': 'randwrite',
            'fsync': 32,
            "test_obj": Test009,
        },
        {
            # 50/50 r/w, aio
            # enable slat, clat, lat
            "test_id": 10,
            "runtime": 5,
            "output-format": "terse,json+",
            "slat_percentiles": 1,
            "clat_percentiles": 1,
            "lat_percentiles": 1,
            "ioengine": aio,
            'rw': 'randrw',
            "test_obj": Test010,
        },
        {
            # 50/50 r/w, aio
            # enable only lat
            "test_id": 11,
            "runtime": 5,
            "output-format": "terse,json+",
            "slat_percentiles": 0,
            "clat_percentiles": 0,
            "lat_percentiles": 1,
            "ioengine": aio,
            'rw': 'randrw',
            "test_obj": Test011,
        },
        {
            # randread, null
            # enable slat, clat, lat
            # only clat and lat will appear because
            # because the null ioengine is syncrhonous
            # same as Test 1 except
            # numjobs = 4 to test sum_thread_stats() changes
            "test_id": 12,
            "runtime": 2,
            "output-format": "json",
            "slat_percentiles": 1,
            "clat_percentiles": 1,
            "lat_percentiles": 1,
            "ioengine": 'null',
            'rw': 'randread',
            'numjobs': 4,
            "test_obj": Test001,
        },
        {
            # randread, aio
            # enable slat, clat, lat
            # all will appear because liaio is asynchronous
            # same as Test 4 except
            # numjobs = 4 to test sum_thread_stats() changes
            "test_id": 13,
            "runtime": 5,
            "output-format": "json+",
            "slat_percentiles": 1,
            "clat_percentiles": 1,
            "lat_percentiles": 1,
            "ioengine": aio,
            'rw': 'randread',
            'numjobs': 4,
            "test_obj": Test004,
        },
        {
            # 50/50 r/w, aio, unified_rw_reporting
            # enable slat, clat, lata
            # same as Test 8 except
            # numjobs = 4 to test sum_thread_stats() changes
            "test_id": 14,
            "runtime": 5,
            "output-format": "json+",
            "slat_percentiles": 1,
            "clat_percentiles": 1,
            "lat_percentiles": 1,
            "ioengine": aio,
            'rw': 'randrw',
            'unified_rw_reporting': 1,
            'numjobs': 4,
            "test_obj": Test008,
        },
        {
            # randread, aio
            # enable slat, clat, lat
            # all will appear because liaio is asynchronous
            # same as Test 4 except add cmdprio_percentage
            "test_id": 15,
            "runtime": 5,
            "output-format": "json+",
            "slat_percentiles": 1,
            "clat_percentiles": 1,
            "lat_percentiles": 1,
            "ioengine": aio,
            'rw': 'randread',
            'cmdprio_percentage': 50,
            "test_obj": Test015,
        },
        {
            # randwrite, aio
            # enable only clat, lat
            # same as Test 5 except add cmdprio_percentage
            "test_id": 16,
            "runtime": 5,
            "output-format": "json+",
            "slat_percentiles": 0,
            "clat_percentiles": 1,
            "lat_percentiles": 1,
            "ioengine": aio,
            'rw': 'randwrite',
            'cmdprio_percentage': 50,
            "test_obj": Test016,
        },
        {
            # randread, aio
            # by default only clat should appear
            # same as Test 6 except add cmdprio_percentage
            "test_id": 17,
            "runtime": 5,
            "output-format": "json+",
            "ioengine": aio,
            'rw': 'randread',
            'cmdprio_percentage': 50,
            "test_obj": Test017,
        },
        {
            # 50/50 r/w, aio
            # enable only slat
            # same as Test 7 except add cmdprio_percentage
            "test_id": 18,
            "runtime": 5,
            "output-format": "json+",
            "slat_percentiles": 1,
            "clat_percentiles": 0,
            "lat_percentiles": 0,
            "ioengine": aio,
            'rw': 'randrw',
            'cmdprio_percentage': 50,
            "test_obj": Test018,
        },
        {
            # 50/50 r/w, aio, unified_rw_reporting
            # enable slat, clat, lat
            # same as Test 8 except add cmdprio_percentage
            "test_id": 19,
            "runtime": 5,
            "output-format": "json+",
            "slat_percentiles": 1,
            "clat_percentiles": 1,
            "lat_percentiles": 1,
            "ioengine": aio,
            'rw': 'randrw',
            'unified_rw_reporting': 1,
            'cmdprio_percentage': 50,
            "test_obj": Test019,
        },
        {
            # 50/50 r/w, aio, unified_rw_reporting
            # enable slat, clat, lat
            # same as Test 19 except
            # add numjobs = 4 to test sum_thread_stats() changes
            "test_id": 20,
            "runtime": 5,
            "output-format": "json+",
            "slat_percentiles": 1,
            "clat_percentiles": 1,
            "lat_percentiles": 1,
            "ioengine": aio,
            'rw': 'randrw',
            'unified_rw_reporting': 1,
            'cmdprio_percentage': 50,
            'numjobs': 4,
            "test_obj": Test019,
        },
    ]

    passed = 0
    failed = 0
    skipped = 0

    for test in test_list:
        if (args.skip and test['test_id'] in args.skip) or \
           (args.run_only and test['test_id'] not in args.run_only):
            skipped = skipped + 1
            outcome = 'SKIPPED (User request)'
        elif platform.system() != 'Linux' and 'cmdprio_percentage' in test:
            skipped = skipped + 1
            outcome = 'SKIPPED (Linux required for cmdprio_percentage tests)'
        else:
            test_obj = test['test_obj'](artifact_root, test, args.debug)
            status = test_obj.run_fio(fio)
            if status:
                status = test_obj.check()
            if status:
                passed = passed + 1
                outcome = 'PASSED'
            else:
                failed = failed + 1
                outcome = 'FAILED'

        print("**********Test {0} {1}**********".format(test['test_id'], outcome))

    print("{0} tests passed, {1} failed, {2} skipped".format(passed, failed, skipped))

    sys.exit(failed)


if __name__ == '__main__':
    main()
