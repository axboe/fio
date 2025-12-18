#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2019 Western Digital Corporation or its affiliates.
#
"""
# run-fio-tests.py
#
# Automate running of fio tests
#
# USAGE
# python3 run-fio-tests.py [-r fio-root] [-f fio-path] [-a artifact-root]
#                           [--skip # # #...] [--run-only # # #...]
#
#
# EXAMPLE
# # git clone https://git.kernel.org/pub/scm/linux/kernel/git/axboe/fio
# # cd fio
# # make -j
# # python3 t/run-fio-tests.py
#
#
# REQUIREMENTS
# - Python 3.5 (subprocess.run)
# - Linux (libaio ioengine, zbd tests, etc)
# - The artifact directory must be on a file system that accepts 512-byte IO
#   (t0002, t0003, t0004).
# - The artifact directory needs to be on an SSD. Otherwise tests that carry
#   out file-based IO will trigger a timeout (t0006).
# - 4 CPUs (t0009)
# - SciPy (steadystate_tests.py)
# - libzbc (zbd tests)
# - root privileges (zbd test)
# - kernel 4.19 or later for zoned null block devices (zbd tests)
# - CUnit support (unittests)
#
"""

#
# TODO  run multiple tests simultaneously
# TODO  Add sgunmap tests (requires SAS SSD)
#

import os
import sys
import time
import shutil
import logging
import argparse
import re
from pathlib import Path
from statsmodels.sandbox.stats.runs import runstest_1samp
from fiotestlib import FioExeTest, FioJobFileTest, run_fio_tests
from fiotestcommon import *


class FioJobFileTest_t0005(FioJobFileTest):
    """Test consists of fio test job t0005
    Confirm that read['io_kbytes'] == write['io_kbytes'] == 102400"""

    def check_result(self):
        super().check_result()

        if not self.passed:
            return

        if self.json_data['jobs'][0]['read']['io_kbytes'] != 102400:
            self.failure_reason = f"{self.failure_reason} bytes read mismatch,"
            self.passed = False
        if self.json_data['jobs'][0]['write']['io_kbytes'] != 102400:
            self.failure_reason = f"{self.failure_reason} bytes written mismatch,"
            self.passed = False


class FioJobFileTest_t0006(FioJobFileTest):
    """Test consists of fio test job t0006
    Confirm that read['io_kbytes'] ~ 2*write['io_kbytes']"""

    def check_result(self):
        super().check_result()

        if not self.passed:
            return

        ratio = self.json_data['jobs'][0]['read']['io_kbytes'] \
            / self.json_data['jobs'][0]['write']['io_kbytes']
        logging.debug("Test %d: ratio: %f", self.testnum, ratio)
        if ratio < 1.99 or ratio > 2.01:
            self.failure_reason = f"{self.failure_reason} read/write ratio mismatch,"
            self.passed = False


class FioJobFileTest_t0007(FioJobFileTest):
    """Test consists of fio test job t0007
    Confirm that read['io_kbytes'] = 87040"""

    def check_result(self):
        super().check_result()

        if not self.passed:
            return

        if self.json_data['jobs'][0]['read']['io_kbytes'] != 87040:
            self.failure_reason = f"{self.failure_reason} bytes read mismatch,"
            self.passed = False


class FioJobFileTest_t0008(FioJobFileTest):
    """Test consists of fio test job t0008
    Confirm that read['io_kbytes'] = 32768 and that
                write['io_kbytes'] ~ 16384

    This is a 50/50 seq read/write workload. Since fio flips a coin to
    determine whether to issue a read or a write, total bytes written will not
    be exactly 16384K. But total bytes read will be exactly 32768K because
    reads will include the initial phase as well as the verify phase where all
    the blocks originally written will be read."""

    def check_result(self):
        super().check_result()

        if not self.passed:
            return

        ratio = self.json_data['jobs'][0]['write']['io_kbytes'] / 16384
        logging.debug("Test %d: ratio: %f", self.testnum, ratio)

        if ratio < 0.97 or ratio > 1.03:
            self.failure_reason = f"{self.failure_reason} bytes written mismatch,"
            self.passed = False
        if self.json_data['jobs'][0]['read']['io_kbytes'] != 32768:
            self.failure_reason = f"{self.failure_reason} bytes read mismatch,"
            self.passed = False


class FioJobFileTest_t0009(FioJobFileTest):
    """Test consists of fio test job t0009
    Confirm that runtime >= 60s"""

    def check_result(self):
        super().check_result()

        if not self.passed:
            return

        logging.debug('Test %d: elapsed: %d', self.testnum, self.json_data['jobs'][0]['elapsed'])

        if self.json_data['jobs'][0]['elapsed'] < 60:
            self.failure_reason = f"{self.failure_reason} elapsed time mismatch,"
            self.passed = False


class FioJobFileTest_t0012(FioJobFileTest):
    """Test consists of fio test job t0012
    Confirm ratios of job iops are 1:5:10
    job1,job2,job3 respectively"""

    def check_result(self):
        super().check_result()

        if not self.passed:
            return

        iops_files = []
        for i in range(1, 4):
            filename = os.path.join(self.paths['test_dir'], "{0}_iops.{1}.log".format(os.path.basename(
                self.fio_job), i))
            file_data = self.get_file_fail(filename)
            if not file_data:
                return

            iops_files.append(file_data.splitlines())

        # there are 9 samples for job1 and job2, 4 samples for job3
        iops1 = 0.0
        iops2 = 0.0
        iops3 = 0.0
        for i in range(9):
            iops1 = iops1 + float(iops_files[0][i].split(',')[1])
            iops2 = iops2 + float(iops_files[1][i].split(',')[1])
            iops3 = iops3 + float(iops_files[2][i].split(',')[1])

            ratio1 = iops3/iops2
            ratio2 = iops3/iops1
            logging.debug("sample {0}: job1 iops={1} job2 iops={2} job3 iops={3} " \
                "job3/job2={4:.3f} job3/job1={5:.3f}".format(i, iops1, iops2, iops3, ratio1,
                                                             ratio2))

        # test job1 and job2 succeeded to recalibrate
        if ratio1 < 1 or ratio1 > 3 or ratio2 < 7 or ratio2 > 13:
            self.failure_reason += " iops ratio mismatch iops1={0} iops2={1} iops3={2} " \
                "expected r1~2 r2~10 got r1={3:.3f} r2={4:.3f},".format(iops1, iops2, iops3,
                                                                        ratio1, ratio2)
            self.passed = False
            return


class FioJobFileTest_t0014(FioJobFileTest):
    """Test consists of fio test job t0014
	Confirm that job1_iops / job2_iops ~ 1:2 for entire duration
	and that job1_iops / job3_iops ~ 1:3 for first half of duration.

    The test is about making sure the flow feature can
    re-calibrate the activity dynamically"""

    def check_result(self):
        super().check_result()

        if not self.passed:
            return

        iops_files = []
        for i in range(1, 4):
            filename = os.path.join(self.paths['test_dir'], "{0}_iops.{1}.log".format(os.path.basename(
                self.fio_job), i))
            file_data = self.get_file_fail(filename)
            if not file_data:
                return

            iops_files.append(file_data.splitlines())

        # there are 9 samples for job1 and job2, 4 samples for job3
        iops1 = 0.0
        iops2 = 0.0
        iops3 = 0.0
        for i in range(9):
            if i < 4:
                iops3 = iops3 + float(iops_files[2][i].split(',')[1])
            elif i == 4:
                ratio1 = iops1 / iops2
                ratio2 = iops1 / iops3


                if ratio1 < 0.43 or ratio1 > 0.57 or ratio2 < 0.21 or ratio2 > 0.45:
                    self.failure_reason += " iops ratio mismatch iops1={0} iops2={1} iops3={2} " \
                                           "expected r1~0.5 r2~0.33 got r1={3:.3f} r2={4:.3f},".format(
                                               iops1, iops2, iops3, ratio1, ratio2)
                    self.passed = False

            iops1 = iops1 + float(iops_files[0][i].split(',')[1])
            iops2 = iops2 + float(iops_files[1][i].split(',')[1])

            ratio1 = iops1/iops2
            ratio2 = iops1/iops3
            logging.debug("sample {0}: job1 iops={1} job2 iops={2} job3 iops={3} " \
                          "job1/job2={4:.3f} job1/job3={5:.3f}".format(i, iops1, iops2, iops3,
                                                                       ratio1, ratio2))

        # test job1 and job2 succeeded to recalibrate
        if ratio1 < 0.43 or ratio1 > 0.57:
            self.failure_reason += " iops ratio mismatch iops1={0} iops2={1} expected ratio~0.5 " \
                                   "got ratio={2:.3f},".format(iops1, iops2, ratio1)
            self.passed = False
            return


class FioJobFileTest_t0015(FioJobFileTest):
    """Test consists of fio test jobs t0015 and t0016
    Confirm that mean(slat) + mean(clat) = mean(tlat)"""

    def check_result(self):
        super().check_result()

        if not self.passed:
            return

        slat = self.json_data['jobs'][0]['read']['slat_ns']['mean']
        clat = self.json_data['jobs'][0]['read']['clat_ns']['mean']
        tlat = self.json_data['jobs'][0]['read']['lat_ns']['mean']
        logging.debug('Test %d: slat %f, clat %f, tlat %f', self.testnum, slat, clat, tlat)

        if abs(slat + clat - tlat) > 1:
            self.failure_reason = "{0} slat {1} + clat {2} = {3} != tlat {4},".format(
                self.failure_reason, slat, clat, slat+clat, tlat)
            self.passed = False


class FioJobFileTest_t0019(FioJobFileTest):
    """Test consists of fio test job t0019
    Confirm that all offsets were touched sequentially"""

    def check_result(self):
        super().check_result()

        bw_log_filename = os.path.join(self.paths['test_dir'], "test_bw.log")
        file_data = self.get_file_fail(bw_log_filename)
        if not file_data:
            return

        log_lines = file_data.split('\n')

        prev = -4096
        for line in log_lines:
            if len(line.strip()) == 0:
                continue
            cur = int(line.split(',')[4])
            if cur - prev != 4096:
                self.passed = False
                self.failure_reason = f"offsets {prev}, {cur} not sequential"
                return
            prev = cur

        if cur/4096 != 255:
            self.passed = False
            self.failure_reason = f"unexpected last offset {cur}"


class FioJobFileTest_t0020(FioJobFileTest):
    """Test consists of fio test jobs t0020 and t0021
    Confirm that almost all offsets were touched non-sequentially"""

    def check_result(self):
        super().check_result()

        bw_log_filename = os.path.join(self.paths['test_dir'], "test_bw.log")
        file_data = self.get_file_fail(bw_log_filename)
        if not file_data:
            return

        log_lines = file_data.split('\n')

        offsets = []

        prev = int(log_lines[0].split(',')[4])
        for line in log_lines[1:]:
            offsets.append(prev/4096)
            if len(line.strip()) == 0:
                continue
            cur = int(line.split(',')[4])
            prev = cur

        if len(offsets) != 256:
            self.passed = False
            self.failure_reason += f" number of offsets is {len(offsets)} instead of 256"

        for i in range(256):
            if not i in offsets:
                self.passed = False
                self.failure_reason += f" missing offset {i * 4096}"

        (_, p) = runstest_1samp(list(offsets))
        if p < 0.05:
            self.passed = False
            self.failure_reason += f" runs test failed with p = {p}"


class FioJobFileTest_t0022(FioJobFileTest):
    """Test consists of fio test job t0022"""

    def check_result(self):
        super().check_result()

        bw_log_filename = os.path.join(self.paths['test_dir'], "test_bw.log")
        file_data = self.get_file_fail(bw_log_filename)
        if not file_data:
            return

        log_lines = file_data.split('\n')

        filesize = 1024*1024
        bs = 4096
        seq_count = 0
        offsets = set()

        prev = int(log_lines[0].split(',')[4])
        for line in log_lines[1:]:
            offsets.add(prev/bs)
            if len(line.strip()) == 0:
                continue
            cur = int(line.split(',')[4])
            if cur - prev == bs:
                seq_count += 1
            prev = cur

        # 10 is an arbitrary threshold
        if seq_count > 10:
            self.passed = False
            self.failure_reason = f"too many ({seq_count}) consecutive offsets"

        if len(offsets) == filesize/bs:
            self.passed = False
            self.failure_reason += " no duplicate offsets found with norandommap=1"


class FioJobFileTest_t0023(FioJobFileTest):
    """Test consists of fio test job t0023 randtrimwrite test."""

    def check_trimwrite(self, filename):
        """Make sure that trims are followed by writes of the same size at the same offset."""

        bw_log_filename = os.path.join(self.paths['test_dir'], filename)
        file_data = self.get_file_fail(bw_log_filename)
        if not file_data:
            return

        log_lines = file_data.split('\n')

        prev_ddir = 1
        for line in log_lines:
            if len(line.strip()) == 0:
                continue
            vals = line.split(',')
            ddir = int(vals[2])
            bs = int(vals[3])
            offset = int(vals[4])
            if prev_ddir == 1:
                if ddir != 2:
                    self.passed = False
                    self.failure_reason += " {0}: write not preceeded by trim: {1}".format(
                        bw_log_filename, line)
                    break
            else:
                if ddir != 1:   # pylint: disable=no-else-break
                    self.passed = False
                    self.failure_reason += " {0}: trim not preceeded by write: {1}".format(
                        bw_log_filename, line)
                    break
                else:
                    if prev_bs != bs:
                        self.passed = False
                        self.failure_reason += " {0}: block size does not match: {1}".format(
                            bw_log_filename, line)
                        break

                    if prev_offset != offset:
                        self.passed = False
                        self.failure_reason += " {0}: offset does not match: {1}".format(
                            bw_log_filename, line)
                        break

            prev_ddir = ddir
            prev_bs = bs
            prev_offset = offset


    def check_all_offsets(self, filename, sectorsize, filesize):
        """Make sure all offsets were touched."""

        file_data = self.get_file_fail(os.path.join(self.paths['test_dir'], filename))
        if not file_data:
            return

        log_lines = file_data.split('\n')

        offsets = set()

        for line in log_lines:
            if len(line.strip()) == 0:
                continue
            vals = line.split(',')
            bs = int(vals[3])
            offset = int(vals[4])
            if offset % sectorsize != 0:
                self.passed = False
                self.failure_reason += " {0}: offset {1} not a multiple of sector size {2}".format(
                    filename, offset, sectorsize)
                break
            if bs % sectorsize != 0:
                self.passed = False
                self.failure_reason += " {0}: block size {1} not a multiple of sector size " \
                    "{2}".format(filename, bs, sectorsize)
                break
            for i in range(int(bs/sectorsize)):
                offsets.add(offset/sectorsize + i)

        if len(offsets) != filesize/sectorsize:
            self.passed = False
            self.failure_reason += " {0}: only {1} offsets touched; expected {2}".format(
                filename, len(offsets), filesize/sectorsize)
        else:
            logging.debug("%s: %d sectors touched", filename, len(offsets))


    def check_result(self):
        super().check_result()

        filesize = 1024*1024

        self.check_trimwrite("basic_bw.log")
        self.check_trimwrite("bs_bw.log")
        self.check_trimwrite("bsrange_bw.log")
        self.check_trimwrite("bssplit_bw.log")
        self.check_trimwrite("basic_no_rm_bw.log")
        self.check_trimwrite("bs_no_rm_bw.log")
        self.check_trimwrite("bsrange_no_rm_bw.log")
        self.check_trimwrite("bssplit_no_rm_bw.log")

        self.check_all_offsets("basic_bw.log", 4096, filesize)
        self.check_all_offsets("bs_bw.log", 8192, filesize)
        self.check_all_offsets("bsrange_bw.log", 512, filesize)
        self.check_all_offsets("bssplit_bw.log", 512, filesize)


class FioJobFileTest_t0024(FioJobFileTest_t0023):
    """Test consists of fio test job t0024 trimwrite test."""

    def check_result(self):
        # call FioJobFileTest_t0023's parent to skip checks done by t0023
        super(FioJobFileTest_t0023, self).check_result()

        filesize = 1024*1024

        self.check_trimwrite("basic_bw.log")
        self.check_trimwrite("bs_bw.log")
        self.check_trimwrite("bsrange_bw.log")
        self.check_trimwrite("bssplit_bw.log")

        self.check_all_offsets("basic_bw.log", 4096, filesize)
        self.check_all_offsets("bs_bw.log", 8192, filesize)
        self.check_all_offsets("bsrange_bw.log", 512, filesize)
        self.check_all_offsets("bssplit_bw.log", 512, filesize)


class FioJobFileTest_t0025(FioJobFileTest):
    """Test experimental verify read backs written data pattern."""
    def check_result(self):
        super().check_result()

        if not self.passed:
            return

        if self.json_data['jobs'][0]['read']['io_kbytes'] != 128:
            self.passed = False

class FioJobFileTest_t0027(FioJobFileTest):
    def setup(self, *args, **kws):
        super().setup(*args, **kws)
        self.pattern_file = os.path.join(self.paths['test_dir'], "t0027.pattern")
        self.output_file = os.path.join(self.paths['test_dir'], "t0027file")
        self.pattern = os.urandom(16 << 10)
        with open(self.pattern_file, "wb") as f:
            f.write(self.pattern)

    def check_result(self):
        super().check_result()

        if not self.passed:
            return

        with open(self.output_file, "rb") as f:
            data = f.read()

        if data != self.pattern:
            self.passed = False

class FioJobFileTest_t0029(FioJobFileTest):
    """Test loops option works with read-verify workload."""
    def check_result(self):
        super().check_result()

        if not self.passed:
            return

        if self.json_data['jobs'][1]['read']['io_kbytes'] != 8:
            self.passed = False

class FioJobFileTest_LogFileFormat(FioJobFileTest):
    """Test log file format"""
    def setup(self, *args, **kws):
        super().setup(*args, **kws)
        self.patterns = {}

    def check_result(self):
        super().check_result()

        if not self.passed:
            return

        for logfile in self.patterns.keys():
            file_path = os.path.join(self.paths['test_dir'], logfile)
            with open(file_path, "r") as f:
                line = f.readline()
                if not re.match(self.patterns[logfile], line):
                    self.passed = False
                    self.failure_reason = "wrong log file format: " + logfile
                    return

class FioJobFileTest_t0033(FioJobFileTest_LogFileFormat):
    """Test log file format"""
    def setup(self, *args, **kws):
        super().setup(*args, **kws)
        self.patterns = {
            'log_bw.1.log': '\\d+, \\d+, \\d+, \\d+, 0x[\\da-f]+\\n',
            'log_clat.2.log': '\\d+, \\d+, \\d+, \\d+, 0, \\d+\\n',
            'log_iops.3.log': '\\d+, \\d+, \\d+, \\d+, \\d+, 0x[\\da-f]+\\n',
            'log_iops.4.log': '\\d+, \\d+, \\d+, \\d+, 0, 0, \\d+\\n',
        }

class FioJobFileTest_t0034(FioJobFileTest_LogFileFormat):
    """Test log file format"""
    def setup(self, *args, **kws):
        super().setup(*args, **kws)
        self.patterns = {
            'log_clat.1.log': '\\d+, \\d+, \\d+, \\d+, \\d+, \\d+, \\d+\\n',
            'log_slat.1.log': '\\d+, \\d+, \\d+, \\d+, \\d+, \\d+, \\d+\\n',
            'log_lat.1.log': '\\d+, \\d+, \\d+, \\d+, \\d+, \\d+, 0\\n',
            'log_clat.2.log': '\\d+, \\d+, \\d+, \\d+, 0, 0, \\d+, 0\\n',
            'log_bw.3.log': '\\d+, \\d+, \\d+, \\d+, \\d+, \\d+, 0\\n',
            'log_iops.3.log': '\\d+, \\d+, \\d+, \\d+, \\d+, \\d+, 0\\n',
        }

class FioJobFileTest_iops_rate(FioJobFileTest):
    """Test consists of fio test job t0011
    Confirm that job0 iops == 1000
    and that job1_iops / job0_iops ~ 8
    With two runs of fio-3.16 I observed a ratio of 8.3"""

    def check_result(self):
        super().check_result()

        if not self.passed:
            return

        iops1 = self.json_data['jobs'][0]['read']['iops']
        logging.debug("Test %d: iops1: %f", self.testnum, iops1)
        iops2 = self.json_data['jobs'][1]['read']['iops']
        logging.debug("Test %d: iops2: %f", self.testnum, iops2)
        ratio = iops2 / iops1
        logging.debug("Test %d: ratio: %f", self.testnum, ratio)

        if iops1 < 950 or iops1 > 1050:
            self.failure_reason = f"{self.failure_reason} iops value mismatch,"
            self.passed = False

        if ratio < 6 or ratio > 10:
            self.failure_reason = f"{self.failure_reason} iops ratio mismatch,"
            self.passed = False


TEST_LIST = [
    {
        'test_id':          1,
        'test_class':       FioJobFileTest,
        'job':              't0001-52c58027.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'requirements':     [],
    },
    {
        'test_id':          2,
        'test_class':       FioJobFileTest,
        'job':              't0002-13af05ae-post.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          't0002-13af05ae-pre.fio',
        'pre_success':      None,
        'requirements':     [Requirements.linux, Requirements.libaio],
    },
    {
        'test_id':          3,
        'test_class':       FioJobFileTest,
        'job':              't0003-0ae2c6e1-post.fio',
        'success':          SUCCESS_NONZERO,
        'pre_job':          't0003-0ae2c6e1-pre.fio',
        'pre_success':      SUCCESS_DEFAULT,
        'requirements':     [Requirements.linux, Requirements.libaio],
    },
    {
        'test_id':          4,
        'test_class':       FioJobFileTest,
        'job':              't0004-8a99fdf6.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'requirements':     [Requirements.linux, Requirements.libaio],
    },
    {
        'test_id':          5,
        'test_class':       FioJobFileTest_t0005,
        'job':              't0005-f7078f7b.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'output_format':    'json',
        'requirements':     [Requirements.not_windows],
    },
    {
        'test_id':          6,
        'test_class':       FioJobFileTest_t0006,
        'job':              't0006-82af2a7c.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'output_format':    'json',
        'requirements':     [Requirements.linux, Requirements.libaio],
    },
    {
        'test_id':          7,
        'test_class':       FioJobFileTest_t0007,
        'job':              't0007-37cf9e3c.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'output_format':    'json',
        'requirements':     [],
    },
    {
        'test_id':          8,
        'test_class':       FioJobFileTest_t0008,
        'job':              't0008-ae2fafc8.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'output_format':    'json',
        'requirements':     [],
    },
    {
        'test_id':          9,
        'test_class':       FioJobFileTest_t0009,
        'job':              't0009-f8b0bd10.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'output_format':    'json',
        'requirements':     [Requirements.not_macos,
                             Requirements.cpucount4],
        # mac os does not support CPU affinity
    },
    {
        'test_id':          10,
        'test_class':       FioJobFileTest,
        'job':              't0010-b7aae4ba.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'requirements':     [],
    },
    {
        'test_id':          11,
        'test_class':       FioJobFileTest_iops_rate,
        'job':              't0011-5d2788d5.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'output_format':    'json',
        'requirements':     [],
    },
    {
        'test_id':          12,
        'test_class':       FioJobFileTest_t0012,
        'job':              't0012.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'output_format':    'json',
        'requirements':     [],
    },
    {
        'test_id':          13,
        'test_class':       FioJobFileTest,
        'job':              't0013.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'output_format':    'json',
        'requirements':     [],
    },
    {
        'test_id':          14,
        'test_class':       FioJobFileTest_t0014,
        'job':              't0014.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'output_format':    'json',
        'requirements':     [],
    },
    {
        'test_id':          15,
        'test_class':       FioJobFileTest_t0015,
        'job':              't0015-4e7e7898.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'output_format':    'json',
        'requirements':     [Requirements.linux, Requirements.libaio],
    },
    {
        'test_id':          16,
        'test_class':       FioJobFileTest_t0015,
        'job':              't0016-d54ae22.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'output_format':    'json',
        'requirements':     [],
    },
    {
        'test_id':          17,
        'test_class':       FioJobFileTest_t0015,
        'job':              't0017.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'output_format':    'json',
        'requirements':     [Requirements.not_windows],
    },
    {
        'test_id':          18,
        'test_class':       FioJobFileTest,
        'job':              't0018.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'requirements':     [Requirements.linux, Requirements.io_uring],
    },
    {
        'test_id':          19,
        'test_class':       FioJobFileTest_t0019,
        'job':              't0019.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'requirements':     [],
    },
    {
        'test_id':          20,
        'test_class':       FioJobFileTest_t0020,
        'job':              't0020.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'requirements':     [],
    },
    {
        'test_id':          21,
        'test_class':       FioJobFileTest_t0020,
        'job':              't0021.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'requirements':     [],
    },
    {
        'test_id':          22,
        'test_class':       FioJobFileTest_t0022,
        'job':              't0022.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'requirements':     [],
    },
    {
        'test_id':          23,
        'test_class':       FioJobFileTest_t0023,
        'job':              't0023.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'requirements':     [],
    },
    {
        'test_id':          24,
        'test_class':       FioJobFileTest_t0024,
        'job':              't0024.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'requirements':     [],
    },
    {
        'test_id':          25,
        'test_class':       FioJobFileTest_t0025,
        'job':              't0025.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'output_format':    'json',
        'requirements':     [],
    },
    {
        'test_id':          26,
        'test_class':       FioJobFileTest,
        'job':              't0026.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'requirements':     [Requirements.not_windows],
    },
    {
        'test_id':          27,
        'test_class':       FioJobFileTest_t0027,
        'job':              't0027.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'requirements':     [],
    },
    {
        'test_id':          28,
        'test_class':       FioJobFileTest,
        'job':              't0028-c6cade16.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'requirements':     [],
    },
    {
        'test_id':          29,
        'test_class':       FioJobFileTest_t0029,
        'job':              't0029.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'output_format':    'json',
        'requirements':     [],
    },
    {
        'test_id':          30,
        'test_class':       FioJobFileTest,
        'job':              't0030.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'parameters':       ['--bandwidth-log'],
        'requirements':     [],
    },
    {
        'test_id':          31,
        'test_class':       FioJobFileTest,
        'job':              't0031.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          't0031-pre.fio',
        'pre_success':      SUCCESS_DEFAULT,
        'requirements':     [Requirements.linux, Requirements.libaio],
    },
    {
        'test_id':          33,
        'test_class':       FioJobFileTest_t0033,
        'job':              't0033.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'requirements':     [Requirements.linux, Requirements.libaio],
    },
    {
        'test_id':          34,
        'test_class':       FioJobFileTest_t0034,
        'job':              't0034.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'requirements':     [Requirements.linux, Requirements.libaio],
    },
    {
        'test_id':          35,
        'test_class':       FioJobFileTest,
        'job':              't0035.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'requirements':     [],
    },
    {
        'test_id':          36,
        'test_class':       FioJobFileTest,
        'job':              't0036-post.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          't0036-pre.fio',
        'pre_success':      SUCCESS_DEFAULT,
        'requirements':     [],
    },
    {
        'test_id':          37,
        'test_class':       FioJobFileTest,
        'job':              't0037-post.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          't0037-pre.fio',
        'pre_success':      SUCCESS_DEFAULT,
        'requirements':     [Requirements.linux, Requirements.libaio],
    },
    {
        'test_id':          1000,
        'test_class':       FioExeTest,
        'exe':              't/axmap',
        'parameters':       None,
        'success':          SUCCESS_DEFAULT,
        'requirements':     [],
    },
    {
        'test_id':          1001,
        'test_class':       FioExeTest,
        'exe':              't/ieee754',
        'parameters':       None,
        'success':          SUCCESS_DEFAULT,
        'requirements':     [],
    },
    {
        'test_id':          1002,
        'test_class':       FioExeTest,
        'exe':              't/lfsr-test',
        'parameters':       ['0xFFFFFF', '0', '0', 'verify'],
        'success':          SUCCESS_STDERR,
        'requirements':     [],
    },
    {
        'test_id':          1003,
        'test_class':       FioExeTest,
        'exe':              't/readonly.py',
        'parameters':       ['-f', '{fio_path}'],
        'success':          SUCCESS_DEFAULT,
        'requirements':     [],
    },
    {
        'test_id':          1004,
        'test_class':       FioExeTest,
        'exe':              't/steadystate_tests.py',
        'parameters':       ['{fio_path}'],
        'success':          SUCCESS_DEFAULT,
        'requirements':     [],
    },
    {
        'test_id':          1005,
        'test_class':       FioExeTest,
        'exe':              't/stest',
        'parameters':       None,
        'success':          SUCCESS_STDERR,
        'requirements':     [],
    },
    {
        'test_id':          1006,
        'test_class':       FioExeTest,
        'exe':              't/strided.py',
        'parameters':       ['--fio', '{fio_path}'],
        'success':          SUCCESS_DEFAULT,
        'requirements':     [],
    },
    {
        'test_id':          1007,
        'test_class':       FioExeTest,
        'exe':              't/zbd/run-tests-against-nullb',
        'parameters':       ['-s', '1'],
        'success':          SUCCESS_DEFAULT,
        'requirements':     [Requirements.linux, Requirements.zbd,
                             Requirements.root],
    },
    {
        'test_id':          1008,
        'test_class':       FioExeTest,
        'exe':              't/zbd/run-tests-against-nullb',
        'parameters':       ['-s', '2'],
        'success':          SUCCESS_DEFAULT,
        'requirements':     [Requirements.linux, Requirements.zbd,
                             Requirements.root, Requirements.zoned_nullb],
    },
    {
        'test_id':          1009,
        'test_class':       FioExeTest,
        'exe':              'unittests/unittest',
        'parameters':       None,
        'success':          SUCCESS_DEFAULT,
        'requirements':     [Requirements.unittests],
    },
    {
        'test_id':          1010,
        'test_class':       FioExeTest,
        'exe':              't/latency_percentiles.py',
        'parameters':       ['-f', '{fio_path}'],
        'success':          SUCCESS_DEFAULT,
        'requirements':     [],
    },
    {
        'test_id':          1011,
        'test_class':       FioExeTest,
        'exe':              't/jsonplus2csv_test.py',
        'parameters':       ['-f', '{fio_path}'],
        'success':          SUCCESS_DEFAULT,
        'requirements':     [],
    },
    {
        'test_id':          1012,
        'test_class':       FioExeTest,
        'exe':              't/log_compression.py',
        'parameters':       ['-f', '{fio_path}'],
        'success':          SUCCESS_DEFAULT,
        'requirements':     [],
    },
    {
        'test_id':          1013,
        'test_class':       FioExeTest,
        'exe':              't/random_seed.py',
        'parameters':       ['-f', '{fio_path}'],
        'success':          SUCCESS_DEFAULT,
        'requirements':     [],
    },
    {
        'test_id':          1014,
        'test_class':       FioExeTest,
        'exe':              't/nvmept.py',
        'parameters':       ['-f', '{fio_path}', '--dut', '{nvmecdev}'],
        'success':          SUCCESS_DEFAULT,
        'requirements':     [Requirements.linux, Requirements.nvmecdev],
    },
    {
        'test_id':          1015,
        'test_class':       FioExeTest,
        'exe':              't/nvmept_trim.py',
        'parameters':       ['-f', '{fio_path}', '--dut', '{nvmecdev}'],
        'success':          SUCCESS_DEFAULT,
        'requirements':     [Requirements.linux, Requirements.nvmecdev],
    },
    {
        'test_id':          1016,
        'test_class':       FioExeTest,
        'exe':              't/client_server.py',
        'parameters':       ['-f', '{fio_path}'],
        'success':          SUCCESS_DEFAULT,
        'requirements':     [Requirements.linux],
    },
    {
        'test_id':          1017,
        'test_class':       FioExeTest,
        'exe':              't/verify.py',
        'parameters':       ['-f', '{fio_path}'],
        'success':          SUCCESS_LONG,
        'requirements':     [],
    },
    {
        'test_id':          1018,
        'test_class':       FioExeTest,
        'exe':              't/verify-trim.py',
        'parameters':       ['-f', '{fio_path}'],
        'success':          SUCCESS_DEFAULT,
        'requirements':     [Requirements.linux],
    },
    {
        'test_id':          1019,
        'test_class':       FioExeTest,
        'exe':              't/sprandom.py',
        'parameters':       ['-f', '{fio_path}'],
        'success':          SUCCESS_DEFAULT,
        'requirements':     [Requirements.linux, Requirements.libaio],
    },
]


def parse_args():
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--fio-root',
                        help='fio root path')
    parser.add_argument('-f', '--fio',
                        help='path to fio executable (e.g., ./fio)')
    parser.add_argument('-a', '--artifact-root',
                        help='artifact root directory')
    parser.add_argument('-s', '--skip', nargs='+', type=int,
                        help='list of test(s) to skip')
    parser.add_argument('-o', '--run-only', nargs='+', type=int,
                        help='list of test(s) to run, skipping all others')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='provide debug output')
    parser.add_argument('-k', '--skip-req', action='store_true',
                        help='skip requirements checking')
    parser.add_argument('-p', '--pass-through', action='append',
                        help='pass-through an argument to an executable test')
    parser.add_argument('--nvmecdev', action='store', default=None,
                        help='NVMe character device for **DESTRUCTIVE** testing (e.g., /dev/ng0n1)')
    parser.add_argument('-c', '--cleanup', action='store_true', default=False,
                        help='Delete artifacts for passing tests')
    args = parser.parse_args()

    return args


def main():
    """Entry point."""

    args = parse_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    pass_through = {}
    if args.pass_through:
        for arg in args.pass_through:
            if not ':' in arg:
                print(f"Invalid --pass-through argument '{arg}'")
                print("Syntax for --pass-through is TESTNUMBER:ARGUMENT")
                return
            split = arg.split(":", 1)
            pass_through[int(split[0])] = split[1]
        logging.debug("Pass-through arguments: %s", pass_through)

    if args.fio_root:
        fio_root = args.fio_root
    else:
        fio_root = str(Path(__file__).absolute().parent.parent)
    print(f"fio root is {fio_root}")

    if args.fio:
        fio_path = args.fio
    else:
        if platform.system() == "Windows":
            fio_exe = "fio.exe"
        else:
            fio_exe = "fio"
        fio_path = os.path.join(fio_root, fio_exe)
    print(f"fio path is {fio_path}")
    if not shutil.which(fio_path):
        print("Warning: fio executable not found")

    artifact_root = args.artifact_root if args.artifact_root else \
        f"fio-test-{time.strftime('%Y%m%d-%H%M%S')}"
    os.mkdir(artifact_root)
    print(f"Artifact directory is {artifact_root}")

    if not args.skip_req:
        Requirements(fio_root, args)

    test_env = {
              'fio_path': fio_path,
              'fio_root': fio_root,
              'artifact_root': artifact_root,
              'pass_through': pass_through,
              }
    _, failed, _ = run_fio_tests(TEST_LIST, test_env, args)
    sys.exit(failed)


if __name__ == '__main__':
    main()
