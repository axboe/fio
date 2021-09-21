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
# # git clone git://git.kernel.dk/fio.git
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
import json
import time
import shutil
import logging
import argparse
import platform
import traceback
import subprocess
import multiprocessing
from pathlib import Path


class FioTest(object):
    """Base for all fio tests."""

    def __init__(self, exe_path, parameters, success):
        self.exe_path = exe_path
        self.parameters = parameters
        self.success = success
        self.output = {}
        self.artifact_root = None
        self.testnum = None
        self.test_dir = None
        self.passed = True
        self.failure_reason = ''
        self.command_file = None
        self.stdout_file = None
        self.stderr_file = None
        self.exitcode_file = None

    def setup(self, artifact_root, testnum):
        """Setup instance variables for test."""

        self.artifact_root = artifact_root
        self.testnum = testnum
        self.test_dir = os.path.join(artifact_root, "{:04d}".format(testnum))
        if not os.path.exists(self.test_dir):
            os.mkdir(self.test_dir)

        self.command_file = os.path.join(
            self.test_dir,
            "{0}.command".format(os.path.basename(self.exe_path)))
        self.stdout_file = os.path.join(
            self.test_dir,
            "{0}.stdout".format(os.path.basename(self.exe_path)))
        self.stderr_file = os.path.join(
            self.test_dir,
            "{0}.stderr".format(os.path.basename(self.exe_path)))
        self.exitcode_file = os.path.join(
            self.test_dir,
            "{0}.exitcode".format(os.path.basename(self.exe_path)))

    def run(self):
        """Run the test."""

        raise NotImplementedError()

    def check_result(self):
        """Check test results."""

        raise NotImplementedError()


class FioExeTest(FioTest):
    """Test consists of an executable binary or script"""

    def __init__(self, exe_path, parameters, success):
        """Construct a FioExeTest which is a FioTest consisting of an
        executable binary or script.

        exe_path:       location of executable binary or script
        parameters:     list of parameters for executable
        success:        Definition of test success
        """

        FioTest.__init__(self, exe_path, parameters, success)

    def run(self):
        """Execute the binary or script described by this instance."""

        command = [self.exe_path] + self.parameters
        command_file = open(self.command_file, "w+")
        command_file.write("%s\n" % command)
        command_file.close()

        stdout_file = open(self.stdout_file, "w+")
        stderr_file = open(self.stderr_file, "w+")
        exitcode_file = open(self.exitcode_file, "w+")
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
            proc.communicate(timeout=self.success['timeout'])
            exitcode_file.write('{0}\n'.format(proc.returncode))
            logging.debug("Test %d: return code: %d", self.testnum, proc.returncode)
            self.output['proc'] = proc
        except subprocess.TimeoutExpired:
            proc.terminate()
            proc.communicate()
            assert proc.poll()
            self.output['failure'] = 'timeout'
        except Exception:
            if proc:
                if not proc.poll():
                    proc.terminate()
                    proc.communicate()
            self.output['failure'] = 'exception'
            self.output['exc_info'] = sys.exc_info()
        finally:
            stdout_file.close()
            stderr_file.close()
            exitcode_file.close()

    def check_result(self):
        """Check results of test run."""

        if 'proc' not in self.output:
            if self.output['failure'] == 'timeout':
                self.failure_reason = "{0} timeout,".format(self.failure_reason)
            else:
                assert self.output['failure'] == 'exception'
                self.failure_reason = '{0} exception: {1}, {2}'.format(
                    self.failure_reason, self.output['exc_info'][0],
                    self.output['exc_info'][1])

            self.passed = False
            return

        if 'zero_return' in self.success:
            if self.success['zero_return']:
                if self.output['proc'].returncode != 0:
                    self.passed = False
                    self.failure_reason = "{0} non-zero return code,".format(self.failure_reason)
            else:
                if self.output['proc'].returncode == 0:
                    self.failure_reason = "{0} zero return code,".format(self.failure_reason)
                    self.passed = False

        stderr_size = os.path.getsize(self.stderr_file)
        if 'stderr_empty' in self.success:
            if self.success['stderr_empty']:
                if stderr_size != 0:
                    self.failure_reason = "{0} stderr not empty,".format(self.failure_reason)
                    self.passed = False
            else:
                if stderr_size == 0:
                    self.failure_reason = "{0} stderr empty,".format(self.failure_reason)
                    self.passed = False


class FioJobTest(FioExeTest):
    """Test consists of a fio job"""

    def __init__(self, fio_path, fio_job, success, fio_pre_job=None,
                 fio_pre_success=None, output_format="normal"):
        """Construct a FioJobTest which is a FioExeTest consisting of a
        single fio job file with an optional setup step.

        fio_path:           location of fio executable
        fio_job:            location of fio job file
        success:            Definition of test success
        fio_pre_job:        fio job for preconditioning
        fio_pre_success:    Definition of test success for fio precon job
        output_format:      normal (default), json, jsonplus, or terse
        """

        self.fio_job = fio_job
        self.fio_pre_job = fio_pre_job
        self.fio_pre_success = fio_pre_success if fio_pre_success else success
        self.output_format = output_format
        self.precon_failed = False
        self.json_data = None
        self.fio_output = "{0}.output".format(os.path.basename(self.fio_job))
        self.fio_args = [
            "--max-jobs=16",
            "--output-format={0}".format(self.output_format),
            "--output={0}".format(self.fio_output),
            self.fio_job,
            ]
        FioExeTest.__init__(self, fio_path, self.fio_args, success)

    def setup(self, artifact_root, testnum):
        """Setup instance variables for fio job test."""

        super(FioJobTest, self).setup(artifact_root, testnum)

        self.command_file = os.path.join(
            self.test_dir,
            "{0}.command".format(os.path.basename(self.fio_job)))
        self.stdout_file = os.path.join(
            self.test_dir,
            "{0}.stdout".format(os.path.basename(self.fio_job)))
        self.stderr_file = os.path.join(
            self.test_dir,
            "{0}.stderr".format(os.path.basename(self.fio_job)))
        self.exitcode_file = os.path.join(
            self.test_dir,
            "{0}.exitcode".format(os.path.basename(self.fio_job)))

    def run_pre_job(self):
        """Run fio job precondition step."""

        precon = FioJobTest(self.exe_path, self.fio_pre_job,
                            self.fio_pre_success,
                            output_format=self.output_format)
        precon.setup(self.artifact_root, self.testnum)
        precon.run()
        precon.check_result()
        self.precon_failed = not precon.passed
        self.failure_reason = precon.failure_reason

    def run(self):
        """Run fio job test."""

        if self.fio_pre_job:
            self.run_pre_job()

        if not self.precon_failed:
            super(FioJobTest, self).run()
        else:
            logging.debug("Test %d: precondition step failed", self.testnum)

    @classmethod
    def get_file(cls, filename):
        """Safely read a file."""
        file_data = ''
        success = True

        try:
            with open(filename, "r") as output_file:
                file_data = output_file.read()
        except OSError:
            success = False

        return file_data, success

    def check_result(self):
        """Check fio job results."""

        if self.precon_failed:
            self.passed = False
            self.failure_reason = "{0} precondition step failed,".format(self.failure_reason)
            return

        super(FioJobTest, self).check_result()

        if not self.passed:
            return

        if 'json' not in self.output_format:
            return

        file_data, success = self.get_file(os.path.join(self.test_dir, self.fio_output))
        if not success:
            self.failure_reason = "{0} unable to open output file,".format(self.failure_reason)
            self.passed = False
            return

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
                logging.debug("Test %d: skipped %d lines decoding JSON data", self.testnum, i)
                return

        self.failure_reason = "{0} unable to decode JSON data,".format(self.failure_reason)
        self.passed = False


class FioJobTest_t0005(FioJobTest):
    """Test consists of fio test job t0005
    Confirm that read['io_kbytes'] == write['io_kbytes'] == 102400"""

    def check_result(self):
        super(FioJobTest_t0005, self).check_result()

        if not self.passed:
            return

        if self.json_data['jobs'][0]['read']['io_kbytes'] != 102400:
            self.failure_reason = "{0} bytes read mismatch,".format(self.failure_reason)
            self.passed = False
        if self.json_data['jobs'][0]['write']['io_kbytes'] != 102400:
            self.failure_reason = "{0} bytes written mismatch,".format(self.failure_reason)
            self.passed = False


class FioJobTest_t0006(FioJobTest):
    """Test consists of fio test job t0006
    Confirm that read['io_kbytes'] ~ 2*write['io_kbytes']"""

    def check_result(self):
        super(FioJobTest_t0006, self).check_result()

        if not self.passed:
            return

        ratio = self.json_data['jobs'][0]['read']['io_kbytes'] \
            / self.json_data['jobs'][0]['write']['io_kbytes']
        logging.debug("Test %d: ratio: %f", self.testnum, ratio)
        if ratio < 1.99 or ratio > 2.01:
            self.failure_reason = "{0} read/write ratio mismatch,".format(self.failure_reason)
            self.passed = False


class FioJobTest_t0007(FioJobTest):
    """Test consists of fio test job t0007
    Confirm that read['io_kbytes'] = 87040"""

    def check_result(self):
        super(FioJobTest_t0007, self).check_result()

        if not self.passed:
            return

        if self.json_data['jobs'][0]['read']['io_kbytes'] != 87040:
            self.failure_reason = "{0} bytes read mismatch,".format(self.failure_reason)
            self.passed = False


class FioJobTest_t0008(FioJobTest):
    """Test consists of fio test job t0008
    Confirm that read['io_kbytes'] = 32768 and that
                write['io_kbytes'] ~ 16568

    I did runs with fio-ae2fafc8 and saw write['io_kbytes'] values of
    16585, 16588. With two runs of fio-3.16 I obtained 16568"""

    def check_result(self):
        super(FioJobTest_t0008, self).check_result()

        if not self.passed:
            return

        ratio = self.json_data['jobs'][0]['write']['io_kbytes'] / 16568
        logging.debug("Test %d: ratio: %f", self.testnum, ratio)

        if ratio < 0.99 or ratio > 1.01:
            self.failure_reason = "{0} bytes written mismatch,".format(self.failure_reason)
            self.passed = False
        if self.json_data['jobs'][0]['read']['io_kbytes'] != 32768:
            self.failure_reason = "{0} bytes read mismatch,".format(self.failure_reason)
            self.passed = False


class FioJobTest_t0009(FioJobTest):
    """Test consists of fio test job t0009
    Confirm that runtime >= 60s"""

    def check_result(self):
        super(FioJobTest_t0009, self).check_result()

        if not self.passed:
            return

        logging.debug('Test %d: elapsed: %d', self.testnum, self.json_data['jobs'][0]['elapsed'])

        if self.json_data['jobs'][0]['elapsed'] < 60:
            self.failure_reason = "{0} elapsed time mismatch,".format(self.failure_reason)
            self.passed = False


class FioJobTest_t0012(FioJobTest):
    """Test consists of fio test job t0012
    Confirm ratios of job iops are 1:5:10
    job1,job2,job3 respectively"""

    def check_result(self):
        super(FioJobTest_t0012, self).check_result()

        if not self.passed:
            return

        iops_files = []
        for i in range(1,4):
            file_data, success = self.get_file(os.path.join(self.test_dir, "{0}_iops.{1}.log".format(os.path.basename(self.fio_job), i)))

            if not success:
                self.failure_reason = "{0} unable to open output file,".format(self.failure_reason)
                self.passed = False
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
            logging.debug(
                "sample {0}: job1 iops={1} job2 iops={2} job3 iops={3} job3/job2={4:.3f} job3/job1={5:.3f}".format(
                    i, iops1, iops2, iops3, ratio1, ratio2
                )
            )

        # test job1 and job2 succeeded to recalibrate
        if ratio1 < 1 or ratio1 > 3 or ratio2 < 7 or ratio2 > 13:
            self.failure_reason = "{0} iops ratio mismatch iops1={1} iops2={2} iops3={3} expected r1~2 r2~10 got r1={4:.3f} r2={5:.3f},".format(
                self.failure_reason, iops1, iops2, iops3, ratio1, ratio2
            )
            self.passed = False
            return


class FioJobTest_t0014(FioJobTest):
    """Test consists of fio test job t0014
	Confirm that job1_iops / job2_iops ~ 1:2 for entire duration
	and that job1_iops / job3_iops ~ 1:3 for first half of duration.

    The test is about making sure the flow feature can
    re-calibrate the activity dynamically"""

    def check_result(self):
        super(FioJobTest_t0014, self).check_result()

        if not self.passed:
            return

        iops_files = []
        for i in range(1,4):
            file_data, success = self.get_file(os.path.join(self.test_dir, "{0}_iops.{1}.log".format(os.path.basename(self.fio_job), i)))

            if not success:
                self.failure_reason = "{0} unable to open output file,".format(self.failure_reason)
                self.passed = False
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
                    self.failure_reason = "{0} iops ratio mismatch iops1={1} iops2={2} iops3={3}\
                                                expected r1~0.5 r2~0.33 got r1={4:.3f} r2={5:.3f},".format(
                        self.failure_reason, iops1, iops2, iops3, ratio1, ratio2
                    )
                    self.passed = False

            iops1 = iops1 + float(iops_files[0][i].split(',')[1])
            iops2 = iops2 + float(iops_files[1][i].split(',')[1])

            ratio1 = iops1/iops2
            ratio2 = iops1/iops3
            logging.debug(
                "sample {0}: job1 iops={1} job2 iops={2} job3 iops={3} job1/job2={4:.3f} job1/job3={5:.3f}".format(
                    i, iops1, iops2, iops3, ratio1, ratio2
                )
            )

        # test job1 and job2 succeeded to recalibrate
        if ratio1 < 0.43 or ratio1 > 0.57:
            self.failure_reason = "{0} iops ratio mismatch iops1={1} iops2={2} expected ratio~0.5 got ratio={3:.3f},".format(
                self.failure_reason, iops1, iops2, ratio1
            )
            self.passed = False
            return


class FioJobTest_iops_rate(FioJobTest):
    """Test consists of fio test job t0009
    Confirm that job0 iops == 1000
    and that job1_iops / job0_iops ~ 8
    With two runs of fio-3.16 I observed a ratio of 8.3"""

    def check_result(self):
        super(FioJobTest_iops_rate, self).check_result()

        if not self.passed:
            return

        iops1 = self.json_data['jobs'][0]['read']['iops']
        iops2 = self.json_data['jobs'][1]['read']['iops']
        ratio = iops2 / iops1
        logging.debug("Test %d: iops1: %f", self.testnum, iops1)
        logging.debug("Test %d: ratio: %f", self.testnum, ratio)

        if iops1 < 950 or iops1 > 1050:
            self.failure_reason = "{0} iops value mismatch,".format(self.failure_reason)
            self.passed = False

        if ratio < 6 or ratio > 10:
            self.failure_reason = "{0} iops ratio mismatch,".format(self.failure_reason)
            self.passed = False


class Requirements(object):
    """Requirements consists of multiple run environment characteristics.
    These are to determine if a particular test can be run"""

    _linux = False
    _libaio = False
    _zbd = False
    _root = False
    _zoned_nullb = False
    _not_macos = False
    _not_windows = False
    _unittests = False
    _cpucount4 = False

    def __init__(self, fio_root):
        Requirements._not_macos = platform.system() != "Darwin"
        Requirements._not_windows = platform.system() != "Windows"
        Requirements._linux = platform.system() == "Linux"

        if Requirements._linux:
            config_file = os.path.join(fio_root, "config-host.h")
            contents, success = FioJobTest.get_file(config_file)
            if not success:
                print("Unable to open {0} to check requirements".format(config_file))
                Requirements._zbd = True
            else:
                Requirements._zbd = "CONFIG_HAS_BLKZONED" in contents
                Requirements._libaio = "CONFIG_LIBAIO" in contents

            Requirements._root = (os.geteuid() == 0)
            if Requirements._zbd and Requirements._root:
                try:
                    subprocess.run(["modprobe", "null_blk"],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
                    if os.path.exists("/sys/module/null_blk/parameters/zoned"):
                        Requirements._zoned_nullb = True
                except Exception:
                    pass

        if platform.system() == "Windows":
            utest_exe = "unittest.exe"
        else:
            utest_exe = "unittest"
        unittest_path = os.path.join(fio_root, "unittests", utest_exe)
        Requirements._unittests = os.path.exists(unittest_path)

        Requirements._cpucount4 = multiprocessing.cpu_count() >= 4

        req_list = [Requirements.linux,
                    Requirements.libaio,
                    Requirements.zbd,
                    Requirements.root,
                    Requirements.zoned_nullb,
                    Requirements.not_macos,
                    Requirements.not_windows,
                    Requirements.unittests,
                    Requirements.cpucount4]
        for req in req_list:
            value, desc = req()
            logging.debug("Requirements: Requirement '%s' met? %s", desc, value)

    @classmethod
    def linux(cls):
        """Are we running on Linux?"""
        return Requirements._linux, "Linux required"

    @classmethod
    def libaio(cls):
        """Is libaio available?"""
        return Requirements._libaio, "libaio required"

    @classmethod
    def zbd(cls):
        """Is ZBD support available?"""
        return Requirements._zbd, "Zoned block device support required"

    @classmethod
    def root(cls):
        """Are we running as root?"""
        return Requirements._root, "root required"

    @classmethod
    def zoned_nullb(cls):
        """Are zoned null block devices available?"""
        return Requirements._zoned_nullb, "Zoned null block device support required"

    @classmethod
    def not_macos(cls):
        """Are we running on a platform other than macOS?"""
        return Requirements._not_macos, "platform other than macOS required"

    @classmethod
    def not_windows(cls):
        """Are we running on a platform other than Windws?"""
        return Requirements._not_windows, "platform other than Windows required"

    @classmethod
    def unittests(cls):
        """Were unittests built?"""
        return Requirements._unittests, "Unittests support required"

    @classmethod
    def cpucount4(cls):
        """Do we have at least 4 CPUs?"""
        return Requirements._cpucount4, "4+ CPUs required"


SUCCESS_DEFAULT = {
    'zero_return': True,
    'stderr_empty': True,
    'timeout': 600,
    }
SUCCESS_NONZERO = {
    'zero_return': False,
    'stderr_empty': False,
    'timeout': 600,
    }
SUCCESS_STDERR = {
    'zero_return': True,
    'stderr_empty': False,
    'timeout': 600,
    }
TEST_LIST = [
    {
        'test_id':          1,
        'test_class':       FioJobTest,
        'job':              't0001-52c58027.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'requirements':     [],
    },
    {
        'test_id':          2,
        'test_class':       FioJobTest,
        'job':              't0002-13af05ae-post.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          't0002-13af05ae-pre.fio',
        'pre_success':      None,
        'requirements':     [Requirements.linux, Requirements.libaio],
    },
    {
        'test_id':          3,
        'test_class':       FioJobTest,
        'job':              't0003-0ae2c6e1-post.fio',
        'success':          SUCCESS_NONZERO,
        'pre_job':          't0003-0ae2c6e1-pre.fio',
        'pre_success':      SUCCESS_DEFAULT,
        'requirements':     [Requirements.linux, Requirements.libaio],
    },
    {
        'test_id':          4,
        'test_class':       FioJobTest,
        'job':              't0004-8a99fdf6.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'requirements':     [Requirements.linux, Requirements.libaio],
    },
    {
        'test_id':          5,
        'test_class':       FioJobTest_t0005,
        'job':              't0005-f7078f7b.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'output_format':    'json',
        'requirements':     [Requirements.not_windows],
    },
    {
        'test_id':          6,
        'test_class':       FioJobTest_t0006,
        'job':              't0006-82af2a7c.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'output_format':    'json',
        'requirements':     [Requirements.linux, Requirements.libaio],
    },
    {
        'test_id':          7,
        'test_class':       FioJobTest_t0007,
        'job':              't0007-37cf9e3c.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'output_format':    'json',
        'requirements':     [],
    },
    {
        'test_id':          8,
        'test_class':       FioJobTest_t0008,
        'job':              't0008-ae2fafc8.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'output_format':    'json',
        'requirements':     [],
    },
    {
        'test_id':          9,
        'test_class':       FioJobTest_t0009,
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
        'test_class':       FioJobTest,
        'job':              't0010-b7aae4ba.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'requirements':     [],
    },
    {
        'test_id':          11,
        'test_class':       FioJobTest_iops_rate,
        'job':              't0011-5d2788d5.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'output_format':    'json',
        'requirements':     [],
    },
    {
        'test_id':          12,
        'test_class':       FioJobTest_t0012,
        'job':              't0012.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'output_format':    'json',
        'requirements':     [],
    },
    {
        'test_id':          13,
        'test_class':       FioJobTest,
        'job':              't0013.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'output_format':    'json',
        'requirements':     [],
    },
    {
        'test_id':          14,
        'test_class':       FioJobTest_t0014,
        'job':              't0014.fio',
        'success':          SUCCESS_DEFAULT,
        'pre_job':          None,
        'pre_success':      None,
        'output_format':    'json',
        'requirements':     [],
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
        'parameters':       ['{fio_path}'],
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
                print("Invalid --pass-through argument '%s'" % arg)
                print("Syntax for --pass-through is TESTNUMBER:ARGUMENT")
                return
            split = arg.split(":", 1)
            pass_through[int(split[0])] = split[1]
        logging.debug("Pass-through arguments: %s", pass_through)

    if args.fio_root:
        fio_root = args.fio_root
    else:
        fio_root = str(Path(__file__).absolute().parent.parent)
    print("fio root is %s" % fio_root)

    if args.fio:
        fio_path = args.fio
    else:
        if platform.system() == "Windows":
            fio_exe = "fio.exe"
        else:
            fio_exe = "fio"
        fio_path = os.path.join(fio_root, fio_exe)
    print("fio path is %s" % fio_path)
    if not shutil.which(fio_path):
        print("Warning: fio executable not found")

    artifact_root = args.artifact_root if args.artifact_root else \
        "fio-test-{0}".format(time.strftime("%Y%m%d-%H%M%S"))
    os.mkdir(artifact_root)
    print("Artifact directory is %s" % artifact_root)

    if not args.skip_req:
        req = Requirements(fio_root)

    passed = 0
    failed = 0
    skipped = 0

    for config in TEST_LIST:
        if (args.skip and config['test_id'] in args.skip) or \
           (args.run_only and config['test_id'] not in args.run_only):
            skipped = skipped + 1
            print("Test {0} SKIPPED (User request)".format(config['test_id']))
            continue

        if issubclass(config['test_class'], FioJobTest):
            if config['pre_job']:
                fio_pre_job = os.path.join(fio_root, 't', 'jobs',
                                           config['pre_job'])
            else:
                fio_pre_job = None
            if config['pre_success']:
                fio_pre_success = config['pre_success']
            else:
                fio_pre_success = None
            if 'output_format' in config:
                output_format = config['output_format']
            else:
                output_format = 'normal'
            test = config['test_class'](
                fio_path,
                os.path.join(fio_root, 't', 'jobs', config['job']),
                config['success'],
                fio_pre_job=fio_pre_job,
                fio_pre_success=fio_pre_success,
                output_format=output_format)
            desc = config['job']
        elif issubclass(config['test_class'], FioExeTest):
            exe_path = os.path.join(fio_root, config['exe'])
            if config['parameters']:
                parameters = [p.format(fio_path=fio_path) for p in config['parameters']]
            else:
                parameters = []
            if Path(exe_path).suffix == '.py' and platform.system() == "Windows":
                parameters.insert(0, exe_path)
                exe_path = "python.exe"
            if config['test_id'] in pass_through:
                parameters += pass_through[config['test_id']].split()
            test = config['test_class'](exe_path, parameters,
                                        config['success'])
            desc = config['exe']
        else:
            print("Test {0} FAILED: unable to process test config".format(config['test_id']))
            failed = failed + 1
            continue

        if not args.skip_req:
            reqs_met = True
            for req in config['requirements']:
                reqs_met, reason = req()
                logging.debug("Test %d: Requirement '%s' met? %s", config['test_id'], reason,
                              reqs_met)
                if not reqs_met:
                    break
            if not reqs_met:
                print("Test {0} SKIPPED ({1}) {2}".format(config['test_id'], reason, desc))
                skipped = skipped + 1
                continue

        try:
            test.setup(artifact_root, config['test_id'])
            test.run()
            test.check_result()
        except KeyboardInterrupt:
            break
        except Exception as e:
            test.passed = False
            test.failure_reason += str(e)
            logging.debug("Test %d exception:\n%s\n", config['test_id'], traceback.format_exc())
        if test.passed:
            result = "PASSED"
            passed = passed + 1
        else:
            result = "FAILED: {0}".format(test.failure_reason)
            failed = failed + 1
            contents, _ = FioJobTest.get_file(test.stderr_file)
            logging.debug("Test %d: stderr:\n%s", config['test_id'], contents)
            contents, _ = FioJobTest.get_file(test.stdout_file)
            logging.debug("Test %d: stdout:\n%s", config['test_id'], contents)
        print("Test {0} {1} {2}".format(config['test_id'], result, desc))

    print("{0} test(s) passed, {1} failed, {2} skipped".format(passed, failed, skipped))

    sys.exit(failed)


if __name__ == '__main__':
    main()
