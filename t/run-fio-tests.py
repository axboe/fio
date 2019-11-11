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
# - Python 3
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
# TODO  automatically detect dependencies and skip tests accordingly
#

import os
import sys
import json
import time
import logging
import argparse
import subprocess
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

    def setup(self, artifact_root, testnum):
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
        self.exticode_file = os.path.join(
                self.test_dir,
                "{0}.exitcode".format(os.path.basename(self.exe_path)))

    def run(self):
        raise NotImplementedError()

    def check_result(self):
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

    def setup(self, artifact_root, testnum):
        super(FioExeTest, self).setup(artifact_root, testnum)

    def run(self):
        if self.parameters:
            command = [self.exe_path] + self.parameters
        else:
            command = [self.exe_path]
        command_file = open(self.command_file, "w+")
        command_file.write("%s\n" % command)
        command_file.close()

        stdout_file = open(self.stdout_file, "w+")
        stderr_file = open(self.stderr_file, "w+")
        exticode_file = open(self.exticode_file, "w+")
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
            exticode_file.write('{0}\n'.format(proc.returncode))
            logging.debug("return code: %d" % proc.returncode)
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
            exticode_file.close()

    def check_result(self):
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

        if 'stderr_empty' in self.success:
            stderr_size = os.path.getsize(self.stderr_file)
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
            "--output-format={0}".format(self.output_format),
            "--output={0}".format(self.fio_output),
            self.fio_job,
            ]
        FioExeTest.__init__(self, fio_path, self.fio_args, success)

    def setup(self, artifact_root, testnum):
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
        self.exticode_file = os.path.join(
                self.test_dir,
                "{0}.exitcode".format(os.path.basename(self.fio_job)))

    def run_pre_job(self):
        precon = FioJobTest(self.exe_path, self.fio_pre_job,
                            self.fio_pre_success,
                            output_format=self.output_format)
        precon.setup(self.artifact_root, self.testnum)
        precon.run()
        precon.check_result()
        self.precon_failed = not precon.passed
        self.failure_reason = precon.failure_reason

    def run(self):
        if self.fio_pre_job:
            self.run_pre_job()

        if not self.precon_failed:
            super(FioJobTest, self).run()
        else:
            logging.debug("precondition step failed")

    def check_result(self):
        if self.precon_failed:
            self.passed = False
            self.failure_reason = "{0} precondition step failed,".format(self.failure_reason)
            return

        super(FioJobTest, self).check_result()

        if 'json' in self.output_format:
            output_file = open(os.path.join(self.test_dir, self.fio_output), "r")
            file_data = output_file.read()
            output_file.close()
            try:
                self.json_data = json.loads(file_data)
            except json.JSONDecodeError:
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
        logging.debug("ratio: %f" % ratio)
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
        logging.debug("ratio: %f" % ratio)

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

        logging.debug('elapsed: %d' % self.json_data['jobs'][0]['elapsed'])

        if self.json_data['jobs'][0]['elapsed'] < 60:
            self.failure_reason = "{0} elapsed time mismatch,".format(self.failure_reason)
            self.passed = False


class FioJobTest_t0011(FioJobTest):
    """Test consists of fio test job t0009
    Confirm that job0 iops == 1000
    and that job1_iops / job0_iops ~ 8
    With two runs of fio-3.16 I observed a ratio of 8.3"""

    def check_result(self):
        super(FioJobTest_t0011, self).check_result()

        if not self.passed:
            return

        iops1 = self.json_data['jobs'][0]['read']['iops']
        iops2 = self.json_data['jobs'][1]['read']['iops']
        ratio = iops2 / iops1
        logging.debug("ratio: %f" % ratio)

        if iops1 < 999 or iops1 > 1001:
            self.failure_reason = "{0} iops value mismatch,".format(self.failure_reason)
            self.passed = False

        if ratio < 7 or ratio > 9:
            self.failure_reason = "{0} iops ratio mismatch,".format(self.failure_reason)
            self.passed = False


SUCCESS_DEFAULT = {
        'zero_return': True,
        'stderr_empty': True,
        'timeout': 300,
        }
SUCCESS_NONZERO = {
        'zero_return': False,
        'stderr_empty': False,
        'timeout': 300,
        }
SUCCESS_STDERR = {
        'zero_return': True,
        'stderr_empty': False,
        'timeout': 300,
        }
TEST_LIST = [
        {
            'test_id':          1,
            'test_class':       FioJobTest,
            'job':              't0001-52c58027.fio',
            'success':          SUCCESS_DEFAULT,
            'pre_job':          None,
            'pre_success':      None,
        },
        {
            'test_id':          2,
            'test_class':       FioJobTest,
            'job':              't0002-13af05ae-post.fio',
            'success':          SUCCESS_DEFAULT,
            'pre_job':          't0002-13af05ae-pre.fio',
            'pre_success':      None,
        },
        {
            'test_id':          3,
            'test_class':       FioJobTest,
            'job':              't0003-0ae2c6e1-post.fio',
            'success':          SUCCESS_NONZERO,
            'pre_job':          't0003-0ae2c6e1-pre.fio',
            'pre_success':      SUCCESS_DEFAULT,
        },
        {
            'test_id':          4,
            'test_class':       FioJobTest,
            'job':              't0004-8a99fdf6.fio',
            'success':          SUCCESS_DEFAULT,
            'pre_job':          None,
            'pre_success':      None,
        },
        {
            'test_id':          5,
            'test_class':       FioJobTest_t0005,
            'job':              't0005-f7078f7b.fio',
            'success':          SUCCESS_DEFAULT,
            'pre_job':          None,
            'pre_success':      None,
            'output_format':    'json',
        },
        {
            'test_id':          6,
            'test_class':       FioJobTest_t0006,
            'job':              't0006-82af2a7c.fio',
            'success':          SUCCESS_DEFAULT,
            'pre_job':          None,
            'pre_success':      None,
            'output_format':    'json',
        },
        {
            'test_id':          7,
            'test_class':       FioJobTest_t0007,
            'job':              't0007-37cf9e3c.fio',
            'success':          SUCCESS_DEFAULT,
            'pre_job':          None,
            'pre_success':      None,
            'output_format':    'json',
        },
        {
            'test_id':          8,
            'test_class':       FioJobTest_t0008,
            'job':              't0008-ae2fafc8.fio',
            'success':          SUCCESS_DEFAULT,
            'pre_job':          None,
            'pre_success':      None,
            'output_format':    'json',
        },
        {
            'test_id':          9,
            'test_class':       FioJobTest_t0009,
            'job':              't0009-f8b0bd10.fio',
            'success':          SUCCESS_DEFAULT,
            'pre_job':          None,
            'pre_success':      None,
            'output_format':    'json',
        },
        {
            'test_id':          10,
            'test_class':       FioJobTest,
            'job':              't0010-b7aae4ba.fio',
            'success':          SUCCESS_DEFAULT,
            'pre_job':          None,
            'pre_success':      None,
        },
        {
            'test_id':          11,
            'test_class':       FioJobTest_t0011,
            'job':              't0011-5d2788d5.fio',
            'success':          SUCCESS_DEFAULT,
            'pre_job':          None,
            'pre_success':      None,
            'output_format':    'json',
        },
        {
            'test_id':          1000,
            'test_class':       FioExeTest,
            'exe':              't/axmap',
            'parameters':       None,
            'success':          SUCCESS_DEFAULT,
        },
        {
            'test_id':          1001,
            'test_class':       FioExeTest,
            'exe':              't/ieee754',
            'parameters':       None,
            'success':          SUCCESS_DEFAULT,
        },
        {
            'test_id':          1002,
            'test_class':       FioExeTest,
            'exe':              't/lfsr-test',
            'parameters':       ['0xFFFFFF', '0', '0', 'verify'],
            'success':          SUCCESS_STDERR,
        },
        {
            'test_id':          1003,
            'test_class':       FioExeTest,
            'exe':              't/readonly.py',
            'parameters':       ['-f', '{fio_path}'],
            'success':          SUCCESS_DEFAULT,
        },
        {
            'test_id':          1004,
            'test_class':       FioExeTest,
            'exe':              't/steadystate_tests.py',
            'parameters':       ['{fio_path}'],
            'success':          SUCCESS_DEFAULT,
        },
        {
            'test_id':          1005,
            'test_class':       FioExeTest,
            'exe':              't/stest',
            'parameters':       None,
            'success':          SUCCESS_STDERR,
        },
        {
            'test_id':          1006,
            'test_class':       FioExeTest,
            'exe':              't/strided.py',
            'parameters':       ['{fio_path}'],
            'success':          SUCCESS_DEFAULT,
        },
        {
            'test_id':          1007,
            'test_class':       FioExeTest,
            'exe':              't/zbd/run-tests-against-regular-nullb',
            'parameters':       None,
            'success':          SUCCESS_DEFAULT,
        },
        {
            'test_id':          1008,
            'test_class':       FioExeTest,
            'exe':              't/zbd/run-tests-against-zoned-nullb',
            'parameters':       None,
            'success':          SUCCESS_DEFAULT,
        },
        {
            'test_id':          1009,
            'test_class':       FioExeTest,
            'exe':              'unittests/unittest',
            'parameters':       None,
            'success':          SUCCESS_DEFAULT,
        },
]


def parse_args():
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
    args = parser.parse_args()

    return args


def main():
    logging.basicConfig(level=logging.INFO)

    args = parse_args()
    if args.fio_root:
        fio_root = args.fio_root
    else:
        fio_root = Path(__file__).absolute().parent.parent
    logging.debug("fio_root: %s" % fio_root)

    if args.fio:
        fio_path = args.fio
    else:
        fio_path = os.path.join(fio_root, "fio")
    logging.debug("fio_path: %s" % fio_path)

    artifact_root = args.artifact_root if args.artifact_root else \
        "fio-test-{0}".format(time.strftime("%Y%m%d-%H%M%S"))
    os.mkdir(artifact_root)
    print("Artifact directory is %s" % artifact_root)

    passed = 0
    failed = 0
    skipped = 0

    for config in TEST_LIST:
        if (args.skip and config['test_id'] in args.skip) or \
           (args.run_only and config['test_id'] not in args.run_only):
            skipped = skipped + 1
            print("Test {0} SKIPPED".format(config['test_id']))
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
        elif issubclass(config['test_class'], FioExeTest):
            exe_path = os.path.join(fio_root, config['exe'])
            if config['parameters']:
                parameters = [p.format(fio_path=fio_path) for p in config['parameters']]
            else:
                parameters = None
            test = config['test_class'](exe_path, parameters,
                                        config['success'])
        else:
            print("Test {0} FAILED: unable to process test config".format(config['test_id']))
            failed = failed + 1
            continue

        test.setup(artifact_root, config['test_id'])
        test.run()
        test.check_result()
        if test.passed:
            result = "PASSED"
            passed = passed + 1
        else:
            result = "FAILED: {0}".format(test.failure_reason)
            failed = failed + 1
        print("Test {0} {1}".format(config['test_id'], result))

    print("{0} test(s) passed, {1} failed, {2} skipped".format(passed, failed, skipped))

    sys.exit(failed)


if __name__ == '__main__':
    main()
