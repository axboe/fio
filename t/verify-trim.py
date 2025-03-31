#!/usr/bin/env python3
"""
# verify-trim.c.py
#
# Test fio's verify trim feature.
#
# USAGE
# see python3 verify-trim.c.py --help
#
# EXAMPLES
# python3 t/verify-trim.c.py
# python3 t/verify-trim.c.py --fio ./fio
#
# REQUIREMENTS
# Python 3.6
# Linux
#
"""
import os
import sys
import time
import logging
import argparse
import subprocess
from pathlib import Path
from fiotestlib import FioJobCmdTest, run_fio_tests
from fiotestcommon import SUCCESS_NONZERO, Requirements


VERIFY_OPT_LIST = [
    'direct',
    'iodepth',
    'filesize',
    'bs',
    'time_based',
    'runtime',
    'io_size',
    'offset',
    'number_ios',
    'output-format',
    'directory',
    'norandommap',
    'numjobs',
    'nrfiles',
    'openfiles',
    'ioengine',
    'trim_backlog_batch',
    'trim_verify_zero',
    'number_ios',
]

class VerifyTrimTest(FioJobCmdTest):
    """
    VerifyTrim test class.
    """

    def setup(self, parameters):
        """Setup a test."""

        fio_args = [
            "--name=verifytrim",
            "--verify=md5",
            f"--filename={self.fio_opts['filename']}",
            f"--rw={self.fio_opts['rw']}",
            f"--trim_percentage={self.fio_opts['trim_percentage']}",
            f"--trim_backlog={self.fio_opts['trim_backlog']}",
            f"--output={self.filenames['output']}",
        ]
        for opt in VERIFY_OPT_LIST:
            if opt in self.fio_opts:
                option = f"--{opt}={self.fio_opts[opt]}"
                fio_args.append(option)

        super().setup(fio_args)

    def check_result(self):
        super().check_result()

        if self.fio_opts.get('output-format') == 'json':
            actual = self.json_data['jobs'][0]['trim']['total_ios']
            expected = self.json_data['jobs'][0]['write']['total_ios'] * self.fio_opts['trim_percentage'] / 100
            if abs(expected - actual) > 0.1*expected:
                self.passed = False
                self.failure_reason += f" large discrepancy between expected {expected} and {actual} actual trims,"
            else:
                logging.debug("expected %d trims ~match actual %d trims", expected, actual)

        if not self.passed:
            with open(self.filenames['stderr'], "r") as se:
                contents = se.read()
                logging.info("stderr: %s", contents)

            with open(self.filenames['stdout'], "r") as so:
                contents = so.read()
                logging.info("stdout: %s", contents)

            with open(self.filenames['output'], "r") as out:
                contents = out.read()
                logging.info("output: %s", contents)


TEST_LIST = [
    # These tests are superficial.
    #
    # TODO: add a test case for trim_verify_zero by inducing a failure; the way
    # to do this would be to write non-zero data to a block after it was
    # trimmed but before it was read back (how to do this?)
    {
        # make sure readonly option triggers error message when
        # trim_{percentage,backlog} options make trim operations a possibility
        "test_id": 1,
        "fio_opts": {
            "rw": "read",
            "trim_percentage": 100,
            "trim_backlog": 1,
            "readonly": 1,
            },
        "test_class": VerifyTrimTest,
        "success": SUCCESS_NONZERO,
    },
    {
        # basic test seq write
        # trim_backlog=1
        # trim_percentage=100
        "test_id": 100,
        "fio_opts": {
            "rw": "write",
            "trim_percentage": 100,
            "trim_backlog": 1,
            "trim_verify_zero": 1,
            "number_ios": 64,
            "output-format": "json",
            },
        "test_class": VerifyTrimTest,
    },
    {
        # basic test rand write
        # trim_backlog=1
        # trim_percentage=100
        "test_id": 101,
        "fio_opts": {
            "rw": "randwrite",
            "trim_percentage": 100,
            "trim_backlog": 1,
            "trim_verify_zero": 1,
            "number_ios": 64,
            "output-format": "json",
            },
        "test_class": VerifyTrimTest,
    },
    {
        # basic test seq write
        # trim_backlog=1
        # trim_percentage=50
        "test_id": 102,
        "fio_opts": {
            "rw": "write",
            "trim_percentage": 50,
            "trim_backlog": 1,
            "trim_verify_zero": 1,
            "number_ios": 64,
            "output-format": "json",
            },
        "test_class": VerifyTrimTest,
    },
    {
        # basic test rand write
        # trim_backlog=1
        # trim_percentage=50
        "test_id": 103,
        "fio_opts": {
            "rw": "randwrite",
            "trim_percentage": 50,
            "trim_backlog": 1,
            "trim_verify_zero": 1,
            "number_ios": 64,
            "output-format": "json",
            },
        "test_class": VerifyTrimTest,
    },
    {
        # basic test seq write
        # trim_backlog=16
        # trim_percentage=50
        "test_id": 104,
        "fio_opts": {
            "rw": "write",
            "trim_percentage": 50,
            "trim_backlog": 16,
            "trim_verify_zero": 1,
            "number_ios": 64,
            "output-format": "json",
            },
        "test_class": VerifyTrimTest,
    },
    {
        # basic test rand write
        # trim_backlog=16
        # trim_percentage=50
        "test_id": 105,
        "fio_opts": {
            "rw": "randwrite",
            "trim_percentage": 50,
            "trim_backlog": 16,
            "trim_verify_zero": 1,
            "number_ios": 64,
            "output-format": "json",
            },
        "test_class": VerifyTrimTest,
    },

]


def parse_args():
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--fio-root', help='fio root path')
    parser.add_argument('-d', '--debug', help='Enable debug messages', action='store_true')
    parser.add_argument('-f', '--fio', help='path to file executable (e.g., ./fio)')
    parser.add_argument('-a', '--artifact-root', help='artifact root directory')
    parser.add_argument('-s', '--skip', nargs='+', type=int,
                        help='list of test(s) to skip')
    parser.add_argument('-o', '--run-only', nargs='+', type=int,
                        help='list of test(s) to run, skipping all others')
    parser.add_argument('-k', '--skip-req', action='store_true',
                        help='skip requirements checking')
    parser.add_argument('--dut',
                        help='Block device to test against (use null_blk if not provided')
    args = parser.parse_args()

    return args


def main():
    """
    Run tests for fio's verify trim feature.
    """

    args = parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    artifact_root = args.artifact_root if args.artifact_root else \
        f"verify-trim-test-{time.strftime('%Y%m%d-%H%M%S')}"
    os.mkdir(artifact_root)
    print(f"Artifact directory is {artifact_root}")

    if args.fio:
        fio_path = str(Path(args.fio).absolute())
    else:
        fio_path = os.path.join(os.path.dirname(__file__), '../fio')
    print(f"fio path is {fio_path}")

    if args.fio_root:
        fio_root = args.fio_root
    else:
        fio_root = str(Path(__file__).absolute().parent.parent)
    print(f"fio root is {fio_root}")

    if not args.skip_req:
        Requirements(fio_root, args)

    cleanup_nullb = False
    if not args.dut:
        subprocess.run(["sudo", "modprobe", "-r", "null_blk"],
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
        subprocess.run(["sudo", "modprobe", "null_blk", "memory_backed=1", "discard=1"],
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
        if os.path.exists('/dev/nullb0'):
            args.dut = '/dev/nullb0'
            cleanup_nullb = True
        else:
            print("No block device provided and could not create null_blk device for testing")
            sys.exit(1)

    for test in TEST_LIST:
        test['fio_opts']['filename'] = args.dut

    test_env = {
              'fio_path': fio_path,
              'fio_root': str(Path(__file__).absolute().parent.parent),
              'artifact_root': artifact_root,
              'basename': 'verifytrim',
              }

    total = { 'passed':  0, 'failed': 0, 'skipped': 0 }

    try:
        total['passed'], total['failed'], total['skipped'] = run_fio_tests(TEST_LIST, test_env, args)
    except KeyboardInterrupt:
        pass

    if cleanup_nullb:
        subprocess.run(["sudo", "modprobe", "-r", "null_blk"],
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)

    sys.exit(total['failed'])


if __name__ == '__main__':
    main()
