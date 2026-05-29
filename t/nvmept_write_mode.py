#!/usr/bin/env python3
#
# Copyright 2026 Samsung Electronics Co., Ltd All Rights Reserved
#
# For conditions of distribution and use, see the accompanying COPYING file.
#
"""
# nvmept_write_mode.py
#
# Test fio's io_uring_cmd ioengine with NVMe pass-through write modes
#
# USAGE
# see python3 nvmept_write_mode.py --help
#
# EXAMPLES
# python3 t/nvmept_write_mode.py --dut /dev/ng0n1
# python3 t/nvmept_write_mode.py --dut /dev/ng1n1 -f ./fio
#
# REQUIREMENTS
# Python 3.6
#
"""
import os
import sys
import time
import logging
import argparse
from pathlib import Path
from fiotestlib import FioJobCmdTest, run_fio_tests
from fiotestcommon import SUCCESS_NONZERO


class WriteModeTest(FioJobCmdTest):
    """
    NVMe pass-through test class. Check to make sure output for selected data
    direction(s) is non-zero and that zero data appears for other directions.
    """

    def setup(self, parameters):
        """Setup a test."""

        fio_args = [
            "--name=nvmept-write-mode",
            "--ioengine=io_uring_cmd",
            "--cmd_type=nvme",
            f"--filename={self.fio_opts['filename']}",
            f"--rw={self.fio_opts['rw']}",
            f"--output={self.filenames['output']}",
            f"--output-format={self.fio_opts['output-format']}",
        ]
        for opt in ['fixedbufs', 'nonvectored', 'force_async', 'registerfiles',
                    'sqthread_poll', 'sqthread_poll_cpu', 'hipri', 'nowait',
                    'time_based', 'runtime', 'verify', 'io_size', 'num_range',
                    'iodepth', 'iodepth_batch', 'iodepth_batch_complete',
                    'size', 'rate', 'bs', 'bssplit', 'bsrange', 'randrepeat',
                    'buffer_pattern', 'verify_pattern', 'verify', 'offset',
                    'filesize', 'write_mode', ]:
            if opt in self.fio_opts:
                option = f"--{opt}={self.fio_opts[opt]}"
                fio_args.append(option)

        super().setup(fio_args)


    def check_result(self):

        super().check_result()

        if 'rw' not in self.fio_opts or \
                not self.passed or \
                'json' not in self.fio_opts['output-format']:
            return

        job = self.json_data['jobs'][0]

        if self.fio_opts['rw'] in ['read', 'randread']:
            self.passed = self.check_all_ddirs(['read'], job)
        elif self.fio_opts['rw'] in ['write', 'randwrite']:
            if 'verify' not in self.fio_opts:
                self.passed = self.check_all_ddirs(['write'], job)
            else:
                self.passed = self.check_all_ddirs(['read', 'write'], job)
        elif self.fio_opts['rw'] in ['trim', 'randtrim']:
            self.passed = self.check_all_ddirs(['trim'], job)
        elif self.fio_opts['rw'] in ['readwrite', 'randrw']:
            self.passed = self.check_all_ddirs(['read', 'write'], job)
        elif self.fio_opts['rw'] in ['trimwrite', 'randtrimwrite']:
            self.passed = self.check_all_ddirs(['trim', 'write'], job)
        else:
            logging.error("Unhandled rw value %s", self.fio_opts['rw'])
            self.passed = False

TEST_SIZE="16M"

TEST_LIST = [
    {
        # Use write_mode=write to precondition device for write_mode=verify
        # which just tells the device to check the integrity of the stored data
        "test_id": 10,
        "fio_opts": {
            "rw": 'randwrite',
            "filesize": TEST_SIZE,
            "write_mode": "write",
            "randrepeat": 0,
            "output-format": "json",
            },
        "test_class": WriteModeTest,
    },
    {
        "test_id": 11,
        "fio_opts": {
            "rw": 'write',
            "filesize": TEST_SIZE,
            "write_mode": "verify",
            "output-format": "json",
            },
        "test_class": WriteModeTest,
    },
    {
        "test_id": 12,
        "fio_opts": {
            "rw": 'randwrite',
            "filesize": TEST_SIZE,
            "write_mode": "verify",
            "randrepeat": 0,
            "output-format": "json",
            },
        "test_class": WriteModeTest,
    },

    {
        # Precondition device using write zeroes. Then use pattern verification
        # to read everything back
        "test_id": 20,
        "fio_opts": {
            "rw": 'randwrite',
            "filesize": TEST_SIZE,
            "write_mode": "zeroes",
            "randrepeat": 0,
            "output-format": "json",
            },
        "test_class": WriteModeTest,
    },
    {
        "test_id": 21,
        "fio_opts": {
            "rw": 'read',
            "filesize": TEST_SIZE,
            "verify": "pattern",
            "verify_pattern": 0,
            "output-format": "json",
            },
        "test_class": WriteModeTest,
    },
    {
        "test_id": 22,
        "fio_opts": {
            "rw": 'randread',
            "filesize": TEST_SIZE,
            "verify": "pattern",
            "verify_pattern": 0,
            "randrepeat": 0,
            "output-format": "json",
            },
        "test_class": WriteModeTest,
    },

    {
        # Precondition device for write_mode=verify which just tells the device
        # to check the integrity of the stored data
        # Issue write uncorrectable commands which instruct the device to
        # return an uncorrectable error when reading back the data
        "test_id": 30,
        "fio_opts": {
            "rw": 'randwrite',
            "filesize": TEST_SIZE,
            "write_mode": "uncor",
            "output-format": "json",
            },
        "test_class": WriteModeTest,
    },
    {
        "test_id": 31,
        "fio_opts": {
            "rw": 'write',
            "filesize": TEST_SIZE,
            "write_mode": "verify",
            "output-format": "json",
            },
        "test_class": WriteModeTest,
        "success": SUCCESS_NONZERO,
    },
    {
        "test_id": 32,
        "fio_opts": {
            "rw": 'randwrite',
            "filesize": TEST_SIZE,
            "write_mode": "verify",
            "output-format": "json",
            "randrepeat": 0,
            },
        "test_class": WriteModeTest,
        "success": SUCCESS_NONZERO,
    },
    {
        "test_id": 33,
        "fio_opts": {
            "rw": 'read',
            "filesize": TEST_SIZE,
            "output-format": "json",
            },
        "test_class": WriteModeTest,
        "success": SUCCESS_NONZERO,
    },
    {
        "test_id": 34,
        "fio_opts": {
            "rw": 'randread',
            "filesize": TEST_SIZE,
            "output-format": "json",
            "randrepeat": 0,
            },
        "test_class": WriteModeTest,
        "success": SUCCESS_NONZERO,
    },
]

def parse_args():
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', help='Enable debug messages', action='store_true')
    parser.add_argument('-f', '--fio', help='path to file executable (e.g., ./fio)')
    parser.add_argument('-a', '--artifact-root', help='artifact root directory')
    parser.add_argument('-s', '--skip', nargs='+', type=int,
                        help='list of test(s) to skip')
    parser.add_argument('-o', '--run-only', nargs='+', type=int,
                        help='list of test(s) to run, skipping all others')
    parser.add_argument('--dut', help='target NVMe character device to test '
                        '(e.g., /dev/ng0n1). WARNING: THIS IS A DESTRUCTIVE TEST', required=True)
    args = parser.parse_args()

    return args


def main():
    """Run tests using fio's io_uring_cmd ioengine to send NVMe pass through commands."""

    args = parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    artifact_root = args.artifact_root if args.artifact_root else \
        f"nvmept-write-mode-test-{time.strftime('%Y%m%d-%H%M%S')}"
    os.mkdir(artifact_root)
    print(f"Artifact directory is {artifact_root}")

    if args.fio:
        fio_path = str(Path(args.fio).absolute())
    else:
        fio_root = str(Path(__file__).absolute().parent.parent)
    print(f"fio path is {fio_path}")

    for test in TEST_LIST:
        test['fio_opts']['filename'] = args.dut

    test_env = {
              'fio_path': fio_path,
              'fio_root': str(Path(__file__).absolute().parent.parent),
              'artifact_root': artifact_root,
              'basename': 'nvmept-write-mode',
              }

    _, failed, _ = run_fio_tests(TEST_LIST, test_env, args)
    sys.exit(failed)


if __name__ == '__main__':
    main()
