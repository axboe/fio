#!/usr/bin/env python3
#
# Copyright 2026 Samsung Electronics Co., Ltd All Rights Reserved
#
# For conditions of distribution and use, see the accompanying COPYING file.
#
"""
# verify_state_save.py
#
# Superficial tests of fio's verify state save feature
#
# USAGE
# see python3 verify_state_save.py --help
#
# EXAMPLES
# python3 t/verify_state_save.py
# python3 t/verify_state_save.py -f ./fio
#
# REQUIREMENTS
# Python 3.6
#
"""
import os
import sys
import time
import logging
import platform
import argparse
from pathlib import Path
from fiotestlib import FioJobCmdTest, run_fio_tests
from fiotestcommon import SUCCESS_NONZERO


class VerifyStateSaveTest(FioJobCmdTest):
    """
    Verify state save test class. Just make sure the test completes successfully.
    """

    def setup(self, parameters):
        """Setup a test."""

        fio_args = [
            f"--output={self.filenames['output']}",
            f"--output-format={self.fio_opts['output-format']}",
            "--name=verify-state",
            f"--ioengine={self.fio_opts['ioengine']}",
            f"--filesize={self.fio_opts['filesize']}",
            f"--rw={self.fio_opts['rw']}",
        ]
        for opt in ['fixedbufs', 'nonvectored', 'force_async', 'registerfiles',
                    'sqthread_poll', 'sqthread_poll_cpu', 'hipri', 'nowait',
                    'time_based', 'runtime', 'verify', 'io_size', 'num_range',
                    'iodepth', 'iodepth_batch', 'iodepth_batch_complete',
                    'size', 'rate', 'bs', 'bssplit', 'bsrange', 'randrepeat',
                    'buffer_pattern', 'verify_pattern', 'offset', 'write_mode',
                    "fsync", "verify_state_save", "verify_state_load",
                    'directory', "verify_only", "verify_policy", "aux-path",
                    "rwmixread", "rwmixwrite", ]:
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

TEST_SIZE="4M"

TEST_LIST = [
    # Simple tests where a verify job runs to completion and we save
    # verify state
    {
        "test_id": 100,
        "fio_opts": {
            "rw": 'randwrite',
            "ioengine": "psync",
            "filesize": TEST_SIZE,
            "output-format": "json",
            "verify": "crc32c",
            "verify_state_save": 1,
            },
        "test_class": VerifyStateSaveTest,
    },
    {
        "test_id": 101,
        "fio_opts": {
            "rw": 'randwrite',
            "ioengine": "psync",
            "filesize": TEST_SIZE,
            "output-format": "json",
            "verify": "crc32c",
            "verify_state_save": 1,
            "verify_policy": "completed",
            },
        "test_class": VerifyStateSaveTest,
    },
    {
        "test_id": 102,
        "fio_opts": {
            "rw": 'randwrite',
            "ioengine": "psync",
            "filesize": TEST_SIZE,
            "output-format": "json",
            "verify": "crc32c",
            "verify_state_save": 1,
            "verify_policy": "fsynced",
            "fsync": 16,
            },
        "test_class": VerifyStateSaveTest,
    },
    {
        "test_id": 103,
        "fio_opts": {
            "rw": 'randrw',
            "ioengine": "psync",
            "filesize": TEST_SIZE,
            "output-format": "json",
            "verify": "crc32c",
            "verify_state_save": 1,
            },
        "test_class": VerifyStateSaveTest,
    },
    {
        "test_id": 104,
        "fio_opts": {
            "rw": 'randrw',
            "ioengine": "psync",
            "filesize": TEST_SIZE,
            "output-format": "json",
            "verify": "crc32c",
            "verify_state_save": 1,
            "verify_policy": "completed",
            },
        "test_class": VerifyStateSaveTest,
    },
    {
        "test_id": 105,
        "fio_opts": {
            "rw": 'randrw',
            "ioengine": "psync",
            "filesize": TEST_SIZE,
            "output-format": "json",
            "verify": "crc32c",
            "verify_state_save": 1,
            "verify_policy": "fsynced",
            "fsync": 16,
            },
        "test_class": VerifyStateSaveTest,
    },
    {
        "test_id": 106,
        "fio_opts": {
            "rw": 'randrw',
            "rwmixread": 70,
            "ioengine": "psync",
            "filesize": TEST_SIZE,
            "output-format": "json",
            "verify": "crc32c",
            "verify_state_save": 1,
            },
        "test_class": VerifyStateSaveTest,
    },
    {
        "test_id": 107,
        "fio_opts": {
            "rw": 'randrw',
            "rwmixread": 70,
            "ioengine": "psync",
            "filesize": TEST_SIZE,
            "output-format": "json",
            "verify": "crc32c",
            "verify_state_save": 1,
            "verify_policy": "completed",
            },
        "test_class": VerifyStateSaveTest,
    },
    {
        "test_id": 108,
        "fio_opts": {
            "rw": 'randrw',
            "rwmixread": 70,
            "ioengine": "psync",
            "filesize": TEST_SIZE,
            "output-format": "json",
            "verify": "crc32c",
            "verify_state_save": 1,
            "verify_policy": "fsynced",
            "fsync": 16,
            },
        "test_class": VerifyStateSaveTest,
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
    args = parser.parse_args()

    return args


def main():
    """Run tests to exercise fio's verify_state_save feature."""

    args = parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    artifact_root = args.artifact_root if args.artifact_root else \
        f"verify-state-save-test-{time.strftime('%Y%m%d-%H%M%S')}"
    os.mkdir(artifact_root)
    print(f"Artifact directory is {artifact_root}")

    if args.fio:
        fio_path = str(Path(args.fio).absolute())
    else:
        fio_path = os.path.join(str(Path(__file__).absolute().parent.parent), "fio")
    print(f"fio path is {fio_path}")

    test_env = {
              'fio_path': fio_path,
              'fio_root': str(Path(__file__).absolute().parent.parent),
              'artifact_root': artifact_root,
              'basename': 'verify-state-save',
              }

    if platform.system() == 'Linux':
        aio = 'libaio'
        sync = 'psync'
    elif platform.system() == 'Windows':
        aio = 'windowsaio'
        sync = 'sync'
    else:
        aio = 'posixaio'
        sync = 'psync'

    total = { 'passed':  0, 'failed': 0, 'skipped': 0 }
    for ioengine in [aio, sync]:

        #
        # set up tests with verify_state_save=1 to generate verify state save files
        #
        test_env['artifact_root'] = os.path.join(artifact_root, ioengine, "verify-state-save")
        os.makedirs(test_env['artifact_root'])

        for test in TEST_LIST:
            test['fio_opts']['ioengine'] = ioengine
            test['fio_opts']['verify_state_save'] = 1
            test['fio_opts']['rw'] = test['fio_opts']['rw'].replace("read", "write")
            test['fio_opts'].pop('verify_state_load', None)
            test['fio_opts'].pop('directory', None)
            test['fio_opts'].pop('aux-path', None)
            test['force_skip'] = False

        print(f"\nRunning verify_state_save=1 tests with ioengine={ioengine}")
        passed, failed, skipped = run_fio_tests(TEST_LIST, test_env, args)

        total['passed'] += passed
        total['failed'] += failed
        total['skipped'] += skipped

        #
        # set up same tests with verify_state_load=1 and verify_only=1
        #
        test_env['artifact_root'] = os.path.join(artifact_root, ioengine, "verify-only")
        os.makedirs(test_env['artifact_root'])

        for test in TEST_LIST:
            test['fio_opts']['verify_state_save'] = 0  # don't overwrite vssave file
            test['fio_opts']['verify_state_load'] = 1
            test['fio_opts']['verify_only'] = 1
            vss_dir = os.path.join(artifact_root, ioengine, "verify-state-save", f"{test['test_id']:04d}")
            this_dir = os.path.join(test_env['artifact_root'], f"{test['test_id']:04d}")
            directory = os.path.relpath(vss_dir, this_dir)
            test['fio_opts']['directory'] = directory
            test['fio_opts']['aux-path'] = directory


        print(f"\nRunning verify_only=1 tests with ioengine={ioengine}")
        passed, failed, skipped = run_fio_tests(TEST_LIST, test_env, args)

        total['passed'] += passed
        total['failed'] += failed
        total['skipped'] += skipped

        #
        # now run the same verify_state_load=1 tests replacing randwrite with
        # randread
        #
        test_env['artifact_root'] = os.path.join(artifact_root, ioengine, "read")
        os.makedirs(test_env['artifact_root'])

        for test in TEST_LIST:
            test['fio_opts'].pop('verify_only', None)
            test['fio_opts']['rw'] = test['fio_opts']['rw'].replace("write", "read")
            if test['fio_opts']['rw'] == 'randrw':
                test['force_skip'] = True
                # there is no 100% read equivalent of a randrw verify workload,
                # so just skip these tests when run in read mode

        print(f"\nRunning rw=[rand]read tests with ioengine={ioengine}")
        passed, failed, skipped = run_fio_tests(TEST_LIST, test_env, args)

        total['passed'] += passed
        total['failed'] += failed
        total['skipped'] += skipped

    print(f"\n\n{total['passed']} test(s) passed, {total['failed']} failed, " \
            f"{total['skipped']} skipped")
    sys.exit(total['failed'])


if __name__ == '__main__':
    main()
