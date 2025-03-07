#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2019 Western Digital Corporation or its affiliates.

"""
# readonly.py
#
# Do some basic tests of the --readonly parameter
#
# USAGE
# python readonly.py [-f fio-executable]
#
# EXAMPLES
# python t/readonly.py
# python t/readonly.py -f ./fio
#
# REQUIREMENTS
# Python 3.5+
#
"""

import os
import sys
import time
import argparse
from pathlib import Path
from fiotestlib import FioJobCmdTest, run_fio_tests
from fiotestcommon import SUCCESS_DEFAULT, SUCCESS_NONZERO


class FioReadOnlyTest(FioJobCmdTest):
    """fio read only test."""

    def setup(self, parameters):
        """Setup the test."""

        fio_args = [
                    "--name=readonly",
                    "--ioengine=null",
                    "--time_based",
                    "--runtime=1s",
                    "--size=1M",
                    f"--rw={self.fio_opts['rw']}",
                   ]
        if 'readonly-pre' in parameters:
            fio_args.insert(0, "--readonly")
        if 'readonly-post' in parameters:
            fio_args.append("--readonly")

        super().setup(fio_args)


TEST_LIST = [
            {
                "test_id": 1,
                "fio_opts": { "rw": "randread", },
                "readonly-pre": 1,
                "success": SUCCESS_DEFAULT,
                "test_class": FioReadOnlyTest,
            },
            {
                "test_id": 2,
                "fio_opts": { "rw": "randwrite", },
                "readonly-pre": 1,
                "success": SUCCESS_NONZERO,
                "test_class": FioReadOnlyTest,
            },
            {
                "test_id": 3,
                "fio_opts": { "rw": "randtrim", },
                "readonly-pre": 1,
                "success": SUCCESS_NONZERO,
                "test_class": FioReadOnlyTest,
            },
            {
                "test_id": 4,
                "fio_opts": { "rw": "randread", },
                "readonly-post": 1,
                "success": SUCCESS_DEFAULT,
                "test_class": FioReadOnlyTest,
            },
            {
                "test_id": 5,
                "fio_opts": { "rw": "randwrite", },
                "readonly-post": 1,
                "success": SUCCESS_NONZERO,
                "test_class": FioReadOnlyTest,
            },
            {
                "test_id": 6,
                "fio_opts": { "rw": "randtrim", },
                "readonly-post": 1,
                "success": SUCCESS_NONZERO,
                "test_class": FioReadOnlyTest,
            },
            {
                "test_id": 7,
                "fio_opts": { "rw": "randread", },
                "success": SUCCESS_DEFAULT,
                "test_class": FioReadOnlyTest,
            },
            {
                "test_id": 8,
                "fio_opts": { "rw": "randwrite", },
                "success": SUCCESS_DEFAULT,
                "test_class": FioReadOnlyTest,
            },
            {
                "test_id": 9,
                "fio_opts": { "rw": "randtrim", },
                "success": SUCCESS_DEFAULT,
                "test_class": FioReadOnlyTest,
            },
        ]


def parse_args():
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--fio', help='path to fio executable (e.g., ./fio)')
    parser.add_argument('-a', '--artifact-root', help='artifact root directory')
    parser.add_argument('-s', '--skip', nargs='+', type=int,
                        help='list of test(s) to skip')
    parser.add_argument('-o', '--run-only', nargs='+', type=int,
                        help='list of test(s) to run, skipping all others')
    args = parser.parse_args()

    return args


def main():
    """Run readonly tests."""

    args = parse_args()

    if args.fio:
        fio_path = str(Path(args.fio).absolute())
    else:
        fio_path = 'fio'
    print(f"fio path is {fio_path}")

    artifact_root = args.artifact_root if args.artifact_root else \
        f"readonly-test-{time.strftime('%Y%m%d-%H%M%S')}"
    os.mkdir(artifact_root)
    print(f"Artifact directory is {artifact_root}")

    test_env = {
              'fio_path': fio_path,
              'fio_root': str(Path(__file__).absolute().parent.parent),
              'artifact_root': artifact_root,
              'basename': 'readonly',
              }

    _, failed, _ = run_fio_tests(TEST_LIST, test_env, args)
    sys.exit(failed)


if __name__ == '__main__':
    main()
