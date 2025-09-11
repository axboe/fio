#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2025 Sandisk Corporation or its affiliates

"""
sprandom.py
-----------
Tests for fio's sprandom feature.

USAGE:
  python t/sprandom.py [-f fio-executable]

This script is also invoked by t/run-fio-tests.py.
"""

import sys
import argparse
import time
from pathlib import Path

from fiotestlib import FioJobCmdTest, run_fio_tests
from fiotestcommon import SUCCESS_DEFAULT, SUCCESS_NONZERO

SPRANDOM_OPT_LIST = [
    'spr_op',
    'spr_num_regions',
    'size',
    'norandommap',
    'random_generator',
    'rw',
]

class FioSPrandomTest(FioJobCmdTest):
    """fio sprandom test wrapper."""

    def setup(self, parameters):
        """Setup fio arguments for the test."""
        bs = parameters.get("bs", "4k")
        fio_args = [
            "--name=sprandom",
            "--ioengine=libaio",
            "--filename=sprandom_testfile",
            f"--bs={bs}",
            f"--blockalign={bs}",
            "--direct=1",
            "--iodepth=16",
            "--sprandom=1",
        ]

        # Add variable parameters if provided

        for opt in SPRANDOM_OPT_LIST:
            if opt in self.fio_opts:
                option = f"--{opt}={self.fio_opts[opt]}"
                fio_args.append(option)
        if "rw" not in self.fio_opts:
            fio_args.append("--rw=randwrite")

        super().setup(fio_args)


TEST_LIST = [
    {
        "test_id": 1,
        "fio_opts": {
            "spr_op": "0.10",
            "spr_num_regions": "50",
            "size": "32M",
        },
        "success": SUCCESS_DEFAULT,
        "test_class": FioSPrandomTest,
    },
    {
        "test_id": 2,
        "fio_opts": {
            "spr_op": "0.25",
            "spr_num_regions": "100",
            "size": "64M",
        },
        "success": SUCCESS_DEFAULT,
        "test_class": FioSPrandomTest,
    },
    {
        "test_id": 3,
        "fio_opts": {
            "spr_op": "0.50",
            "spr_num_regions": "200",
            "size": "128M",
            "random_generator": "tausworthe",
        },
        "success": SUCCESS_NONZERO,
        "test_class": FioSPrandomTest,
    },
    {
        "test_id": 4,
        "fio_opts": {
            "spr_op": "0.75",
            "spr_num_regions": "400",
            "size": "256M",
            "norandommap": "0"
        },
        "bs": "16K",
        "success": SUCCESS_NONZERO,
        "test_class": FioSPrandomTest,
    },
    {
        "test_id": 4,
        "fio_opts": {
            "spr_op": "0.75",
            "spr_num_regions": "400",
            "size": "256M",
            "rw": "randread",
        },
        "bs": "16K",
        "success": SUCCESS_NONZERO,
        "test_class": FioSPrandomTest,
    },
]


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--fio",
                        help="path to fio executable (default: fio in PATH)")
    parser.add_argument('-s', '--skip', nargs='+', type=int,
                        help='list of test(s) to skip')
    parser.add_argument('-a', '--artifact-root', help='artifact root directory')
    parser.add_argument('-o', '--run-only', nargs='+', type=int,
                        help='list of test(s) to run, skipping all others')

    return parser.parse_args()


def main():
    """Run sprandom tests."""
    args = parse_args()

    fio_path = str(Path(args.fio).absolute()) if args.fio else "fio"
    artifact_root = args.artifact_root if args.artifact_root else \
            f"sprandom-test-{time.strftime('%Y%m%d-%H%M%S')}"
    Path(artifact_root).mkdir(parents=True, exist_ok=True)
    print(f"Artifact directory is {str(Path(artifact_root).absolute())}")

    test_env = {
        "fio_path": fio_path,
        "fio_root": str(Path(__file__).absolute().parent.parent),
        "artifact_root": artifact_root,
        "basename": "sprandom"
    }

    _, failed, _ = run_fio_tests(TEST_LIST, test_env, args)
    sys.exit(failed)


if __name__ == "__main__":
    main()
