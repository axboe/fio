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
            f"--output-format={self.fio_opts.get('output-format', 'normal')}",
        ]
        for opt in ['fixedbufs', 'nonvectored', 'force_async', 'registerfiles',
                    'sqthread_poll', 'sqthread_poll_cpu', 'hipri', 'nowait',
                    'time_based', 'runtime', 'verify', 'io_size', 'num_range',
                    'iodepth', 'iodepth_batch', 'iodepth_batch_complete',
                    'size', 'rate', 'bs', 'bssplit', 'bsrange', 'randrepeat',
                    'buffer_pattern', 'verify_pattern', 'verify', 'offset',
                    'filesize', 'write_mode', 'debug', ]:
            if opt in self.fio_opts:
                option = f"--{opt}={self.fio_opts[opt]}"
                fio_args.append(option)

        super().setup(fio_args)


    def check_result(self):

        super().check_result()

        if 'rw' not in self.fio_opts or \
                not self.passed or \
                'json' not in self.fio_opts.get('output-format', ''):
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

nvme_cmd_write = 1
nvme_cmd_write_uncor = 4
nvme_cmd_write_zeroes = 8
nvme_cmd_verify = 12

class WriteModeSplit(WriteModeTest):
    """
    Make sure that the expected fraction of write, write uncorrectable, write
    zeroes, and verify commands are actually submitted.
    """

    def __init__(self, fio_path, success, testnum, artifact_root, fio_opts, basename=None):
        super().__init__(fio_path, success, testnum, artifact_root, fio_opts, basename)
        self.actual = None

    def check_result(self):

        super().check_result()

        if not self.passed:
            return

        split = {'write': 0, 'uncor': 0, 'verify': 0, 'zeroes': 0}
        wm = self.fio_opts['write_mode']
        for s in wm.split(':'):
            sp = s.split('/')
            split[sp[0]] = sp[1]

        total = 0
        blanks = 0
        for v in split.values():
            if v == '':
                blanks += 1
            else:
                total += int(v)

        if blanks:
            fill = int((100 - total) / blanks)
        for k in split.keys():
            if split[k] == '':
                split[k] = fill
            else:
                split[k] = int(split[k])

        logging.debug(split)

        self.actual = {'write': 0, 'uncor': 0, 'verify': 0, 'zeroes': 0}
        with open(self.filenames['output'], 'r') as file:
            for line in file:
                if "op selected" in line:
                    op = int(line.split(" op selected ")[1])
                    if op == nvme_cmd_write:
                        self.actual['write'] += 1
                    elif op == nvme_cmd_write_uncor:
                        self.actual['uncor'] += 1
                    elif op == nvme_cmd_write_zeroes:
                        self.actual['zeroes'] += 1
                    elif op == nvme_cmd_verify:
                        self.actual['verify'] += 1
                    else:
                        raise ValueError(f"Unknown opcode {op}")

        logging.debug(self.actual)
        total = sum(self.actual.values())
        if total == 0:
            self.passed = False
            self.failure_reason += \
                    "No write/uncor/zeroes/verify commands detected"
            return

        for key, value in self.actual.items():
            expected = int(split[key] / 100 * total)
            logging.debug("mode %s: expected %d, actual %d", key, expected, value)
            if expected != 0:
                if abs(value - expected) / expected > 0.1:
                    self.passed = False
                    self.failure_reason += \
                        f"large discrepancy for write mode {key}: expected {expected}, actual {value};"
            elif value != 0:
                self.passed = False
                self.failure_reason += \
                    f"discrepancy for write mode {key}: expected {expected}, actual {value};"


class WriteModeVerify(WriteModeSplit):
    """
    Make sure that offsets that are the target of write uncorrectable commands
    and offsets that are the target of write zeroes commands are appropriately
    verified.

    This only checks that the number of write zeroes commands matches the
    number of write zero verify debug messages and that the number of write
    uncorrectable commands matches the number of uncorrectable verify debug
    messages.

    No checking is done to make sure that the offsets where write zeroes
    (uncorrectables) were originally targeted are the offsets where write zero
    (uncorrectable) verification is carried out.

    No overlap checking is carried out, so write offsets cannot be repeated.

    Jobs must be run with --debug=verify,io in order to detect errored IOs and
    write zeroes verification.
    """

    def check_result(self):

        super().check_result()
        if not self.passed:
            return

        verify = {'uncor': 0, 'zeroes': 0}
        with open(self.filenames['output'], 'r') as file:
            for line in file:
                if "errored io_u" in line:
                    verify['uncor'] += 1
                elif "verifying write zeroes" in line:
                    verify['zeroes'] += 1

        logging.debug("verify: %s", str(verify))
        for cmd in ['zeroes', 'uncor']:
            if verify[cmd] != self.actual[cmd]:
                self.passed = False
                self.failure_reason += \
                    f"{cmd}: writes {self.actual[cmd]} and verifies {verify[cmd]} do not match; "


TEST_SIZE = "16M"

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

    #
    # Mixed write_mode tests
    #
    # test_id 40-41: valid mixed modes, all percentages explicit
    # test_id 50-53: valid mixed modes, blank percentages (evenly split)
    # test_id 60-63: invalid mixed modes (parsing should fail)
    #
    {
        # All percentages explicit, sum == 100
        "test_id": 40,
        "fio_opts": {
            "rw": 'randwrite',
            "filesize": TEST_SIZE,
            "write_mode": "write/30:zeroes/20:uncor/50",
            "randrepeat": 0,
            "debug": "io",
            },
        "test_class": WriteModeSplit,
    },
    {
        # All percentages explicit with verify; write/50 + zeroes/50
        "test_id": 41,
        "fio_opts": {
            "rw": 'randwrite',
            "filesize": TEST_SIZE,
            "write_mode": "write/50:zeroes/50",
            "randrepeat": 0,
            "debug": "io",
            },
        "test_class": WriteModeSplit,
    },

    {
        # Blank percentages: write/50 takes half, zeroes and uncor split the
        # remainder evenly (25% each)
        "test_id": 50,
        "fio_opts": {
            "rw": 'randwrite',
            "filesize": TEST_SIZE,
            "write_mode": "write/50:zeroes/:uncor/",
            "randrepeat": 0,
            "debug": "io",
            },
        "test_class": WriteModeSplit,
    },
    {
        # All blanks: write, zeroes, uncor each get 33% (integer division)
        "test_id": 51,
        "fio_opts": {
            "rw": 'randwrite',
            "filesize": TEST_SIZE,
            "write_mode": "write/:zeroes/:uncor/",
            "randrepeat": 0,
            "debug": "io",
            },
        "test_class": WriteModeSplit,
    },
    {
        # Two entries, one blank: write/60 + zeroes blank gets remaining 40%
        "test_id": 52,
        "fio_opts": {
            "rw": 'randwrite',
            "filesize": TEST_SIZE,
            "write_mode": "write/60:zeroes/",
            "randrepeat": 0,
            "debug": "io",
            },
        "test_class": WriteModeSplit,
    },
    {
        # Three entries, one blank: write/30 + zeroes/40 + uncor blank gets
        # remaining 30%
        "test_id": 53,
        "fio_opts": {
            "rw": 'randwrite',
            "filesize": TEST_SIZE,
            "write_mode": "write/30:zeroes/40:uncor/",
            "randrepeat": 0,
            "debug": "io",
            },
        "test_class": WriteModeSplit,
    },
    {
        # Invalid: percentages exceed 100
        "test_id": 60,
        "fio_opts": {
            "rw": 'randwrite',
            "filesize": TEST_SIZE,
            "write_mode": "write/60:zeroes/60",
            },
        "test_class": WriteModeTest,
        "success": SUCCESS_NONZERO,
    },
    {
        # Invalid: only one entry (needs at least 2)
        "test_id": 61,
        "fio_opts": {
            "rw": 'randwrite',
            "filesize": TEST_SIZE,
            "write_mode": "write/100",
            },
        "test_class": WriteModeTest,
        "success": SUCCESS_NONZERO,
    },
    {
        # Invalid: explicit percentages don't add up to 100, no blanks
        "test_id": 62,
        "fio_opts": {
            "rw": 'randwrite',
            "filesize": TEST_SIZE,
            "write_mode": "write/30:zeroes/30",
            },
        "test_class": WriteModeTest,
        "success": SUCCESS_NONZERO,
    },
    {
        # Invalid: unknown mode name
        "test_id": 63,
        "fio_opts": {
            "rw": 'randwrite',
            "filesize": TEST_SIZE,
            "write_mode": "write/50:bogus/50",
            },
        "test_class": WriteModeTest,
        "success": SUCCESS_NONZERO,
    },

    #
    # Make sure verify handles write zeroes and write uncorrectable opcodes
    # correctly
    #
    {
        # All percentages explicit, sum == 100
        "test_id": 70,
        "fio_opts": {
            "rw": 'randwrite',
            "filesize": TEST_SIZE,
            "write_mode": "write/30:zeroes/20:uncor/50",
            "verify": "crc32c",
            "randrepeat": 0,
            "debug": "io,verify",
            },
        "test_class": WriteModeVerify,
    },
    {
        # All percentages explicit with verify; write/50 + zeroes/50
        "test_id": 71,
        "fio_opts": {
            "rw": 'randwrite',
            "filesize": TEST_SIZE,
            "write_mode": "write/50:zeroes/50",
            "verify": "crc32c",
            "randrepeat": 0,
            "debug": "io,verify",
            },
        "test_class": WriteModeVerify,
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
        fio_path = os.path.join(str(Path(__file__).absolute().parent.parent), "fio")
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
