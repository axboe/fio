#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2019 Western Digital Corporation or its affiliates.
#
#
# readonly.py
#
# Do some basic tests of the --readonly paramter
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
#

import sys
import argparse
import subprocess


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--fio',
                        help='path to fio executable (e.g., ./fio)')
    args = parser.parse_args()

    return args


def run_fio(fio, test, index):
    fio_args = [
                "--name=readonly",
                "--ioengine=null",
                "--time_based",
                "--runtime=1s",
                "--size=1M",
                "--rw={rw}".format(**test),
               ]
    if 'readonly-pre' in test:
        fio_args.insert(0, "--readonly")
    if 'readonly-post' in test:
        fio_args.append("--readonly")

    output = subprocess.run([fio] + fio_args, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)

    return output


def check_output(output, test):
    expect_error = False
    if 'readonly-pre' in test or 'readonly-post' in test:
        if 'write' in test['rw'] or 'trim' in test['rw']:
            expect_error = True

#    print(output.stdout)
#    print(output.stderr)

    if output.returncode == 0:
        if expect_error:
            return False
        else:
            return True
    else:
        if expect_error:
            return True
        else:
            return False


if __name__ == '__main__':
    args = parse_args()

    tests = [
                {
                    "rw": "randread",
                    "readonly-pre": 1,
                },
                {
                    "rw": "randwrite",
                    "readonly-pre": 1,
                },
                {
                    "rw": "randtrim",
                    "readonly-pre": 1,
                },
                {
                    "rw": "randread",
                    "readonly-post": 1,
                },
                {
                    "rw": "randwrite",
                    "readonly-post": 1,
                },
                {
                    "rw": "randtrim",
                    "readonly-post": 1,
                },
                {
                    "rw": "randread",
                },
                {
                    "rw": "randwrite",
                },
                {
                    "rw": "randtrim",
                },
            ]

    index = 1
    passed = 0
    failed = 0

    if args.fio:
        fio_path = args.fio
    else:
        fio_path = 'fio'

    for test in tests:
        output = run_fio(fio_path, test, index)
        status = check_output(output, test)
        print("Test {0} {1}".format(index, ("PASSED" if status else "FAILED")))
        if status:
            passed = passed + 1
        else:
            failed = failed + 1
        index = index + 1

    print("{0} tests passed, {1} failed".format(passed, failed))

    sys.exit(failed)
