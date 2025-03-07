#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2020 Western Digital Corporation or its affiliates.
#
"""
jsonplus2csv-test.py

Do one basic test of tools/fio_jsonplus2csv

USAGE
python jsonplus2csv-test.py [-f fio-executable] [-s script-location]

EXAMPLES
python t/jsonplus2csv-test.py
python t/jsonplus2csv-test.py -f ./fio -s tools

REQUIREMENTS
Python 3.5+
"""

import os
import sys
import platform
import argparse
import subprocess


def parse_args():
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--fio',
                        help='path to fio executable (e.g., ./fio)')
    parser.add_argument('-s', '--script',
                        help='directory containing fio_jsonplus2csv script')
    return parser.parse_args()


def run_fio(fio):
    """Run fio to generate json+ data.

    Parameters:
        fio     path to fio executable.
    """

# We need an async ioengine to get submission latencies
    if platform.system() == 'Linux':
        aio = 'libaio'
    elif platform.system() == 'Windows':
        aio = 'windowsaio'
    else:
        aio = 'posixaio'

    fio_args = [
        "--max-jobs=4",
        "--output=fio-output.json",
        "--output-format=json+",
        "--filename=fio_jsonplus_clat2csv.test",
        "--ioengine=" + aio,
        "--time_based",
        "--runtime=3s",
        "--size=1M",
        "--slat_percentiles=1",
        "--clat_percentiles=1",
        "--lat_percentiles=1",
        "--thread=1",
        "--name=test1",
        "--rw=randrw",
        "--name=test2",
        "--rw=read",
        "--name=test3",
        "--rw=write",
        ]

    output = subprocess.run([fio] + fio_args, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)

    return output


def check_output(fio_output, script_path):
    """Run t/fio_jsonplus_clat2csv and validate the generated CSV files
    against the original json+ fio output.

    Parameters:
        fio_output      subprocess.run object describing fio run.
        script_path     path to fio_jsonplus_clat2csv script.
    """

    if fio_output.returncode != 0:
        print("ERROR: fio run failed")
        return False

    if platform.system() == 'Windows':
        script = ['python.exe', script_path]
    else:
        script = [script_path]

    script_args = ["fio-output.json", "fio-output.csv"]
    script_args_validate = script_args + ["--validate"]

    script_output = subprocess.run(script + script_args)
    if script_output.returncode != 0:
        return False

    script_output = subprocess.run(script + script_args_validate)
    if script_output.returncode != 0:
        return False

    return True


def main():
    """Entry point for this script."""

    args = parse_args()

    index = 1
    passed = 0
    failed = 0

    if args.fio:
        fio_path = args.fio
    else:
        fio_path = os.path.join(os.path.dirname(__file__), '../fio')
        if not os.path.exists(fio_path):
            fio_path = 'fio'
    print("fio path is", fio_path)

    if args.script:
        script_path = args.script
    else:
        script_path = os.path.join(os.path.dirname(__file__), '../tools/fio_jsonplus_clat2csv')
        if not os.path.exists(script_path):
            script_path = 'fio_jsonplus_clat2csv'
    print("script path is", script_path)

    fio_output = run_fio(fio_path)
    status = check_output(fio_output, script_path)
    print("Test {0} {1}".format(index, ("PASSED" if status else "FAILED")))
    if status:
        passed = passed + 1
    else:
        failed = failed + 1
    index = index + 1

    print("{0} tests passed, {1} failed".format(passed, failed))

    sys.exit(failed)

if __name__ == '__main__':
    main()
