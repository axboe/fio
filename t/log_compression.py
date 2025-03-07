#!/usr/bin/env python3
#
# log_compression.py
#
# Test log_compression and log_store_compressed. Uses null ioengine.
# Previous bugs have caused output in per I/O log files to be missing
# and/or out of order
#
# Expected result: 8000 log entries, offset starting at 0 and increasing by bs
# Buggy result: Log entries out of order (usually without log_store_compressed)
# and/or missing log entries (usually with log_store_compressed)
#
# USAGE
# python log_compression.py [-f fio-executable]
#
# EXAMPLES
# python t/log_compression.py
# python t/log_compression.py -f ./fio
#
# REQUIREMENTS
# Python 3.5+
#
# ===TEST MATRIX===
#
# With log_compression=10K
# With log_store_compressed=1 and log_compression=10K

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
    return parser.parse_args()


def run_fio(fio,log_store_compressed):
    fio_args = [
        '--name=job',
        '--ioengine=null',
        '--filesize=1000M',
        '--bs=128K',
        '--rw=write',
        '--iodepth=1',
        '--write_bw_log=test',
        '--per_job_logs=0',
        '--log_offset=1',
        '--log_compression=10K',
        ]
    if log_store_compressed:
        fio_args.append('--log_store_compressed=1')

    subprocess.check_output([fio] + fio_args)

    if log_store_compressed:
        fio_inflate_args = [
            '--inflate-log=test_bw.log.fz'
            ]
        with open('test_bw.from_fz.log','wt') as f:
            subprocess.check_call([fio]+fio_inflate_args,stdout=f)

def check_log_file(log_store_compressed):
    filename = 'test_bw.from_fz.log' if log_store_compressed else 'test_bw.log'
    with open(filename,'rt') as f:
        file_data = f.read()
    log_lines = [x for x in file_data.split('\n') if len(x.strip())!=0]
    log_ios = len(log_lines)

    filesize = 1000*1024*1024
    bs = 128*1024
    ios = filesize//bs
    if log_ios!=ios:
        print('wrong number of ios ({}) in log; should be {}'.format(log_ios,ios))
        return False

    expected_offset = 0
    for line_number,line in enumerate(log_lines):
        log_offset = int(line.split(',')[4])
        if log_offset != expected_offset:
            print('wrong offset ({}) for io number {} in log; should be {}'.format(
                log_offset, line_number, expected_offset))
            return False
        expected_offset += bs
    return True

def main():
    """Entry point for this script."""
    args = parse_args()
    if args.fio:
        fio_path = args.fio
    else:
        fio_path = os.path.join(os.path.dirname(__file__), '../fio')
        if not os.path.exists(fio_path):
            fio_path = 'fio'
    print("fio path is", fio_path)

    passed_count = 0
    failed_count = 0
    for log_store_compressed in [False, True]:
        run_fio(fio_path, log_store_compressed)
        passed = check_log_file(log_store_compressed)
        print('Test with log_store_compressed={} {}'.format(log_store_compressed,
            'PASSED' if passed else 'FAILED'))
        if passed:
            passed_count+=1
        else:
            failed_count+=1

    print('{} tests passed, {} failed'.format(passed_count, failed_count))

    sys.exit(failed_count)

if __name__ == '__main__':
    main()

