#!/usr/bin/python
# Note: this script is python2 and python3 compatible.
#
# strided.py
#
# Test zonemode=strided. This uses the null ioengine when no file is
# specified. If a file is specified, use it for randdom read testing.
# Some of the zoneranges in the tests are 16MiB. So when using a file
# a minimum size of 32MiB is recommended.
#
# USAGE
# python strided.py fio-executable [-f file/device]
#
# EXAMPLES
# python t/strided.py ./fio
# python t/strided.py ./fio -f /dev/sda
# dd if=/dev/zero of=temp bs=1M count=32
# python t/strided.py ./fio -f temp
#
# REQUIREMENTS
# Python 2.6+
#
# ===TEST MATRIX===
#
# --zonemode=strided, zoneskip unset
#   w/ randommap and LFSR
#       zonesize=zonerange  all blocks in zonerange touched
#       zonesize>zonerange  all blocks touched and roll-over back into zone
#       zonesize<zonerange  all blocks inside zone
#
#   w/o randommap       all blocks inside zone
#

from __future__ import absolute_import
from __future__ import print_function
import os
import sys
import argparse
import subprocess


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('fio',
                        help='path to fio executable (e.g., ./fio)')
    parser.add_argument('-f', '--filename', help="file/device to test")
    args = parser.parse_args()

    return args


def run_fio(fio, test, index):
    filename = "strided"
    fio_args = [
                "--name=strided",
                "--zonemode=strided",
                "--log_offset=1",
                "--randrepeat=0",
                "--rw=randread",
                "--write_iops_log={0}{1:03d}".format(filename, index),
                "--output={0}{1:03d}.out".format(filename, index),
                "--zonerange={zonerange}".format(**test),
                "--zonesize={zonesize}".format(**test),
                "--bs={bs}".format(**test),
               ]
    if 'norandommap' in test:
        fio_args.append('--norandommap')
    if 'random_generator' in test:
        fio_args.append('--random_generator={random_generator}'.format(**test))
    if 'offset' in test:
        fio_args.append('--offset={offset}'.format(**test))
    if 'filename' in test:
        fio_args.append('--filename={filename}'.format(**test))
        fio_args.append('--filesize={filesize})'.format(**test))
    else:
        fio_args.append('--ioengine=null')
        fio_args.append('--size={size}'.format(**test))
        fio_args.append('--io_size={io_size}'.format(**test))
        fio_args.append('--filesize={size})'.format(**test))

    output = subprocess.check_output([fio] + fio_args, universal_newlines=True)

    f = open("{0}{1:03d}_iops.1.log".format(filename, index), "r")
    log = f.read()
    f.close()

    return log


def check_output(iops_log, test):
    zonestart = 0 if 'offset' not in test else test['offset']
    iospersize = test['zonesize'] / test['bs']
    iosperrange = test['zonerange'] / test['bs']
    iosperzone = 0
    lines = iops_log.split('\n')
    zoneset = set()

    for line in lines:
        if len(line) == 0:
            continue

        if iosperzone == iospersize:
            # time to move to a new zone
            iosperzone = 0
            zoneset = set()
            zonestart += test['zonerange']
            if zonestart >= test['filesize']:
                zonestart = 0 if 'offset' not in test else test['offset']

        iosperzone = iosperzone + 1
        tokens = line.split(',')
        offset = int(tokens[4])
        if offset < zonestart or offset >= zonestart + test['zonerange']:
            print("Offset {0} outside of zone starting at {1}".format(
                    offset, zonestart))
            return False

        # skip next section if norandommap is enabled with no
        # random_generator or with a random_generator != lfsr
        if 'norandommap' in test:
            if 'random_generator' in test:
                if test['random_generator'] != 'lfsr':
                    continue
            else:
                continue

        # we either have a random map enabled or we
        # are using an LFSR
        # so all blocks should be unique and we should have
        # covered the entire zone when iosperzone % iosperrange == 0
        block = (offset - zonestart) / test['bs']
        if block in zoneset:
            print("Offset {0} in zone already touched".format(offset))
            return False

        zoneset.add(block)
        if iosperzone % iosperrange == 0:
            if len(zoneset) != iosperrange:
                print("Expected {0} blocks in zone but only saw {1}".format(
                        iosperrange, len(zoneset)))
                return False
            zoneset = set()

    return True


if __name__ == '__main__':
    args = parse_args()

    tests = [   # randommap enabled
                {
                    "zonerange": 4096,
                    "zonesize": 4096,
                    "bs": 4096,
                    "offset": 8*4096,
                    "size": 16*4096,
                    "io_size": 16*4096,
                },
                {
                    "zonerange": 4096,
                    "zonesize": 4096,
                    "bs": 4096,
                    "size": 16*4096,
                    "io_size": 16*4096,
                },
                {
                    "zonerange": 16*1024*1024,
                    "zonesize": 16*1024*1024,
                    "bs": 4096,
                    "size": 256*1024*1024,
                    "io_size": 256*1024*204,
                },
                {
                    "zonerange": 4096,
                    "zonesize": 4*4096,
                    "bs": 4096,
                    "size": 16*4096,
                    "io_size": 16*4096,
                },
                {
                    "zonerange": 16*1024*1024,
                    "zonesize": 32*1024*1024,
                    "bs": 4096,
                    "size": 256*1024*1024,
                    "io_size": 256*1024*204,
                },
                {
                    "zonerange": 8192,
                    "zonesize": 4096,
                    "bs": 4096,
                    "size": 16*4096,
                    "io_size": 16*4096,
                },
                {
                    "zonerange": 16*1024*1024,
                    "zonesize": 8*1024*1024,
                    "bs": 4096,
                    "size": 256*1024*1024,
                    "io_size": 256*1024*204,
                },
                # lfsr
                {
                    "random_generator": "lfsr",
                    "zonerange": 4096*1024,
                    "zonesize": 4096*1024,
                    "bs": 4096,
                    "offset": 8*4096*1024,
                    "size": 16*4096*1024,
                    "io_size": 16*4096*1024,
                },
                {
                    "random_generator": "lfsr",
                    "zonerange": 4096*1024,
                    "zonesize": 4096*1024,
                    "bs": 4096,
                    "size": 16*4096*1024,
                    "io_size": 16*4096*1024,
                },
                {
                    "random_generator": "lfsr",
                    "zonerange": 16*1024*1024,
                    "zonesize": 16*1024*1024,
                    "bs": 4096,
                    "size": 256*1024*1024,
                    "io_size": 256*1024*204,
                },
                {
                    "random_generator": "lfsr",
                    "zonerange": 4096*1024,
                    "zonesize": 4*4096*1024,
                    "bs": 4096,
                    "size": 16*4096*1024,
                    "io_size": 16*4096*1024,
                },
                {
                    "random_generator": "lfsr",
                    "zonerange": 16*1024*1024,
                    "zonesize": 32*1024*1024,
                    "bs": 4096,
                    "size": 256*1024*1024,
                    "io_size": 256*1024*204,
                },
                {
                    "random_generator": "lfsr",
                    "zonerange": 8192*1024,
                    "zonesize": 4096*1024,
                    "bs": 4096,
                    "size": 16*4096*1024,
                    "io_size": 16*4096*1024,
                },
                {
                    "random_generator": "lfsr",
                    "zonerange": 16*1024*1024,
                    "zonesize": 8*1024*1024,
                    "bs": 4096,
                    "size": 256*1024*1024,
                    "io_size": 256*1024*204,
                },
                # norandommap
                {
                    "norandommap": 1,
                    "zonerange": 4096,
                    "zonesize": 4096,
                    "bs": 4096,
                    "offset": 8*4096,
                    "size": 16*4096,
                    "io_size": 16*4096,
                },
                {
                    "norandommap": 1,
                    "zonerange": 4096,
                    "zonesize": 4096,
                    "bs": 4096,
                    "size": 16*4096,
                    "io_size": 16*4096,
                },
                {
                    "norandommap": 1,
                    "zonerange": 16*1024*1024,
                    "zonesize": 16*1024*1024,
                    "bs": 4096,
                    "size": 256*1024*1024,
                    "io_size": 256*1024*204,
                },
                {
                    "norandommap": 1,
                    "zonerange": 4096,
                    "zonesize": 8192,
                    "bs": 4096,
                    "size": 16*4096,
                    "io_size": 16*4096,
                },
                {
                    "norandommap": 1,
                    "zonerange": 16*1024*1024,
                    "zonesize": 32*1024*1024,
                    "bs": 4096,
                    "size": 256*1024*1024,
                    "io_size": 256*1024*204,
                },
                {
                    "norandommap": 1,
                    "zonerange": 8192,
                    "zonesize": 4096,
                    "bs": 4096,
                    "size": 16*4096,
                    "io_size": 16*4096,
                },
                {
                    "norandommap": 1,
                    "zonerange": 16*1024*1024,
                    "zonesize": 8*1024*1024,
                    "bs": 4096,
                    "size": 256*1024*1024,
                    "io_size": 256*1024*1024,
                },

            ]

    index = 1
    passed = 0
    failed = 0

    if args.filename:
        statinfo = os.stat(args.filename)
        filesize = statinfo.st_size
        if filesize == 0:
            f = os.open(args.filename, os.O_RDONLY)
            filesize = os.lseek(f, 0, os.SEEK_END)
            os.close(f)

    for test in tests:
        if args.filename:
            test['filename'] = args.filename
            test['filesize'] = filesize
        else:
            test['filesize'] = test['size']
        iops_log = run_fio(args.fio, test, index)
        status = check_output(iops_log, test)
        print("Test {0} {1}".format(index, ("PASSED" if status else "FAILED")))
        if status:
            passed = passed + 1
        else:
            failed = failed + 1
        index = index + 1

    print("{0} tests passed, {1} failed".format(passed, failed))

    sys.exit(failed)
