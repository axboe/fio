#!/usr/bin/env python3

"""
# strided.py
#
# Test zonemode=strided. This uses the null ioengine when no file is
# specified. If a file is specified, use it for randdom read testing.
# Some of the zoneranges in the tests are 16MiB. So when using a file
# a minimum size of 64MiB is recommended.
#
# USAGE
# python strided.py fio-executable [-f file/device]
#
# EXAMPLES
# python t/strided.py ./fio
# python t/strided.py ./fio -f /dev/sda
# dd if=/dev/zero of=temp bs=1M count=64
# python t/strided.py ./fio -f temp
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
"""

import os
import sys
import time
import argparse
from pathlib import Path
from fiotestlib import FioJobCmdTest, run_fio_tests


class StridedTest(FioJobCmdTest):
    """Test zonemode=strided."""

    def setup(self, parameters):
        fio_args = [
                    "--name=strided",
                    "--zonemode=strided",
                    "--log_offset=1",
                    "--randrepeat=0",
                    "--rw=randread",
                    f"--write_iops_log={self.filenames['iopslog']}",
                    f"--output={self.filenames['output']}",
                    f"--zonerange={self.fio_opts['zonerange']}",
                    f"--zonesize={self.fio_opts['zonesize']}",
                    f"--bs={self.fio_opts['bs']}",
                   ]

        for opt in ['norandommap', 'random_generator', 'offset']:
            if opt in self.fio_opts:
                option = f"--{opt}={self.fio_opts[opt]}"
                fio_args.append(option)

        if 'filename' in self.fio_opts:
            for opt in ['filename', 'filesize']:
                option = f"--{opt}={self.fio_opts[opt]}"
                fio_args.append(option)
        else:
            fio_args.append('--ioengine=null')
            for opt in ['size', 'io_size', 'filesize']:
                option = f"--{opt}={self.fio_opts[opt]}"
                fio_args.append(option)

        super().setup(fio_args)

    def check_result(self):
        super().check_result()
        if not self.passed:
            return

        zonestart = 0 if 'offset' not in self.fio_opts else self.fio_opts['offset']
        iospersize = self.fio_opts['zonesize'] / self.fio_opts['bs']
        iosperrange = self.fio_opts['zonerange'] / self.fio_opts['bs']
        iosperzone = 0
        lines = self.iops_log_lines.split('\n')
        zoneset = set()

        for line in lines:
            if len(line) == 0:
                continue

            if iosperzone == iospersize:
                # time to move to a new zone
                iosperzone = 0
                zoneset = set()
                zonestart += self.fio_opts['zonerange']
                if zonestart >= self.fio_opts['filesize']:
                    zonestart = 0 if 'offset' not in self.fio_opts else self.fio_opts['offset']

            iosperzone = iosperzone + 1
            tokens = line.split(',')
            offset = int(tokens[4])
            if offset < zonestart or offset >= zonestart + self.fio_opts['zonerange']:
                print(f"Offset {offset} outside of zone starting at {zonestart}")
                return

            # skip next section if norandommap is enabled with no
            # random_generator or with a random_generator != lfsr
            if 'norandommap' in self.fio_opts:
                if 'random_generator' in self.fio_opts:
                    if self.fio_opts['random_generator'] != 'lfsr':
                        continue
                else:
                    continue

            # we either have a random map enabled or we
            # are using an LFSR
            # so all blocks should be unique and we should have
            # covered the entire zone when iosperzone % iosperrange == 0
            block = (offset - zonestart) / self.fio_opts['bs']
            if block in zoneset:
                print(f"Offset {offset} in zone already touched")
                return

            zoneset.add(block)
            if iosperzone % iosperrange == 0:
                if len(zoneset) != iosperrange:
                    print(f"Expected {iosperrange} blocks in zone but only saw {len(zoneset)}")
                    return
                zoneset = set()


TEST_LIST = [   # randommap enabled
    {
        "test_id": 1,
        "fio_opts": {
            "zonerange": 4096,
            "zonesize": 4096,
            "bs": 4096,
            "offset": 8*4096,
            "size": 16*4096,
            "io_size": 16*4096,
            },
        "test_class": StridedTest,
    },
    {
        "test_id": 2,
        "fio_opts": {
            "zonerange": 4096,
            "zonesize": 4096,
            "bs": 4096,
            "size": 16*4096,
            "io_size": 16*4096,
            },
        "test_class": StridedTest,
    },
    {
        "test_id": 3,
        "fio_opts": {
            "zonerange": 16*1024*1024,
            "zonesize": 16*1024*1024,
            "bs": 4096,
            "size": 256*1024*1024,
            "io_size": 256*1024*204,
            },
        "test_class": StridedTest,
    },
    {
        "test_id": 4,
        "fio_opts": {
            "zonerange": 4096,
            "zonesize": 4*4096,
            "bs": 4096,
            "size": 16*4096,
            "io_size": 16*4096,
            },
        "test_class": StridedTest,
    },
    {
        "test_id": 5,
        "fio_opts": {
            "zonerange": 16*1024*1024,
            "zonesize": 32*1024*1024,
            "bs": 4096,
            "size": 256*1024*1024,
            "io_size": 256*1024*204,
            },
        "test_class": StridedTest,
    },
    {
        "test_id": 6,
        "fio_opts": {
            "zonerange": 8192,
            "zonesize": 4096,
            "bs": 4096,
            "size": 16*4096,
            "io_size": 16*4096,
            },
        "test_class": StridedTest,
    },
    {
        "test_id": 7,
        "fio_opts": {
            "zonerange": 16*1024*1024,
            "zonesize": 8*1024*1024,
            "bs": 4096,
            "size": 256*1024*1024,
            "io_size": 256*1024*204,
            },
        "test_class": StridedTest,
    },
            # lfsr
    {
        "test_id": 8,
        "fio_opts": {
            "random_generator": "lfsr",
            "zonerange": 4096*1024,
            "zonesize": 4096*1024,
            "bs": 4096,
            "offset": 8*4096*1024,
            "size": 16*4096*1024,
            "io_size": 16*4096*1024,
            },
        "test_class": StridedTest,
    },
    {
        "test_id": 9,
        "fio_opts": {
            "random_generator": "lfsr",
            "zonerange": 4096*1024,
            "zonesize": 4096*1024,
            "bs": 4096,
            "size": 16*4096*1024,
            "io_size": 16*4096*1024,
            },
        "test_class": StridedTest,
    },
    {
        "test_id": 10,
        "fio_opts": {
            "random_generator": "lfsr",
            "zonerange": 16*1024*1024,
            "zonesize": 16*1024*1024,
            "bs": 4096,
            "size": 256*1024*1024,
            "io_size": 256*1024*204,
            },
        "test_class": StridedTest,
    },
    {
        "test_id": 11,
        "fio_opts": {
            "random_generator": "lfsr",
            "zonerange": 4096*1024,
            "zonesize": 4*4096*1024,
            "bs": 4096,
            "size": 16*4096*1024,
            "io_size": 16*4096*1024,
            },
        "test_class": StridedTest,
    },
    {
        "test_id": 12,
        "fio_opts": {
            "random_generator": "lfsr",
            "zonerange": 16*1024*1024,
            "zonesize": 32*1024*1024,
            "bs": 4096,
            "size": 256*1024*1024,
            "io_size": 256*1024*204,
            },
        "test_class": StridedTest,
    },
    {
        "test_id": 13,
        "fio_opts": {
            "random_generator": "lfsr",
            "zonerange": 8192*1024,
            "zonesize": 4096*1024,
            "bs": 4096,
            "size": 16*4096*1024,
            "io_size": 16*4096*1024,
            },
        "test_class": StridedTest,
    },
    {
        "test_id": 14,
        "fio_opts": {
            "random_generator": "lfsr",
            "zonerange": 16*1024*1024,
            "zonesize": 8*1024*1024,
            "bs": 4096,
            "size": 256*1024*1024,
            "io_size": 256*1024*204,
            },
        "test_class": StridedTest,
    },
    # norandommap
    {
        "test_id": 15,
        "fio_opts": {
            "norandommap": 1,
            "zonerange": 4096,
            "zonesize": 4096,
            "bs": 4096,
            "offset": 8*4096,
            "size": 16*4096,
            "io_size": 16*4096,
            },
        "test_class": StridedTest,
    },
    {
        "test_id": 16,
        "fio_opts": {
            "norandommap": 1,
            "zonerange": 4096,
            "zonesize": 4096,
            "bs": 4096,
            "size": 16*4096,
            "io_size": 16*4096,
            },
        "test_class": StridedTest,
    },
    {
        "test_id": 17,
        "fio_opts": {
            "norandommap": 1,
            "zonerange": 16*1024*1024,
            "zonesize": 16*1024*1024,
            "bs": 4096,
            "size": 256*1024*1024,
            "io_size": 256*1024*204,
            },
        "test_class": StridedTest,
    },
    {
        "test_id": 18,
        "fio_opts": {
            "norandommap": 1,
            "zonerange": 4096,
            "zonesize": 8192,
            "bs": 4096,
            "size": 16*4096,
            "io_size": 16*4096,
            },
        "test_class": StridedTest,
    },
    {
        "test_id": 19,
        "fio_opts": {
            "norandommap": 1,
            "zonerange": 16*1024*1024,
            "zonesize": 32*1024*1024,
            "bs": 4096,
            "size": 256*1024*1024,
            "io_size": 256*1024*204,
            },
        "test_class": StridedTest,
    },
    {
        "test_id": 20,
        "fio_opts": {
            "norandommap": 1,
            "zonerange": 8192,
            "zonesize": 4096,
            "bs": 4096,
            "size": 16*4096,
            "io_size": 16*4096,
            },
        "test_class": StridedTest,
    },
    {
        "test_id": 21,
        "fio_opts": {
            "norandommap": 1,
            "zonerange": 16*1024*1024,
            "zonesize": 8*1024*1024,
            "bs": 4096,
            "size": 256*1024*1024,
            "io_size": 256*1024*1024,
            },
        "test_class": StridedTest,
    },
]


def parse_args():
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--fio', help='path to file executable (e.g., ./fio)')
    parser.add_argument('-a', '--artifact-root', help='artifact root directory')
    parser.add_argument('-s', '--skip', nargs='+', type=int,
                        help='list of test(s) to skip')
    parser.add_argument('-o', '--run-only', nargs='+', type=int,
                        help='list of test(s) to run, skipping all others')
    parser.add_argument('--dut',
                        help='target file/device to test.')
    args = parser.parse_args()

    return args


def main():
    """Run zonemode=strided tests."""

    args = parse_args()

    artifact_root = args.artifact_root if args.artifact_root else \
        f"strided-test-{time.strftime('%Y%m%d-%H%M%S')}"
    os.mkdir(artifact_root)
    print(f"Artifact directory is {artifact_root}")

    if args.fio:
        fio_path = str(Path(args.fio).absolute())
    else:
        fio_path = 'fio'
    print(f"fio path is {fio_path}")

    if args.dut:
        statinfo = os.stat(args.dut)
        filesize = statinfo.st_size
        if filesize == 0:
            f = os.open(args.dut, os.O_RDONLY)
            filesize = os.lseek(f, 0, os.SEEK_END)
            os.close(f)

    for test in TEST_LIST:
        if args.dut:
            test['fio_opts']['filename'] = os.path.abspath(args.dut)
            test['fio_opts']['filesize'] = filesize
        else:
            test['fio_opts']['filesize'] = test['fio_opts']['size']

    test_env = {
              'fio_path': fio_path,
              'fio_root': str(Path(__file__).absolute().parent.parent),
              'artifact_root': artifact_root,
              'basename': 'strided',
              }

    _, failed, _ = run_fio_tests(TEST_LIST, test_env, args)
    sys.exit(failed)


if __name__ == '__main__':
    main()
