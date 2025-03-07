#!/usr/bin/env python3
#
# Copyright 2024 Samsung Electronics Co., Ltd All Rights Reserved
#
# For conditions of distribution and use, see the accompanying COPYING file.
#
"""
# nvmept_trim.py
#
# Test fio's io_uring_cmd ioengine with NVMe pass-through dataset management
# commands that trim multiple ranges.
#
# USAGE
# see python3 nvmept_trim.py --help
#
# EXAMPLES
# python3 t/nvmept_trim.py --dut /dev/ng0n1
# python3 t/nvmept_trim.py --dut /dev/ng1n1 -f ./fio
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


class TrimTest(FioJobCmdTest):
    """
    NVMe pass-through test class. Check to make sure output for selected data
    direction(s) is non-zero and that zero data appears for other directions.
    """

    def setup(self, parameters):
        """Setup a test."""

        fio_args = [
            "--name=nvmept-trim",
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
                    'buffer_pattern', 'verify_pattern', 'verify', 'offset']:
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

        if 'iodepth' in self.fio_opts:
            # We will need to figure something out if any test uses an iodepth
            # different from 8
            if job['iodepth_level']['8'] < 95:
                logging.error("Did not achieve requested iodepth")
                self.passed = False
            else:
                logging.debug("iodepth 8 target met %s", job['iodepth_level']['8'])


class RangeTrimTest(TrimTest):
    """
    Multi-range trim test class.
    """

    def get_bs(self):
        """Calculate block size and determine whether bs will be an average or exact."""

        if 'bs' in self.fio_opts:
            exact_size = True
            bs = self.fio_opts['bs']
        elif 'bssplit' in self.fio_opts:
            exact_size = False
            bs = 0
            total = 0
            for split in self.fio_opts['bssplit'].split(':'):
                [blocksize, share] = split.split('/')
                total += int(share)
                bs += int(blocksize) * int(share) / 100
            if total != 100:
                logging.error("bssplit '%s' total percentage is not 100", self.fio_opts['bssplit'])
                self.passed = False
            else:
                logging.debug("bssplit: average block size is %d", int(bs))
            # The only check we do here for bssplit is to calculate an average
            # blocksize and see if the IOPS and bw are consistent
        elif 'bsrange' in self.fio_opts:
            exact_size = False
            [minbs, maxbs] = self.fio_opts['bsrange'].split('-')
            minbs = int(minbs)
            maxbs = int(maxbs)
            bs = int((minbs + maxbs) / 2)
            logging.debug("bsrange: average block size is %d", int(bs))
            # The only check we do here for bsrange is to calculate an average
            # blocksize and see if the IOPS and bw are consistent
        else:
            exact_size = True
            bs = 4096

        return bs, exact_size


    def check_result(self):
        """
        Make sure that the number of IO requests is consistent with the
        blocksize and num_range values. In other words, if the blocksize is
        4KiB and num_range is 2, we should have 128 IO requests to trim 1MiB.
        """
        # TODO Enable debug output to check the actual offsets

        super().check_result()

        if not self.passed or 'json' not in self.fio_opts['output-format']:
            return

        job = self.json_data['jobs'][0]['trim']
        bs, exact_size = self.get_bs()

        # make sure bw and IOPS are consistent
        bw = job['bw_bytes']
        iops = job['iops']
        runtime = job['runtime']

        calculated = int(bw*runtime/1000)
        expected = job['io_bytes']
        if abs(calculated - expected) / expected > 0.05:
            logging.error("Total bytes %d from bw does not match reported total bytes %d",
                          calculated, expected)
            self.passed = False
        else:
            logging.debug("Total bytes %d from bw matches reported total bytes %d", calculated,
                          expected)

        calculated = int(iops*runtime/1000*bs*self.fio_opts['num_range'])
        if abs(calculated - expected) / expected > 0.05:
            logging.error("Total bytes %d from IOPS does not match reported total bytes %d",
                          calculated, expected)
            self.passed = False
        else:
            logging.debug("Total bytes %d from IOPS matches reported total bytes %d", calculated,
                          expected)

        if 'size' in self.fio_opts:
            io_count = self.fio_opts['size'] / self.fio_opts['num_range'] / bs
            if exact_size:
                delta = 0.1
            else:
                delta = 0.05*job['total_ios']

            if abs(job['total_ios'] - io_count) > delta:
                logging.error("Expected numbers of IOs %d does not match actual value %d",
                              io_count, job['total_ios'])
                self.passed = False
            else:
                logging.debug("Expected numbers of IOs %d matches actual value %d", io_count,
                              job['total_ios'])

        if 'rate' in self.fio_opts:
            if abs(bw - self.fio_opts['rate']) / self.fio_opts['rate'] > 0.05:
                logging.error("Actual rate %f does not match expected rate %f", bw,
                              self.fio_opts['rate'])
                self.passed = False
            else:
                logging.debug("Actual rate %f matches expeected rate %f", bw, self.fio_opts['rate'])



TEST_LIST = [
    # The group of tests below checks existing use cases to make sure there are
    # no regressions.
    {
        "test_id": 1,
        "fio_opts": {
            "rw": 'trim',
            "time_based": 1,
            "runtime": 3,
            "output-format": "json",
            },
        "test_class": TrimTest,
    },
    {
        "test_id": 2,
        "fio_opts": {
            "rw": 'randtrim',
            "time_based": 1,
            "runtime": 3,
            "output-format": "json",
            },
        "test_class": TrimTest,
    },
    {
        "test_id": 3,
        "fio_opts": {
            "rw": 'trim',
            "time_based": 1,
            "runtime": 3,
            "iodepth": 8,
            "iodepth_batch": 4,
            "iodepth_batch_complete": 4,
            "output-format": "json",
            },
        "test_class": TrimTest,
    },
    {
        "test_id": 4,
        "fio_opts": {
            "rw": 'randtrim',
            "time_based": 1,
            "runtime": 3,
            "iodepth": 8,
            "iodepth_batch": 4,
            "iodepth_batch_complete": 4,
            "output-format": "json",
            },
        "test_class": TrimTest,
    },
    {
        "test_id": 5,
        "fio_opts": {
            "rw": 'trimwrite',
            "time_based": 1,
            "runtime": 3,
            "output-format": "json",
            },
        "test_class": TrimTest,
    },
    {
        "test_id": 6,
        "fio_opts": {
            "rw": 'randtrimwrite',
            "time_based": 1,
            "runtime": 3,
            "output-format": "json",
            },
        "test_class": TrimTest,
    },
    {
        "test_id": 7,
        "fio_opts": {
            "rw": 'randtrim',
            "time_based": 1,
            "runtime": 3,
            "fixedbufs": 0,
            "nonvectored": 1,
            "force_async": 1,
            "registerfiles": 1,
            "sqthread_poll": 1,
            "fixedbuffs": 1,
            "output-format": "json",
            },
        "test_class": TrimTest,
    },
    # The group of tests below try out the new functionality
    {
        "test_id": 100,
        "fio_opts": {
            "rw": 'trim',
            "num_range": 2,
            "size": 16*1024*1024,
            "output-format": "json",
            },
        "test_class": RangeTrimTest,
    },
    {
        "test_id": 101,
        "fio_opts": {
            "rw": 'randtrim',
            "num_range": 2,
            "size": 16*1024*1024,
            "output-format": "json",
            },
        "test_class": RangeTrimTest,
    },
    {
        "test_id": 102,
        "fio_opts": {
            "rw": 'randtrim',
            "num_range": 256,
            "size": 64*1024*1024,
            "output-format": "json",
            },
        "test_class": RangeTrimTest,
    },
    {
        "test_id": 103,
        "fio_opts": {
            "rw": 'trim',
            "num_range": 2,
            "bs": 16*1024,
            "size": 32*1024*1024,
            "output-format": "json",
            },
        "test_class": RangeTrimTest,
    },
    {
        "test_id": 104,
        "fio_opts": {
            "rw": 'randtrim',
            "num_range": 2,
            "bs": 16*1024,
            "size": 32*1024*1024,
            "output-format": "json",
            },
        "test_class": RangeTrimTest,
    },
    {
        "test_id": 105,
        "fio_opts": {
            "rw": 'randtrim',
            "num_range": 2,
            "bssplit": "4096/50:16384/50",
            "size": 80*1024*1024,
            "output-format": "json",
            "randrepeat": 0,
            },
        "test_class": RangeTrimTest,
    },
    {
        "test_id": 106,
        "fio_opts": {
            "rw": 'randtrim',
            "num_range": 4,
            "bssplit": "4096/25:8192/25:12288/25:16384/25",
            "size": 80*1024*1024,
            "output-format": "json",
            "randrepeat": 0,
            },
        "test_class": RangeTrimTest,
    },
    {
        "test_id": 107,
        "fio_opts": {
            "rw": 'randtrim',
            "num_range": 4,
            "bssplit": "4096/20:8192/20:12288/20:16384/20:20480/20",
            "size": 72*1024*1024,
            "output-format": "json",
            "randrepeat": 0,
            },
        "test_class": RangeTrimTest,
    },
    {
        "test_id": 108,
        "fio_opts": {
            "rw": 'randtrim',
            "num_range": 2,
            "bsrange": "4096-16384",
            "size": 80*1024*1024,
            "output-format": "json",
            "randrepeat": 0,
            },
        "test_class": RangeTrimTest,
    },
    {
        "test_id": 109,
        "fio_opts": {
            "rw": 'randtrim',
            "num_range": 4,
            "bsrange": "4096-20480",
            "size": 72*1024*1024,
            "output-format": "json",
            "randrepeat": 0,
            },
        "test_class": RangeTrimTest,
    },
    {
        "test_id": 110,
        "fio_opts": {
            "rw": 'randtrim',
            "time_based": 1,
            "runtime": 10,
            "rate": 1024*1024,
            "num_range": 2,
            "output-format": "json",
            },
        "test_class": RangeTrimTest,
    },
    # All of the tests below should fail
    # TODO check the error messages resulting from the jobs below
    {
        "test_id": 200,
        "fio_opts": {
            "rw": 'randtrimwrite',
            "time_based": 1,
            "runtime": 10,
            "rate": 1024*1024,
            "num_range": 2,
            "output-format": "normal",
            },
        "test_class": RangeTrimTest,
        "success": SUCCESS_NONZERO,
    },
    {
        "test_id": 201,
        "fio_opts": {
            "rw": 'trimwrite',
            "time_based": 1,
            "runtime": 10,
            "rate": 1024*1024,
            "num_range": 2,
            "output-format": "normal",
            },
        "test_class": RangeTrimTest,
        "success": SUCCESS_NONZERO,
    },
    {
        "test_id": 202,
        "fio_opts": {
            "rw": 'trim',
            "time_based": 1,
            "runtime": 10,
            "num_range": 257,
            "output-format": "normal",
            },
        "test_class": RangeTrimTest,
        "success": SUCCESS_NONZERO,
    },
    # The sequence of jobs below constitute a single test with multiple steps
    # - write a data pattern
    # - verify the data pattern
    # - trim the first half of the LBA space
    # - verify that the trim'd LBA space no longer returns the original data pattern
    # - verify that the remaining LBA space has the expected pattern
    {
        "test_id": 300,
        "fio_opts": {
            "rw": 'write',
            "output-format": 'json',
            "buffer_pattern": 0x0f,
            "size": 256*1024*1024,
            "bs": 256*1024,
            },
        "test_class": TrimTest,
    },
    {
        "test_id": 301,
        "fio_opts": {
            "rw": 'read',
            "output-format": 'json',
            "verify_pattern": 0x0f,
            "verify": "pattern",
            "size": 256*1024*1024,
            "bs": 256*1024,
            },
        "test_class": TrimTest,
    },
    {
        "test_id": 302,
        "fio_opts": {
            "rw": 'randtrim',
            "num_range": 8,
            "output-format": 'json',
            "size": 128*1024*1024,
            "bs": 256*1024,
            },
        "test_class": TrimTest,
    },
    # The identify namespace data structure has a DLFEAT field which specifies
    # what happens when reading data from deallocated blocks. There are three
    # options:
    # - read behavior not reported
    # - deallocated logical block returns all bytes 0x0
    # - deallocated logical block returns all bytes 0xff
    # The test below merely checks that the original data pattern is not returned.
    # Source: Figure 97 from
    # https://nvmexpress.org/wp-content/uploads/NVM-Express-NVM-Command-Set-Specification-1.0c-2022.10.03-Ratified.pdf
    {
        "test_id": 303,
        "fio_opts": {
            "rw": 'read',
            "output-format": 'json',
            "verify_pattern": 0x0f,
            "verify": "pattern",
            "size": 128*1024*1024,
            "bs": 256*1024,
            },
        "test_class": TrimTest,
        "success": SUCCESS_NONZERO,
    },
    {
        "test_id": 304,
        "fio_opts": {
            "rw": 'read',
            "output-format": 'json',
            "verify_pattern": 0x0f,
            "verify": "pattern",
            "offset": 128*1024*1024,
            "size": 128*1024*1024,
            "bs": 256*1024,
            },
        "test_class": TrimTest,
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
        f"nvmept-trim-test-{time.strftime('%Y%m%d-%H%M%S')}"
    os.mkdir(artifact_root)
    print(f"Artifact directory is {artifact_root}")

    if args.fio:
        fio_path = str(Path(args.fio).absolute())
    else:
        fio_path = 'fio'
    print(f"fio path is {fio_path}")

    for test in TEST_LIST:
        test['fio_opts']['filename'] = args.dut

    test_env = {
              'fio_path': fio_path,
              'fio_root': str(Path(__file__).absolute().parent.parent),
              'artifact_root': artifact_root,
              'basename': 'nvmept-trim',
              }

    _, failed, _ = run_fio_tests(TEST_LIST, test_env, args)
    sys.exit(failed)


if __name__ == '__main__':
    main()
