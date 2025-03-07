#!/usr/bin/env python3
#
# Copyright 2024 Samsung Electronics Co., Ltd All Rights Reserved
#
# For conditions of distribution and use, see the accompanying COPYING file.
#
"""
# nvmept_streams.py
#
# Test fio's NVMe streams support using the io_uring_cmd ioengine with NVMe
# pass-through commands.
#
# USAGE
# see python3 nvmept_streams.py --help
#
# EXAMPLES
# python3 t/nvmept_streams.py --dut /dev/ng0n1
# python3 t/nvmept_streams.py --dut /dev/ng1n1 -f ./fio
#
# REQUIREMENTS
# Python 3.6
#
# WARNING
# This is a destructive test
#
# Enable streams with
# nvme dir-send -D 0 -O 1 -e 1 -T 1 /dev/nvme0n1
#
# See streams directive status with
# nvme dir-receive -D 0 -O 1 -H /dev/nvme0n1
"""
import os
import sys
import time
import locale
import logging
import argparse
import subprocess
from pathlib import Path
from fiotestlib import FioJobCmdTest, run_fio_tests
from fiotestcommon import SUCCESS_NONZERO


class StreamsTest(FioJobCmdTest):
    """
    NVMe pass-through test class for streams. Check to make sure output for
    selected data direction(s) is non-zero and that zero data appears for other
    directions.
    """

    def setup(self, parameters):
        """Setup a test."""

        fio_args = [
            "--name=nvmept-streams",
            "--ioengine=io_uring_cmd",
            "--cmd_type=nvme",
            "--randrepeat=0",
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
                    'buffer_pattern', 'verify_pattern', 'offset', 'dataplacement',
                    'plids', 'plid_select' ]:
            if opt in self.fio_opts:
                option = f"--{opt}={self.fio_opts[opt]}"
                fio_args.append(option)

        super().setup(fio_args)


    def check_result(self):
        try:
            self._check_result()
        finally:
            release_all_streams(self.fio_opts['filename'])


    def _check_result(self):

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

        stream_ids = [int(stream) for stream in self.fio_opts['plids'].split(',')]
        if not self.check_streams(self.fio_opts['filename'], stream_ids):
            self.passed = False
            logging.error("Streams not as expected")
        else:
            logging.debug("Streams created as expected")


    def check_streams(self, dut, stream_ids):
        """
        Confirm that the specified stream IDs exist on the specified device.
        """

        id_list = get_device_stream_ids(dut)
        if not id_list:
            return False

        for stream in stream_ids:
            if stream in id_list:
                logging.debug("Stream ID %d found active on device", stream)
                id_list.remove(stream)
            else:
                if self.__class__.__name__ != "StreamsTestRand":
                    logging.error("Stream ID %d not found on device", stream)
                else:
                    logging.debug("Stream ID %d not found on device", stream)
                return False

        if len(id_list) != 0:
            logging.error("Extra stream IDs %s found on device", str(id_list))
            return False

        return True


class StreamsTestRR(StreamsTest):
    """
    NVMe pass-through test class for streams. Check to make sure output for
    selected data direction(s) is non-zero and that zero data appears for other
    directions. Check that Stream IDs are accessed in round robin order.
    """

    def check_streams(self, dut, stream_ids):
        """
        The number of IOs is less than the number of stream IDs provided. Let N
        be the number of IOs. Make sure that the device only has the first N of
        the stream IDs provided.

        This will miss some cases where some other selection algorithm happens
        to select the first N stream IDs. The solution would be to repeat this
        test multiple times. Multiple trials passing would be evidence that
        round robin is working correctly.
        """

        id_list = get_device_stream_ids(dut)
        if not id_list:
            return False

        num_streams = int(self.fio_opts['io_size'] / self.fio_opts['bs'])
        stream_ids = sorted(stream_ids)[0:num_streams]

        return super().check_streams(dut, stream_ids)


class StreamsTestRand(StreamsTest):
    """
    NVMe pass-through test class for streams. Check to make sure output for
    selected data direction(s) is non-zero and that zero data appears for other
    directions. Check that Stream IDs are accessed in random order.
    """

    def check_streams(self, dut, stream_ids):
        """
        The number of IOs is less than the number of stream IDs provided. Let N
        be the number of IOs. Confirm that the stream IDs on the device are not
        the first N stream IDs.

        This will produce false positives because it is possible for the first
        N stream IDs to be randomly selected. We can reduce the probability of
        false positives by increasing N and increasing the number of streams
        IDs to choose from, although fio has a max of 16 placement IDs.
        """

        id_list = get_device_stream_ids(dut)
        if not id_list:
            return False

        num_streams = int(self.fio_opts['io_size'] / self.fio_opts['bs'])
        stream_ids = sorted(stream_ids)[0:num_streams]

        return not super().check_streams(dut, stream_ids)


def get_device_stream_ids(dut):
    cmd = f"sudo nvme dir-receive -D 1 -O 2 -H {dut}"
    logging.debug("check streams command: %s", cmd)
    cmd = cmd.split(' ')
    cmd_result = subprocess.run(cmd, capture_output=True, check=False,
                                encoding=locale.getpreferredencoding())

    logging.debug(cmd_result.stdout)

    if cmd_result.returncode != 0:
        logging.error("Error obtaining device %s stream IDs: %s", dut, cmd_result.stderr)
        return False

    id_list = []
    for line in cmd_result.stdout.split('\n'):
        if not 'Stream Identifier' in line:
            continue
        tokens = line.split(':')
        id_list.append(int(tokens[1]))

    return id_list


def release_stream(dut, stream_id):
    """
    Release stream on given device with selected ID.
    """
    cmd = f"nvme dir-send -D 1 -O 1 -S {stream_id} {dut}"
    logging.debug("release stream command: %s", cmd)
    cmd = cmd.split(' ')
    cmd_result = subprocess.run(cmd, capture_output=True, check=False,
                                encoding=locale.getpreferredencoding())

    if cmd_result.returncode != 0:
        logging.error("Error releasing %s stream %d", dut, stream_id)
        return False

    return True


def release_all_streams(dut):
    """
    Release all streams on specified device.
    """

    id_list = get_device_stream_ids(dut)
    if not id_list:
        return False

    for stream in id_list:
        if not release_stream(dut, stream):
            return False

    return True


TEST_LIST = [
    # 4k block size
    # {seq write, rand write} x {single stream, four streams}
    {
        "test_id": 1,
        "fio_opts": {
            "rw": 'write',
            "bs": 4096,
            "io_size": 256*1024*1024,
            "verify": "crc32c",
            "plids": "8",
            "dataplacement": "streams",
            "output-format": "json",
            },
        "test_class": StreamsTest,
    },
    {
        "test_id": 2,
        "fio_opts": {
            "rw": 'randwrite',
            "bs": 4096,
            "io_size": 256*1024*1024,
            "verify": "crc32c",
            "plids": "3",
            "dataplacement": "streams",
            "output-format": "json",
            },
        "test_class": StreamsTest,
    },
    {
        "test_id": 3,
        "fio_opts": {
            "rw": 'write',
            "bs": 4096,
            "io_size": 256*1024*1024,
            "verify": "crc32c",
            "plids": "1,2,3,4",
            "dataplacement": "streams",
            "output-format": "json",
            },
        "test_class": StreamsTest,
    },
    {
        "test_id": 4,
        "fio_opts": {
            "rw": 'randwrite',
            "bs": 4096,
            "io_size": 256*1024*1024,
            "verify": "crc32c",
            "plids": "5,6,7,8",
            "dataplacement": "streams",
            "output-format": "json",
            },
        "test_class": StreamsTest,
    },
    # 256KiB block size
    # {seq write, rand write} x {single stream, four streams}
    {
        "test_id": 10,
        "fio_opts": {
            "rw": 'write',
            "bs": 256*1024,
            "io_size": 256*1024*1024,
            "verify": "crc32c",
            "plids": "88",
            "dataplacement": "streams",
            "output-format": "json",
            },
        "test_class": StreamsTest,
    },
    {
        "test_id": 11,
        "fio_opts": {
            "rw": 'randwrite',
            "bs": 256*1024,
            "io_size": 256*1024*1024,
            "verify": "crc32c",
            "plids": "20",
            "dataplacement": "streams",
            "output-format": "json",
            },
        "test_class": StreamsTest,
    },
    {
        "test_id": 12,
        "fio_opts": {
            "rw": 'write',
            "bs": 256*1024,
            "io_size": 256*1024*1024,
            "verify": "crc32c",
            "plids": "16,32,64,128",
            "dataplacement": "streams",
            "output-format": "json",
            },
        "test_class": StreamsTest,
    },
    {
        "test_id": 13,
        "fio_opts": {
            "rw": 'randwrite',
            "bs": 256*1024,
            "io_size": 256*1024*1024,
            "verify": "crc32c",
            "plids": "10,20,40,82",
            "dataplacement": "streams",
            "output-format": "json",
            },
        "test_class": StreamsTest,
    },
    # Test placement ID selection patterns
    # default is round robin
    {
        "test_id": 20,
        "fio_opts": {
            "rw": 'write',
            "bs": 4096,
            "io_size": 8192,
            "plids": '88,99,100,123,124,125,126,127,128,129,130,131,132,133,134,135',
            "dataplacement": "streams",
            "output-format": "json",
            },
        "test_class": StreamsTestRR,
    },
    {
        "test_id": 21,
        "fio_opts": {
            "rw": 'write',
            "bs": 4096,
            "io_size": 8192,
            "plids": '12,88,99,100,123,124,125,126,127,128,129,130,131,132,133,11',
            "dataplacement": "streams",
            "output-format": "json",
            },
        "test_class": StreamsTestRR,
    },
    # explicitly select round robin
    {
        "test_id": 22,
        "fio_opts": {
            "rw": 'write',
            "bs": 4096,
            "io_size": 8192,
            "plids": '22,88,99,100,123,124,125,126,127,128,129,130,131,132,133,134',
            "dataplacement": "streams",
            "output-format": "json",
            "plid_select": "roundrobin",
            },
        "test_class": StreamsTestRR,
    },
    # explicitly select random
    {
        "test_id": 23,
        "fio_opts": {
            "rw": 'write',
            "bs": 4096,
            "io_size": 8192,
            "plids": '1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16',
            "dataplacement": "streams",
            "output-format": "json",
            "plid_select": "random",
            },
        "test_class": StreamsTestRand,
    },
    # Error case with placement ID > 0xFFFF
    {
        "test_id": 30,
        "fio_opts": {
            "rw": 'write',
            "bs": 4096,
            "io_size": 8192,
            "plids": "1,2,3,0x10000",
            "dataplacement": "streams",
            "output-format": "normal",
            "plid_select": "random",
            },
        "test_class": StreamsTestRand,
        "success": SUCCESS_NONZERO,
    },
    # Error case with no stream IDs provided
    {
        "test_id": 31,
        "fio_opts": {
            "rw": 'write',
            "bs": 4096,
            "io_size": 8192,
            "dataplacement": "streams",
            "output-format": "normal",
            },
        "test_class": StreamsTestRand,
        "success": SUCCESS_NONZERO,
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
        f"nvmept-streams-test-{time.strftime('%Y%m%d-%H%M%S')}"
    os.mkdir(artifact_root)
    print(f"Artifact directory is {artifact_root}")

    if args.fio:
        fio_path = str(Path(args.fio).absolute())
    else:
        fio_path = 'fio'
    print(f"fio path is {fio_path}")

    for test in TEST_LIST:
        test['fio_opts']['filename'] = args.dut

    release_all_streams(args.dut)
    test_env = {
              'fio_path': fio_path,
              'fio_root': str(Path(__file__).absolute().parent.parent),
              'artifact_root': artifact_root,
              'basename': 'nvmept-streams',
              }

    _, failed, _ = run_fio_tests(TEST_LIST, test_env, args)
    sys.exit(failed)


if __name__ == '__main__':
    main()
