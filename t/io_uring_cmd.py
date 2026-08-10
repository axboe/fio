#!/usr/bin/env python3
r"""
# io_uring_cmd.py
#
# Test fio's io_uring_cmd ioengine.
#
# USAGE
# see python3 io_uring_cmd.py --help
#
# EXAMPLES
# python3 t/io_uring_cmd.py --dut /dev/ng0n1
# python3 t/io_uring_cmd.py --cmd_type=bsg --dut "/dev/bsg/6\:0\:0\:0"
#
# REQUIREMENTS
# Python 3.6
#
"""
import os
import sys
import time
import argparse
from pathlib import Path
from fiotestlib import FioJobCmdTest, run_fio_tests
from fiotestcommon import SUCCESS_NONZERO, SUCCESS_DEFAULT


class PassThruTest(FioJobCmdTest):
    """
    io_uring_cmd pass-through test class. Check to make sure output for
    selected data direction(s) is non-zero and that zero data appears for other
    directions.
    """

    def setup(self, parameters):
        """Setup a test."""

        fio_args = [
            "--name=io_uring_cmd",
            "--ioengine=io_uring_cmd",
            "--iodepth=8",
            "--iodepth_batch=4",
            "--iodepth_batch_complete=4",
            f"--cmd_type={self.fio_opts['cmd_type']}",
            f"--filename={self.fio_opts['filename']}",
            f"--rw={self.fio_opts['rw']}",
            f"--output={self.filenames['output']}",
            f"--output-format={self.fio_opts['output-format']}",
        ]
        for opt in ['fixedbufs', 'nonvectored', 'force_async', 'registerfiles',
                    'sqthread_poll', 'sqthread_poll_cpu', 'hipri', 'nowait',
                    'time_based', 'runtime', 'verify', 'io_size', 'readfua',
                    'writefua', "cdb_len", "write_mode", "read_mode",
                    "verify_bytchk", "buffer_pattern", "bs", "filesize", ]:
            if opt in self.fio_opts:
                option = f"--{opt}={self.fio_opts[opt]}"
                fio_args.append(option)

        super().setup(fio_args)


    def check_result(self):
        super().check_result()

        if 'rw' not in self.fio_opts:
            return

        if not self.passed:
            return

        if 'json' not in self.fio_opts['output-format']:
            return

        if self.success == SUCCESS_NONZERO:
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
            print(f"Unhandled rw value {self.fio_opts['rw']}")
            self.passed = False

        if job['iodepth_level']['8'] < 95:
            print("Did not achieve requested iodepth")
            self.passed = False


class FlushTest(FioJobCmdTest):
    def setup(self, parameters):
        fio_args = [
            "--name=io_uring_cmd-flush",
            "--ioengine=io_uring_cmd",
            "--randrepeat=0",
            f"--cmd_type={self.fio_opts['cmd_type']}",
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
                    'buffer_pattern', 'verify_pattern', 'offset', 'fdp',
                    'fdp_pli', 'fdp_pli_select', 'dataplacement', 'plid_select',
                    'plids', 'dp_scheme', 'number_ios', 'read_iolog', 'fsync']:
            if opt in self.fio_opts:
                option = f"--{opt}={self.fio_opts[opt]}"
                fio_args.append(option)

        super().setup(fio_args)

    def check_result(self):
        super().check_result()

        job = self.json_data['jobs'][0]

        rw = self.fio_opts['rw']
        fsync = self.fio_opts['fsync']

        nr_write = job['write']['total_ios']
        nr_sync = job['sync']['total_ios']

        nr_sync_exp = nr_write // fsync

        # The actual number of DDIR_SYNC issued might miss one DDIR_SYNC command
        # when the last command issued was DDIR_WRITE command.
        if not ((nr_sync == nr_sync_exp) or (nr_sync + 1 == nr_sync_exp)):
            logging.error(f"nr_write={nr_write}, nr_sync={nr_sync}, fsync={fsync}")
            self.passed = False


TEST_LIST = [
    {
        "test_id": 1,
        "fio_opts": {
            "rw": 'read',
            "timebased": 1,
            "runtime": 3,
            "output-format": "json",
            },
        "test_class": PassThruTest,
    },
    {
        "test_id": 2,
        "fio_opts": {
            "rw": 'randread',
            "timebased": 1,
            "runtime": 3,
            "output-format": "json",
            },
        "test_class": PassThruTest,
    },
    {
        "test_id": 3,
        "fio_opts": {
            "rw": 'write',
            "timebased": 1,
            "runtime": 3,
            "output-format": "json",
            },
        "test_class": PassThruTest,
    },
    {
        "test_id": 4,
        "fio_opts": {
            "rw": 'randwrite',
            "timebased": 1,
            "runtime": 3,
            "output-format": "json",
            },
        "test_class": PassThruTest,
    },
    {
        "test_id": 5,
        "fio_opts": {
            "rw": 'trim',
            "timebased": 1,
            "runtime": 3,
            "output-format": "json",
            },
        "test_class": PassThruTest,
    },
    {
        "test_id": 6,
        "fio_opts": {
            "rw": 'randtrim',
            "timebased": 1,
            "runtime": 3,
            "output-format": "json",
            },
        "test_class": PassThruTest,
    },
    {
        "test_id": 7,
        "fio_opts": {
            "rw": 'write',
            "io_size": 1024*1024,
            "verify": "crc32c",
            "output-format": "json",
            },
        "test_class": PassThruTest,
    },
    {
        "test_id": 8,
        "fio_opts": {
            "rw": 'randwrite',
            "io_size": 1024*1024,
            "verify": "crc32c",
            "output-format": "json",
            },
        "test_class": PassThruTest,
    },
    {
        "test_id": 9,
        "fio_opts": {
            "rw": 'readwrite',
            "timebased": 1,
            "runtime": 3,
            "output-format": "json",
            },
        "test_class": PassThruTest,
    },
    {
        "test_id": 10,
        "fio_opts": {
            "rw": 'randrw',
            "timebased": 1,
            "runtime": 3,
            "output-format": "json",
            },
        "test_class": PassThruTest,
    },
    {
        "test_id": 11,
        "fio_opts": {
            "rw": 'trimwrite',
            "timebased": 1,
            "runtime": 3,
            "output-format": "json",
            },
        "test_class": PassThruTest,
    },
    {
        "test_id": 12,
        "fio_opts": {
            "rw": 'randtrimwrite',
            "timebased": 1,
            "runtime": 3,
            "output-format": "json",
            },
        "test_class": PassThruTest,
    },
    {
        "test_id": 13,
        "fio_opts": {
            "rw": 'randread',
            "timebased": 1,
            "runtime": 3,
            "fixedbufs": 1,
            "nonvectored": 1,
            "force_async": 1,
            "registerfiles": 1,
            "sqthread_poll": 1,
            "output-format": "json",
            },
        "test_class": PassThruTest,
    },
    {
        "test_id": 14,
        "fio_opts": {
            "rw": 'randwrite',
            "timebased": 1,
            "runtime": 3,
            "fixedbufs": 1,
            "nonvectored": 1,
            "force_async": 1,
            "registerfiles": 1,
            "sqthread_poll": 1,
            "output-format": "json",
            },
        "test_class": PassThruTest,
    },
    {
        # We can't enable fixedbufs because for trim-only
        # workloads fio actually does not allocate any buffers
        "test_id": 15,
        "fio_opts": {
            "rw": 'randtrim',
            "timebased": 1,
            "runtime": 3,
            "fixedbufs": 0,
            "nonvectored": 1,
            "force_async": 1,
            "registerfiles": 1,
            "sqthread_poll": 1,
            "output-format": "json",
            },
        "test_class": PassThruTest,
    },
    {
        "test_id": 16,
        "fio_opts": {
            "rw": 'read',
            "bs": 4096,
            "number_ios": 10,
            "fsync": 1,
            "output-format": "json",
            },
        "test_class": FlushTest,
    },
    {
        "test_id": 17,
        "fio_opts": {
            "rw": 'write',
            "bs": 4096,
            "number_ios": 10,
            "fsync": 1,
            "output-format": "json",
            },
        "test_class": FlushTest,
    },
    {
        "test_id": 18,
        "fio_opts": {
            "rw": 'readwrite',
            "bs": 4096,
            "number_ios": 10,
            "fsync": 1,
            "output-format": "json",
            },
        "test_class": FlushTest,
    },
    {
        "test_id": 19,
        "fio_opts": {
            "rw": 'trimwrite',
            "bs": 4096,
            "number_ios": 10,
            "fsync": 1,
            "output-format": "json",
            },
        "test_class": FlushTest,
    },
    #
    # Run a test with writefua and readfua
    #
    {
        "test_id": 20,
        "fio_opts": {
            "rw": 'randrw',
            "writefua": 1,
            "readfua": 1,
            "timebased": 1,
            "runtime": 3,
            "output-format": "json",
            },
        "test_class": PassThruTest,
    },

#
# These tests only work for cmd_type=bsg
#

    # cdb_len tests
    {
        "test_id": 100,
        "cmd_types": ['bsg',],
        "fio_opts": {
            "rw": 'randrw',
            "cdb_len": 0,
            "timebased": 1,
            "runtime": 3,
            "output-format": "json",
            },
        "test_class": PassThruTest,
    },
    {
        "test_id": 101,
        "cmd_types": ['bsg',],
        "fio_opts": {
            "rw": 'randrw',
            "cdb_len": 10,
            "timebased": 1,
            "runtime": 3,
            "output-format": "json",
            },
        "test_class": PassThruTest,
    },
    {
        "test_id": 102,
        "cmd_types": ['bsg',],
        "fio_opts": {
            "rw": 'randrw',
            "cdb_len": 16,
            "timebased": 1,
            "runtime": 3,
            "output-format": "json",
            },
        "test_class": PassThruTest,
    },
    {
        "test_id": 103,
        "cmd_types": ['bsg',],
        "fio_opts": {
            "rw": 'randrw',
            "cdb_len": 32,
            "timebased": 1,
            "runtime": 3,
            "output-format": "json",
            },
        "test_class": PassThruTest,
    },
    {
        "test_id": 104,
        "cmd_types": ['bsg',],
        "fio_opts": {
            "rw": 'randrw',
            "cdb_len": 99,
            "timebased": 1,
            "runtime": 3,
            "output-format": "normal",
            },
        "success": SUCCESS_NONZERO,
        "test_class": PassThruTest,
    },

    # write_mode=verify tests
    # first precondition with a known pattern
    # and then try to verify it
    {
        "test_id": 105,
        "cmd_types": ['bsg',],
        "fio_opts": {
            "rw": 'write',
            "filesize": "8M",
            "buffer_pattern": '"98765432"',
            "output-format": "json",
            },
        "test_class": PassThruTest,
    },
    {
        "test_id": 106,
        "cmd_types": ['bsg',],
        "fio_opts": {
            "rw": 'randwrite',
            "filesize": "8M",
            "write_mode": "verify",
            "buffer_pattern": '"98765432"',
            "verify_bytchk": 0,
            "output-format": "json",
            },
        "test_class": PassThruTest,
    },
    {
        "test_id": 107,
        "cmd_types": ['bsg',],
        "fio_opts": {
            "rw": 'randwrite',
            "filesize": "8M",
            "write_mode": "verify",
            "buffer_pattern": '"98765432"',
            "verify_bytchk": 1,
            "output-format": "json",
            },
        "test_class": PassThruTest,
    },
    {
        "test_id": 108,
        "cmd_types": ['bsg',],
        "fio_opts": {
            "rw": 'randwrite',
            "bs": "8k",
            "filesize": "8M",
            "write_mode": "verify",
            "buffer_pattern": '"98765432"',
            "verify_bytchk": 3,
            "output-format": "json",
            },
        "test_class": PassThruTest,
    },
    # The following two tests should fail because we are trying to verify
    # device contents against randomly generated data
    {
        "test_id": 109,
        "cmd_types": ['bsg',],
        "fio_opts": {
            "rw": 'write',
            "filesize": "8M",
            "write_mode": "verify",
            "verify_bytchk": 1,
            "output-format": "json",
            },
        "success": SUCCESS_NONZERO,
        "test_class": PassThruTest,
    },
    {
        "test_id": 110,
        "cmd_types": ['bsg',],
        "fio_opts": {
            "rw": 'write',
            "bs": "8k",
            "filesize": "8M",
            "write_mode": "verify",
            "verify_bytchk": 3,
            "output-format": "json",
            },
        "success": SUCCESS_NONZERO,
        "test_class": PassThruTest,
    },
    # This test should because because we are specifying verify_bytchk with
    # write_mode=write
    {
        "test_id": 111,
        "cmd_types": ['bsg',],
        "fio_opts": {
            "rw": 'write',
            "verify_bytchk": 1,
            "filesize": "8M",
            "buffer_pattern": '"98765432"',
            "output-format": "json",
            },
        "success": SUCCESS_NONZERO,
        "test_class": PassThruTest,
    },
    # This test should because because we are specifying writefua with
    # write_mode=verify
    {
        "test_id": 112,
        "cmd_types": ['bsg',],
        "fio_opts": {
            "rw": 'write',
            "write_mode": "verify",
            "verify_bytchk": 1,
            "writefua": 1,
            "filesize": "8M",
            "buffer_pattern": '"98765432"',
            "output-format": "json",
            },
        "success": SUCCESS_NONZERO,
        "test_class": PassThruTest,
    },

    # read_mode=prefetch tests
    {
        "test_id": 113,
        "cmd_types": ['bsg',],
        "fio_opts": {
            "rw": 'read',
            "timebased": 1,
            "runtime": 3,
            "read_mode": "prefetch",
            "output-format": "json",
            },
        "test_class": PassThruTest,
    },
    # This should fail because readfua does not work with with
    # read_mode=prefetch
    {
        "test_id": 114,
        "cmd_types": ['bsg',],
        "fio_opts": {
            "rw": 'read',
            "timebased": 1,
            "runtime": 3,
            "read_mode": "prefetch",
            "readfua": 1,
            "output-format": "json",
            },
        "success": SUCCESS_NONZERO,
        "test_class": PassThruTest,
    },
    # This should fail because cdb_len=32 does not work with with
    # read_mode=prefetch
    {
        "test_id": 115,
        "cmd_types": ['bsg',],
        "fio_opts": {
            "rw": 'read',
            "timebased": 1,
            "runtime": 3,
            "read_mode": "prefetch",
            "cdb_len": 32,
            "output-format": "json",
            },
        "success": SUCCESS_NONZERO,
        "test_class": PassThruTest,
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
    parser.add_argument('--dut', help='target device to test '
                        r'(e.g., /dev/ng0n1, "/dev/bsg/6\:0\:0\:0"). '
                        'WARNING: THIS IS A DESTRUCTIVE TEST', required=True)
    parser.add_argument('-c', '--cmd_type', help='cmd_type for io_uring_cmd',
                        default='nvme')
    args = parser.parse_args()

    return args


def main():
    """Run tests using fio's io_uring_cmd ioengine to send pass through commands."""

    args = parse_args()

    artifact_root = args.artifact_root if args.artifact_root else \
        f"io_uring_cmd-test-{time.strftime('%Y%m%d-%H%M%S')}"
    os.mkdir(artifact_root)
    print(f"Artifact directory is {artifact_root}")

    if args.fio:
        fio_path = str(Path(args.fio).absolute())
    else:
        fio_path = os.path.join(str(Path(__file__).absolute().parent.parent), "fio")
    print(f"fio path is {fio_path}")

    for test in TEST_LIST:
        test['fio_opts']['filename'] = args.dut
        test['fio_opts']['cmd_type'] = args.cmd_type
        if 'cmd_types' in test and args.cmd_type not in test['cmd_types']:
            test['force_skip'] = True

    test_env = {
              'fio_path': fio_path,
              'fio_root': str(Path(__file__).absolute().parent.parent),
              'artifact_root': artifact_root,
              'basename': 'io_uring_cmd',
              }

    _, failed, _ = run_fio_tests(TEST_LIST, test_env, args)
    sys.exit(failed)


if __name__ == '__main__':
    main()
