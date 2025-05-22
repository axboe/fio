#!/usr/bin/env python3
"""
# verify.py
#
# Test fio's verify options.
#
# USAGE
# see python3 verify.py --help
#
# EXAMPLES
# python3 t/verify.py
# python3 t/verify.py --fio ./fio
#
# REQUIREMENTS
# Python 3.6
# - 4 CPUs
#
"""
import os
import sys
import time
import errno
import logging
import argparse
import platform
import itertools
from pathlib import Path
from fiotestlib import FioJobCmdTest, run_fio_tests
from fiotestcommon import SUCCESS_DEFAULT, SUCCESS_NONZERO, Requirements


VERIFY_OPT_LIST = [
    'direct',
    'iodepth',
    'filesize',
    'bs',
    'time_based',
    'runtime',
    'io_size',
    'offset',
    'number_ios',
    'output-format',
    'directory',
    'norandommap',
    'numjobs',
    'nrfiles',
    'openfiles',
    'cpus_allowed',
    'fallocate',
    'experimental_verify',
    'verify_backlog',
    'verify_backlog_batch',
    'verify_interval',
    'verify_offset',
    'verify_async',
    'verify_async_cpus',
    'verify_pattern',
    'verify_pattern_interval',
    'verify_only',
    'verify_fatal',
]

class VerifyTest(FioJobCmdTest):
    """
    Verify test class.
    """

    def setup(self, parameters):
        """Setup a test."""

        fio_args = [
            "--name=verify",
            "--fallocate=truncate",
            f"--ioengine={self.fio_opts['ioengine']}",
            f"--rw={self.fio_opts['rw']}",
            f"--verify={self.fio_opts['verify']}",
            f"--output={os.path.basename(self.filenames['output'])}",
        ]
        for opt in VERIFY_OPT_LIST:
            if opt in self.fio_opts:
                option = f"--{opt}={self.fio_opts[opt]}"
                fio_args.append(option)

        super().setup(fio_args)

    def check_result(self):
        super().check_result()

        if not self.passed:
            with open(self.filenames['stderr'], "r") as se:
                contents = se.read()
                logging.info("stderr: %s", contents)

            with open(self.filenames['stdout'], "r") as so:
                contents = so.read()
                logging.info("stdout: %s", contents)

            with open(self.filenames['output'], "r") as out:
                contents = out.read()
                logging.info("output: %s", contents)

class VerifyCSUMTest(FioJobCmdTest):
    """
    Verify test class. Run standard verify jobs, modify the data, and then run
    more verify jobs. Hopefully fio will detect that the data has chagned.
    """

    @staticmethod
    def add_verify_opts(opt_list, adds):
        """Add optional options."""

        fio_opts = []

        for opt in adds:
            if opt in opt_list:
                option = f"--{opt}={opt_list[opt]}"
                fio_opts.append(option)

        return fio_opts

    def setup(self, parameters):
        """Setup a test."""

        logging.debug("ioengine is %s", self.fio_opts['ioengine'])
        fio_args_base = [
            "--fallocate=truncate",
            "--filename=verify",
            "--stonewall",
            f"--ioengine={self.fio_opts['ioengine']}",
        ]

        extra_options = self.add_verify_opts(self.fio_opts, VERIFY_OPT_LIST)

        verify_only = [
            "--verify_only",
            f"--rw={self.fio_opts['rw']}",
            f"--verify={self.fio_opts['verify']}",
        ] + fio_args_base + extra_options

        verify_read = [
            "--rw=randread" if 'rand' in self.fio_opts['rw'] else "--rw=read",
            f"--verify={self.fio_opts['verify']}",
        ] + fio_args_base + extra_options

        layout = [
            "--name=layout",
            f"--rw={self.fio_opts['rw']}",
            f"--verify={self.fio_opts['verify']}",
        ] + fio_args_base + extra_options

        success_only = ["--name=success_only"] + verify_only
        success_read = ["--name=success_read"] + verify_read

        mangle = [
            "--name=mangle",
            "--rw=randwrite",
            "--randrepeat=0",
            f"--bs={self.fio_opts['mangle_bs']}",
            "--number_ios=1",
        ] + fio_args_base + self.add_verify_opts(self.fio_opts, ['filesize'])

        failure_only = ["--name=failure_only"] + verify_only
        failure_read = ["--name=failure_read"] + verify_read

        fio_args = layout + success_only + success_read + mangle + failure_only + failure_read + [f"--output={self.filenames['output']}"]
        logging.debug("fio_args: %s", fio_args)

        super().setup(fio_args)

    def check_result(self):
        super().check_result()

        checked = {}

        for job in self.json_data['jobs']:
            if job['jobname'] == 'layout':
                checked[job['jobname']] = True
                if job['error']:
                    self.passed = False
                    self.failure_reason += " layout job failed"
            elif 'success' in job['jobname']:
                checked[job['jobname']] = True
                if job['error']:
                    self.passed = False
                    self.failure_reason += f" verify pass {job['jobname']} that should have succeeded actually failed"
            elif job['jobname'] == 'mangle':
                checked[job['jobname']] = True
                if job['error']:
                    self.passed = False
                    self.failure_reason += " mangle job failed"
            elif 'failure' in job['jobname']:
                checked[job['jobname']] = True
                if self.fio_opts['verify'] == 'null' and not job['error']:
                    continue
                if job['error'] != errno.EILSEQ:
                    self.passed = False
                    self.failure_reason += f" verify job {job['jobname']} produced {job['error']} instead of errno {errno.EILSEQ} Illegal byte sequence"
                    logging.debug(self.json_data)
            else:
                self.passed = False
                self.failure_reason += " unknown job name"

        if len(checked) != 6:
            self.passed = False
            self.failure_reason += " six phases not completed"

        with open(self.filenames['stderr'], "r") as se:
            contents = se.read()
            logging.debug("stderr: %s", contents)


#
# These tests exercise fio's verify_pattern_interval option.
#
TEST_LIST_VPI = [
    {
        # Basic test verify=pattern
        "test_id": 3000,
        "fio_opts": {
            "ioengine": "psync",
            "rw": "write",
            "verify": "pattern",
            "filesize": "1M",
            "bs": 4096,
            "output-format": "json",
            },
        "test_class": VerifyTest,
        "success": SUCCESS_DEFAULT,
    },
    {
        # Basic test verify=pattern_hdr
        "test_id": 3001,
        "fio_opts": {
            "ioengine": "psync",
            "rw": "write",
            "verify": "pattern_hdr",
            "filesize": "1M",
            "bs": 4096,
            "output-format": "json",
            },
        "test_class": VerifyTest,
        "success": SUCCESS_DEFAULT,
    },
]


#
# These tests exercise fio's decisions about verifying the sequence number and
# random seed in the verify header.
#
TEST_LIST_HEADER = [
    {
        # Basic test with options at default values
        "test_id": 2000,
        "fio_opts": {
            "ioengine": "libaio",
            "filesize": "1M",
            "bs": 4096,
            "output-format": "json",
            },
        "test_class": VerifyTest,
        "success": SUCCESS_DEFAULT,
    },
    {
        # Basic test with iodepth 16
        "test_id": 2001,
        "fio_opts": {
            "ioengine": "libaio",
            "filesize": "1M",
            "bs": 4096,
            "iodepth": 16,
            "output-format": "json",
            },
        "test_class": VerifyTest,
        "success": SUCCESS_DEFAULT,
    },
    {
        # Basic test with 3 files
        "test_id": 2002,
        "fio_opts": {
            "ioengine": "libaio",
            "filesize": "1M",
            "bs": 4096,
            "nrfiles": 3,
            "output-format": "json",
            },
        "test_class": VerifyTest,
        "success": SUCCESS_DEFAULT,
    },
    {
        # Basic test with iodepth 16 and 3 files
        "test_id": 2003,
        "fio_opts": {
            "ioengine": "libaio",
            "filesize": "1M",
            "bs": 4096,
            "iodepth": 16,
            "nrfiles": 3,
            "output-format": "json",
            },
        "test_class": VerifyTest,
        "success": SUCCESS_DEFAULT,
    },
]

#
# These tests are mainly intended to assess the checksum functions. They write
# out data, run some verify jobs, then modify the data, and try to verify the
# data again, expecting to see failures.
#
TEST_LIST_CSUM = [
    {
        # basic seq write verify job
        "test_id": 1000,
        "fio_opts": {
            "ioengine": "psync",
            "filesize": "1M",
            "bs": 4096,
            "rw": "write",
            "output-format": "json",
            "verify_fatal": 1,
            },
        "test_class": VerifyCSUMTest,
        "success": SUCCESS_NONZERO,
    },
    {
        # basic rand write verify job
        "test_id": 1001,
        "fio_opts": {
            "ioengine": "psync",
            "filesize": "1M",
            "bs": 4096,
            "rw": "randwrite",
            "output-format": "json",
            "verify_fatal": 1,
            },
        "test_class": VerifyCSUMTest,
        "success": SUCCESS_NONZERO,
    },
    {
        # basic libaio seq write test
        "test_id": 1002,
        "fio_opts": {
            "direct": 1,
            "ioengine": "libaio",
            "iodepth": 16,
            "filesize": "1M",
            "bs": 4096,
            "rw": "write",
            "output-format": "json",
            "verify_fatal": 1,
            },
        "test_class": VerifyCSUMTest,
        "success": SUCCESS_NONZERO,
    },
    {
        # basic libaio rand write test
        "test_id": 1003,
        "fio_opts": {
            "direct": 1,
            "ioengine": "libaio",
            "iodepth": 16,
            "filesize": "1M",
            "bs": 4096,
            "rw": "randwrite",
            "output-format": "json",
            "verify_fatal": 1,
            },
        "test_class": VerifyCSUMTest,
        "success": SUCCESS_NONZERO,
    },
]

#
# These tests are run for all combinations of data direction and checksum
# methods.
#
TEST_LIST = [
    {
        # norandommap with verify backlog
        "test_id": 1,
        "fio_opts": {
            "direct": 1,
            "ioengine": "libaio",
            "iodepth": 32,
            "filesize": "2M",
            "norandommap": 1,
            "bs": 512,
            "time_based": 1,
            "runtime": 3,
            "verify_backlog": 128,
            "verify_backlog_batch": 64,
            },
        "test_class": VerifyTest,
    },
    {
        # norandommap with verify offset and interval
        "test_id": 2,
        "fio_opts": {
            "direct": 1,
            "ioengine": "libaio",
            "iodepth": 32,
            "filesize": "2M",
            "io_size": "4M",
            "norandommap": 1,
            "bs": 4096,
            "verify_interval": 2048,
            "verify_offset": 1024,
            },
        "test_class": VerifyTest,
    },
    {
        # norandommap with verify offload to async threads
        "test_id": 3,
        "fio_opts": {
            "direct": 1,
            "ioengine": "libaio",
            "iodepth": 32,
            "filesize": "2M",
            "norandommap": 1,
            "bs": 4096,
            "cpus_allowed": "0-3",
            "verify_async": 2,
            "verify_async_cpus": "0-1",
            },
        "test_class": VerifyTest,
        "requirements":     [Requirements.not_macos,
                             Requirements.cpucount4],
        # mac os does not support CPU affinity
    },
    {
        # tausworthe combine all verify options
        "test_id": 4,
        "fio_opts": {
            "direct": 1,
            "ioengine": "libaio",
            "iodepth": 32,
            "filesize": "4M",
            "bs": 4096,
            "cpus_allowed": "0-3",
            "time_based": 1,
            "random_generator": "tausworthe",
            "runtime": 3,
            "verify_interval": 2048,
            "verify_offset": 1024,
            "verify_backlog": 128,
            "verify_backlog_batch": 128,
            "verify_async": 2,
            "verify_async_cpus": "0-1",
            },
        "test_class": VerifyTest,
        "requirements":     [Requirements.not_macos,
                             Requirements.cpucount4],
        # mac os does not support CPU affinity
    },
    {
        # norandommap combine all verify options
        "test_id": 5,
        "fio_opts": {
            "direct": 1,
            "ioengine": "libaio",
            "iodepth": 32,
            "filesize": "4M",
            "norandommap": 1,
            "bs": 4096,
            "cpus_allowed": "0-3",
            "time_based": 1,
            "runtime": 3,
            "verify_interval": 2048,
            "verify_offset": 1024,
            "verify_backlog": 128,
            "verify_backlog_batch": 128,
            "verify_async": 2,
            "verify_async_cpus": "0-1",
            },
        "test_class": VerifyTest,
        "requirements":     [Requirements.not_macos,
                             Requirements.cpucount4],
        # mac os does not support CPU affinity
    },
    {
        # multiple jobs and files with verify
        "test_id": 6,
        "fio_opts": {
            "direct": 1,
            "ioengine": "libaio",
            "iodepth": 32,
            "filesize": "512K",
            "nrfiles": 3,
            "openfiles": 2,
            "numjobs": 2,
            "norandommap": 1,
            "bs": 4096,
            "verify_interval": 2048,
            "verify_offset": 1024,
            "verify_backlog": 16,
            "verify_backlog_batch": 16,
            },
        "test_class": VerifyTest,
        "requirements":     [Requirements.not_macos,],
        # Skip this test on macOS because it is flaky. With rw=write it can
        # fail to complete even after 10min which prevents the rw=read instance
        # from passing because the read instance depends on the file created by
        # the write instance. See failure here:
        # https://github.com/vincentkfu/fio/actions/runs/13683127191/job/38260091800#step:14:258
    },
]


def parse_args():
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--fio-root', help='fio root path')
    parser.add_argument('-d', '--debug', help='Enable debug messages', action='store_true')
    parser.add_argument('-f', '--fio', help='path to file executable (e.g., ./fio)')
    parser.add_argument('-a', '--artifact-root', help='artifact root directory')
    parser.add_argument('-c', '--complete', help='Enable all checksums', action='store_true')
    parser.add_argument('-s', '--skip', nargs='+', type=int,
                        help='list of test(s) to skip')
    parser.add_argument('-o', '--run-only', nargs='+', type=int,
                        help='list of test(s) to run, skipping all others')
    parser.add_argument('-k', '--skip-req', action='store_true',
                        help='skip requirements checking')
    parser.add_argument('--csum', nargs='+', type=str,
                        help='list of checksum methods to use, skipping all others')
    args = parser.parse_args()

    return args


def verify_test_header(test_env, args, csum, mode, sequence):
    """
    Adjust test arguments based on values of mode and sequence. Then run the
    tests. This function is intended to run a set of tests that test
    conditions under which the header random seed and sequence number are
    checked.

    The result should be a matrix with these combinations:
        {write, write w/verify_only, read/write, read/write w/verify_only, read} x
        {sequential, random w/randommap, random w/norandommap, sequence modifiers}
    """
    for test in TEST_LIST_HEADER:
        # experimental_verify does not work in verify_only=1 mode
        if "_vo" in mode and 'experimental_verify' in test['fio_opts'] and \
        test['fio_opts']['experimental_verify']:
            test['force_skip'] = True
        else:
            test['force_skip'] = False

        test['fio_opts']['verify'] = csum
        if csum in ('pattern', 'pattern_hdr'):
            test['fio_opts']['verify_pattern'] = '"abcd"-120xdeadface'
            test['fio_opts'].pop('verify_pattern_interval', None)
        elif csum == 'pattern_interval':
            test['fio_opts']['verify'] = "pattern_hdr"
            test['fio_opts']['verify_pattern'] = '%o'
            test['fio_opts']['verify_pattern_interval'] = 512
        elif csum == 'pattern_interval_nohdr':
            test['fio_opts']['verify'] = "pattern"
            test['fio_opts']['verify_pattern'] = '%o'
            test['fio_opts']['verify_pattern_interval'] = 512
        else:
            test['fio_opts'].pop('verify_pattern', None)
            test['fio_opts'].pop('verify_pattern_interval', None)

        if 'norandommap' in sequence:
            test['fio_opts']['norandommap'] = 1
        else:
            test['fio_opts']['norandommap'] = 0

        if 'randommap' in sequence:
            prefix = "rand"
        else:
            prefix = ""

        if 'sequence_modifier' in sequence:
            suffix = ":4096"
        else:
            suffix = ""

        if 'readwrite' in mode:
            fio_ddir = 'rw'
        elif 'write' in mode:
            fio_ddir = 'write'
        elif 'read' in mode:
            fio_ddir = 'read'
        else:
            fio_ddir = ""
            # TODO throw an exception here
        test['fio_opts']['rw'] = prefix + fio_ddir + suffix
        logging.debug("ddir is %s", test['fio_opts']['rw'])

        if '_vo' in mode:
            vo = 1
        else:
            vo = 0
        test['fio_opts']['verify_only'] = vo

        # For 100% read workloads we need to read a file that was written with
        # verify enabled. Use a previous test case for this by pointing fio to
        # write to a file in a specific directory.
        #
        # For verify_only tests we also need to point fio to a file that was
        # written with verify enabled
        if mode == 'read':
            directory = os.path.join(test_env['artifact_root'].replace(f'mode_{mode}','mode_write'),
                        f"{test['test_id']:04d}")
            test['fio_opts']['directory'] = str(Path(directory).absolute()) if \
                platform.system() != "Windows" else str(Path(directory).absolute()).replace(':', '\\:')
        elif vo:
            directory = os.path.join(test_env['artifact_root'].replace('write_vo','write'),
                        f"{test['test_id']:04d}")
            test['fio_opts']['directory'] = str(Path(directory).absolute()) if \
                platform.system() != "Windows" else str(Path(directory).absolute()).replace(':', '\\:')
        else:
            test['fio_opts'].pop('directory', None)

    return run_fio_tests(TEST_LIST_HEADER, test_env, args)


MANGLE_JOB_BS = 0
def verify_test_csum(test_env, args, mbs, csum):
    """
    Adjust test arguments based on values of csum. Then run the tests.
    This function is designed for a series of tests that check that checksum
    methods can reliably detect data integrity issues.
    """
    for test in TEST_LIST_CSUM:
        # The crc7 checksum will produce too many false positives since when we
        # modify the data there is a 1/128 chance that the checksum will not
        # change. So skip this set of tests.
        if csum == 'crc7':
            test['force_skip'] = True
        else:
            test['force_skip'] = False
        test['fio_opts']['verify'] = csum

        if csum in ('pattern', 'pattern_hdr'):
            test['fio_opts']['verify_pattern'] = '"abcd"-120xdeadface'
            test['fio_opts'].pop('verify_pattern_interval', None)
        elif csum == 'pattern_interval':
            test['fio_opts']['verify'] = "pattern_hdr"
            test['fio_opts']['verify_pattern'] = '%o'
            test['fio_opts']['verify_pattern_interval'] = 512
        elif csum == 'pattern_interval_nohdr':
            test['fio_opts']['verify'] = "pattern"
            test['fio_opts']['verify_pattern'] = '%o'
            test['fio_opts']['verify_pattern_interval'] = 512
        else:
            test['fio_opts'].pop('verify_pattern', None)
            test['fio_opts'].pop('verify_pattern_interval', None)

        if mbs == MANGLE_JOB_BS:
            test['fio_opts']['mangle_bs'] = test['fio_opts']['bs']
        else:
            test['fio_opts']['mangle_bs'] = mbs

        # These tests produce verification failures but not when verify=null,
        # so adjust the success criterion.
        if csum == 'null':
            test['success'] = SUCCESS_DEFAULT
        else:
            test['success'] = SUCCESS_NONZERO

    return run_fio_tests(TEST_LIST_CSUM, test_env, args)


def verify_test_vpi(test_env, args, pattern, vpi, vi):
    """
    Adjust test arguments based on values of ddir and csum.  Then run
    the tests.
    """
    for test in TEST_LIST_VPI:
        test['force_skip'] = False

        test['fio_opts']['verify_pattern'] = pattern
        test['fio_opts']['verify_interval'] = vi
        test['fio_opts']['verify_pattern_interval'] = vpi

        for key in ['verify_interval', 'verify_pattern_interval']:
            if not test['fio_opts'][key]:
                test['fio_opts'].pop(key, None)

    return run_fio_tests(TEST_LIST_VPI, test_env, args)


def verify_test(test_env, args, ddir, csum):
    """
    Adjust test arguments based on values of ddir and csum.  Then run
    the tests.
    """
    for test in TEST_LIST:
        test['force_skip'] = False

        test['fio_opts']['rw'] = ddir
        test['fio_opts']['verify'] = csum

        if csum in ('pattern', 'pattern_hdr'):
            test['fio_opts']['verify_pattern'] = '"abcd"-120xdeadface'
            test['fio_opts'].pop('verify_pattern_interval', None)
        elif csum == 'pattern_interval':
            test['fio_opts']['verify'] = "pattern_hdr"
            test['fio_opts']['verify_pattern'] = '%o'
            test['fio_opts']['verify_pattern_interval'] = 512
        elif csum == 'pattern_interval_nohdr':
            test['fio_opts']['verify'] = "pattern"
            test['fio_opts']['verify_pattern'] = '%o'
            test['fio_opts']['verify_pattern_interval'] = 512
        else:
            test['fio_opts'].pop('verify_pattern', None)
            test['fio_opts'].pop('verify_pattern_interval', None)

        # For 100% read data directions we need the write file that was written with
        # verify enabled. Use a previous test case for this by telling fio to
        # write to a file in a specific directory.
        if ddir == 'read':
            directory = os.path.join(test_env['artifact_root'].replace(f'ddir_{ddir}','ddir_write'),
                        f"{test['test_id']:04d}")
            test['fio_opts']['directory'] = str(Path(directory).absolute()) if \
                platform.system() != "Windows" else str(Path(directory).absolute()).replace(':', '\\:')
        elif ddir == 'randread':
            directory = os.path.join(test_env['artifact_root'].replace(f'ddir_{ddir}','ddir_randwrite'),
                        f"{test['test_id']:04d}")
            test['fio_opts']['directory'] = str(Path(directory).absolute()) if \
                platform.system() != "Windows" else str(Path(directory).absolute()).replace(':', '\\:')
        else:
            test['fio_opts'].pop('directory', None)

    return run_fio_tests(TEST_LIST, test_env, args)


# 100% read workloads below must follow write workloads so that the 100% read
# workloads will be reading data written with verification enabled.
DDIR_LIST = [
        'write',
        'readwrite',
        'read',
        'randwrite',
        'randrw',
        'randread',
             ]
CSUM_LIST1 = [
        'md5',
        'crc64',
        'pattern',
             ]
CSUM_LIST2 = [
        'md5',
        'crc64',
        'crc32c',
        'crc32c-intel',
        'crc16',
        'crc7',
        'xxhash',
        'sha512',
        'sha256',
        'sha1',
        'sha3-224',
        'sha3-384',
        'sha3-512',
        'pattern',
        'pattern_hdr',
        'pattern_interval',
        'pattern_interval_nohdr',
        'null',
             ]

def main():
    """
    Run tests for fio's verify feature.
    """

    args = parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    artifact_root = args.artifact_root if args.artifact_root else \
        f"verify-test-{time.strftime('%Y%m%d-%H%M%S')}"
    os.mkdir(artifact_root)
    print(f"Artifact directory is {artifact_root}")

    if args.fio:
        fio_path = str(Path(args.fio).absolute())
    else:
        fio_path = os.path.join(os.path.dirname(__file__), '../fio')
    print(f"fio path is {fio_path}")

    if args.fio_root:
        fio_root = args.fio_root
    else:
        fio_root = str(Path(__file__).absolute().parent.parent)
    print(f"fio root is {fio_root}")

    if not args.skip_req:
        Requirements(fio_root, args)

    test_env = {
              'fio_path': fio_path,
              'fio_root': str(Path(__file__).absolute().parent.parent),
              'artifact_root': artifact_root,
              'basename': 'verify',
              }

    if platform.system() == 'Linux':
        aio = 'libaio'
        sync = 'psync'
    elif platform.system() == 'Windows':
        aio = 'windowsaio'
        sync = 'sync'
    else:
        aio = 'posixaio'
        sync = 'psync'
    for test in TEST_LIST:
        if 'aio' in test['fio_opts']['ioengine']:
            test['fio_opts']['ioengine'] = aio
        if 'sync' in test['fio_opts']['ioengine']:
            test['fio_opts']['ioengine'] = sync
    for test in TEST_LIST_CSUM:
        if 'aio' in test['fio_opts']['ioengine']:
            test['fio_opts']['ioengine'] = aio
        if 'sync' in test['fio_opts']['ioengine']:
            test['fio_opts']['ioengine'] = sync
    for test in TEST_LIST_HEADER:
        if 'aio' in test['fio_opts']['ioengine']:
            test['fio_opts']['ioengine'] = aio
        if 'sync' in test['fio_opts']['ioengine']:
            test['fio_opts']['ioengine'] = sync
    for test in TEST_LIST_VPI:
        if 'aio' in test['fio_opts']['ioengine']:
            test['fio_opts']['ioengine'] = aio
        if 'sync' in test['fio_opts']['ioengine']:
            test['fio_opts']['ioengine'] = sync

    total = { 'passed':  0, 'failed': 0, 'skipped': 0 }

    if args.complete:
        csum_list = CSUM_LIST2
    else:
        csum_list = CSUM_LIST1

    if args.csum:
        csum_list = args.csum

    try:
        for ddir, csum in itertools.product(DDIR_LIST, csum_list):
            print(f"\nddir: {ddir}, checksum: {csum}")

            test_env['artifact_root'] = os.path.join(artifact_root,
                                                     f"ddir_{ddir}_csum_{csum}")
            os.mkdir(test_env['artifact_root'])

            passed, failed, skipped = verify_test(test_env, args, ddir, csum)

            total['passed'] += passed
            total['failed'] += failed
            total['skipped'] += skipped

        # MANGLE_JOB_BS means to mangle an entire block which should result in
        #  a header magic number error
        # 4 means to mangle 4 bytes which should result in a checksum error
        #  unless the 4 bytes occur in the verification header
        mangle_bs = [MANGLE_JOB_BS, 4]
        for mbs, csum in itertools.product(mangle_bs, csum_list):
            print(f"\nmangle block size: {mbs}, checksum: {csum}")

            test_env['artifact_root'] = os.path.join(artifact_root,
                                                     f"mbs_{mbs}_csum_{csum}")
            os.mkdir(test_env['artifact_root'])

            passed, failed, skipped = verify_test_csum(test_env, args, mbs, csum)

            total['passed'] += passed
            total['failed'] += failed
            total['skipped'] += skipped

        # The loop below tests combinations of options that exercise fio's
        # decisions about disabling checks for the sequence number and random
        # seed in the verify header.
        mode_list = [ "write", "write_vo", "readwrite", "readwrite_vo", "read" ]
        sequence_list = [ "sequential", "randommap", "norandommap", "sequence_modifier" ]
        for mode, sequence in itertools.product(mode_list, sequence_list):
            print(f"\nmode: {mode}, sequence: {sequence}")

            test_env['artifact_root'] = os.path.join(artifact_root,
                                                     f"mode_{mode}_seq_{sequence}")
            os.mkdir(test_env['artifact_root'])

            passed, failed, skipped = verify_test_header(test_env, args, 'md5', mode, sequence)

            total['passed'] += passed
            total['failed'] += failed
            total['skipped'] += skipped

        # The loop below is for verify_pattern_interval tests
        pattern_list = ['%o', '"abcde"', '1%o',]
        vpi_list = [10, 129, 512, 4089, None]
        verify_interval_list = [512, 1024, 2222, 3791, None]
        for pattern, vpi, vi in itertools.product(pattern_list, vpi_list, verify_interval_list):
            print(f"\npattern: {pattern}, verify_pattern_interval: {vpi}, verify_interval: {vi}")

            test_env['artifact_root'] = os.path.join(artifact_root,
                f"pattern_{pattern}_vpi_{vpi}_vi_{vi}").replace('"', '').replace("%", 'pct')
            os.mkdir(test_env['artifact_root'])

            passed, failed, skipped = verify_test_vpi(test_env, args, pattern, vpi, vi)

            total['passed'] += passed
            total['failed'] += failed
            total['skipped'] += skipped

    except KeyboardInterrupt:
        pass

    print(f"\n\n{total['passed']} test(s) passed, {total['failed']} failed, " \
            f"{total['skipped']} skipped")
    sys.exit(total['failed'])


if __name__ == '__main__':
    main()
