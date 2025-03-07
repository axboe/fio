#!/usr/bin/env python3
"""
# nvmept_pi.py
#
# Test fio's io_uring_cmd ioengine support for DIF/DIX end-to-end data
# protection.
#
# USAGE
# see python3 nvmept_pi.py --help
#
# EXAMPLES (THIS IS A DESTRUCTIVE TEST!!)
# python3 t/nvmept_pi.py --dut /dev/ng0n1 -f ./fio
# python3 t/nvmept_pi.py --dut /dev/ng0n1 -f ./fio --lbaf 1
#
# REQUIREMENTS
# Python 3.6
#
"""
import os
import sys
import json
import time
import locale
import logging
import argparse
import itertools
import subprocess
from pathlib import Path
from fiotestlib import FioJobCmdTest, run_fio_tests
from fiotestcommon import SUCCESS_NONZERO

NUMBER_IOS = 8192
BS_LOW = 1
BS_HIGH = 16

class DifDixTest(FioJobCmdTest):
    """
    NVMe DIF/DIX test class.
    """

    def setup(self, parameters):
        """Setup a test."""

        fio_args = [
            "--name=nvmept_pi",
            f"--ioengine={self.fio_opts['ioengine']}",
            f"--filename={self.fio_opts['filename']}",
            f"--rw={self.fio_opts['rw']}",
            f"--bsrange={self.fio_opts['bsrange']}",
            f"--output={self.filenames['output']}",
            f"--md_per_io_size={self.fio_opts['md_per_io_size']}",
            f"--pi_act={self.fio_opts['pi_act']}",
            f"--pi_chk={self.fio_opts['pi_chk']}",
            f"--apptag={self.fio_opts['apptag']}",
            f"--apptag_mask={self.fio_opts['apptag_mask']}",
        ]
        for opt in ['fixedbufs', 'nonvectored', 'force_async', 'registerfiles',
                    'sqthread_poll', 'sqthread_poll_cpu', 'hipri', 'nowait',
                    'time_based', 'runtime', 'verify', 'io_size', 'offset', 'number_ios',
                    'output-format']:
            if opt in self.fio_opts:
                option = f"--{opt}={self.fio_opts[opt]}"
                fio_args.append(option)

        if self.fio_opts['ioengine'] == 'io_uring_cmd':
            fio_args.append('--cmd_type=nvme')
        elif self.fio_opts['ioengine'] == 'xnvme':
            fio_args.append('--thread=1')
            fio_args.append('--xnvme_async=io_uring_cmd')

        super().setup(fio_args)


TEST_LIST = [
#
# Write data with pi_act=1 and then read the data back (with both
# pi_act=[0,1]).
#
    {
        # Write workload with variable IO sizes
        # pi_act=1
        "test_id": 101,
        "fio_opts": {
            "rw": 'write',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "apptag": "0x8888",
            "apptag_mask": "0xFFFF",
            "pi_act": 1,
            },
        "pi_chk": "APPTAG,GUARD,REFTAG",
        "bs_low": BS_LOW,
        "bs_high": BS_HIGH,
        "test_class": DifDixTest,
    },
    {
        # Read workload with fixed small IO size
        # pi_act=0
        "test_id": 102,
        "fio_opts": {
            "rw": 'read',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "pi_act": 0,
            "apptag": "0x8888",
            "apptag_mask": "0xFFFF",
            },
        "pi_chk": "APPTAG,GUARD,REFTAG",
        "bs_low": BS_LOW,
        "bs_high": BS_LOW,
        "test_class": DifDixTest,
    },
    {
        # Read workload with fixed small IO size
        # pi_act=1
        "test_id": 103,
        "fio_opts": {
            "rw": 'read',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "pi_act": 1,
            "apptag": "0x8888",
            "apptag_mask": "0xFFFF",
            },
        "pi_chk": "APPTAG,GUARD,REFTAG",
        "bs_low": BS_LOW,
        "bs_high": BS_LOW,
        "test_class": DifDixTest,
    },
    {
        # Write workload with fixed large IO size
        # Precondition for read workloads to follow
        # pi_act=1
        "test_id": 104,
        "fio_opts": {
            "rw": 'write',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "apptag": "0x8888",
            "apptag_mask": "0xFFFF",
            "pi_act": 1,
            },
        "pi_chk": "APPTAG,GUARD,REFTAG",
        "bs_low": BS_HIGH,
        "bs_high": BS_HIGH,
        "test_class": DifDixTest,
    },
    {
        # Read workload with variable IO sizes
        # pi_act=0
        "test_id": 105,
        "fio_opts": {
            "rw": 'read',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "pi_act": 0,
            "apptag": "0x8888",
            "apptag_mask": "0xFFFF",
            },
        "pi_chk": "APPTAG,GUARD,REFTAG",
        "bs_low": BS_LOW,
        "bs_high": BS_HIGH,
        "test_class": DifDixTest,
    },
    {
        # Read workload with variable IO sizes
        # pi_act=1
        "test_id": 106,
        "fio_opts": {
            "rw": 'read',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "pi_act": 1,
            "apptag": "0x8888",
            "apptag_mask": "0xFFFF",
            },
        "pi_chk": "APPTAG,GUARD,REFTAG",
        "bs_low": BS_LOW,
        "bs_high": BS_HIGH,
        "test_class": DifDixTest,
    },
#
# Write data with pi_act=0 and then read the data back (with both
# pi_act=[0,1]).
#
    {
        # Write workload with variable IO sizes
        # pi_act=0
        "test_id": 201,
        "fio_opts": {
            "rw": 'write',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "apptag": "0x8888",
            "apptag_mask": "0xFFFF",
            "pi_act": 0,
            },
        "pi_chk": "APPTAG,GUARD,REFTAG",
        "bs_low": BS_LOW,
        "bs_high": BS_HIGH,
        "test_class": DifDixTest,
    },
    {
        # Read workload with fixed small IO size
        # pi_act=0
        "test_id": 202,
        "fio_opts": {
            "rw": 'read',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "pi_act": 0,
            "apptag": "0x8888",
            "apptag_mask": "0xFFFF",
            },
        "pi_chk": "APPTAG,GUARD,REFTAG",
        "bs_low": BS_LOW,
        "bs_high": BS_LOW,
        "test_class": DifDixTest,
    },
    {
        # Read workload with fixed small IO size
        # pi_act=1
        "test_id": 203,
        "fio_opts": {
            "rw": 'read',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "pi_act": 1,
            "apptag": "0x8888",
            "apptag_mask": "0xFFFF",
            },
        "pi_chk": "APPTAG,GUARD,REFTAG",
        "bs_low": BS_LOW,
        "bs_high": BS_LOW,
        "test_class": DifDixTest,
    },
    {
        # Write workload with fixed large IO sizes
        # pi_act=0
        "test_id": 204,
        "fio_opts": {
            "rw": 'write',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "apptag": "0x8888",
            "apptag_mask": "0xFFFF",
            "pi_act": 0,
            },
        "pi_chk": "APPTAG,GUARD,REFTAG",
        "bs_low": BS_HIGH,
        "bs_high": BS_HIGH,
        "test_class": DifDixTest,
    },
    {
        # Read workload with variable IO sizes
        # pi_act=0
        "test_id": 205,
        "fio_opts": {
            "rw": 'read',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "pi_act": 0,
            "apptag": "0x8888",
            "apptag_mask": "0xFFFF",
            },
        "pi_chk": "APPTAG,GUARD,REFTAG",
        "bs_low": BS_LOW,
        "bs_high": BS_HIGH,
        "test_class": DifDixTest,
    },
    {
        # Read workload with variable IO sizes
        # pi_act=1
        "test_id": 206,
        "fio_opts": {
            "rw": 'read',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "pi_act": 1,
            "apptag": "0x8888",
            "apptag_mask": "0xFFFF",
            },
        "pi_chk": "APPTAG,GUARD,REFTAG",
        "bs_low": BS_LOW,
        "bs_high": BS_HIGH,
        "test_class": DifDixTest,
    },
#
# Test apptag errors.
#
    {
        # Read workload with variable IO sizes
        # pi_act=0
        # trigger an apptag error
        "test_id": 301,
        "fio_opts": {
            "rw": 'read',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "pi_act": 0,
            "apptag": "0x0888",
            "apptag_mask": "0xFFFF",
            },
        "pi_chk": "APPTAG,GUARD,REFTAG",
        "bs_low": BS_LOW,
        "bs_high": BS_HIGH,
        "success": SUCCESS_NONZERO,
        "test_class": DifDixTest,
    },
    {
        # Read workload with variable IO sizes
        # pi_act=1
        # trigger an apptag error
        "test_id": 302,
        "fio_opts": {
            "rw": 'read',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "pi_act": 1,
            "apptag": "0x0888",
            "apptag_mask": "0xFFFF",
            },
        "pi_chk": "APPTAG,GUARD,REFTAG",
        "bs_low": BS_LOW,
        "bs_high": BS_HIGH,
        "success": SUCCESS_NONZERO,
        "test_class": DifDixTest,
    },
    {
        # Read workload with variable IO sizes
        # pi_act=0
        # trigger an apptag error
        # same as above but with pi_chk=APPTAG only
        "test_id": 303,
        "fio_opts": {
            "rw": 'read',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "pi_act": 0,
            "apptag": "0x0888",
            "apptag_mask": "0xFFFF",
            },
        "pi_chk": "APPTAG",
        "bs_low": BS_LOW,
        "bs_high": BS_HIGH,
        "success": SUCCESS_NONZERO,
        "test_class": DifDixTest,
    },
    {
        # Read workload with variable IO sizes
        # pi_act=1
        # trigger an apptag error
        # same as above but with pi_chk=APPTAG only
        "test_id": 304,
        "fio_opts": {
            "rw": 'read',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "pi_act": 1,
            "apptag": "0x0888",
            "apptag_mask": "0xFFFF",
            },
        "pi_chk": "APPTAG",
        "bs_low": BS_LOW,
        "bs_high": BS_HIGH,
        "success": SUCCESS_NONZERO,
        "test_class": DifDixTest,
    },
    {
        # Read workload with variable IO sizes
        # pi_act=0
        # this case would trigger an apptag error, but pi_chk says to check
        # only the Guard PI and reftag, so there should be no error
        "test_id": 305,
        "fio_opts": {
            "rw": 'read',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "pi_act": 0,
            "apptag": "0x0888",
            "apptag_mask": "0xFFFF",
            },
        "pi_chk": "GUARD,REFTAG",
        "bs_low": BS_LOW,
        "bs_high": BS_HIGH,
        "test_class": DifDixTest,
    },
    {
        # Read workload with variable IO sizes
        # pi_act=1
        # this case would trigger an apptag error, but pi_chk says to check
        # only the Guard PI and reftag, so there should be no error
        "test_id": 306,
        "fio_opts": {
            "rw": 'read',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "pi_act": 1,
            "apptag": "0x0888",
            "apptag_mask": "0xFFFF",
            },
        "pi_chk": "GUARD,REFTAG",
        "bs_low": BS_LOW,
        "bs_high": BS_HIGH,
        "test_class": DifDixTest,
    },
    {
        # Read workload with variable IO sizes
        # pi_act=0
        # this case would trigger an apptag error, but pi_chk says to check
        # only the Guard PI, so there should be no error
        "test_id": 307,
        "fio_opts": {
            "rw": 'read',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "pi_act": 0,
            "apptag": "0x0888",
            "apptag_mask": "0xFFFF",
            },
        "pi_chk": "GUARD",
        "bs_low": BS_LOW,
        "bs_high": BS_HIGH,
        "test_class": DifDixTest,
    },
    {
        # Read workload with variable IO sizes
        # pi_act=1
        # this case would trigger an apptag error, but pi_chk says to check
        # only the Guard PI, so there should be no error
        "test_id": 308,
        "fio_opts": {
            "rw": 'read',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "pi_act": 1,
            "apptag": "0x0888",
            "apptag_mask": "0xFFFF",
            },
        "pi_chk": "GUARD",
        "bs_low": BS_LOW,
        "bs_high": BS_HIGH,
        "test_class": DifDixTest,
    },
    {
        # Read workload with variable IO sizes
        # pi_act=0
        # this case would trigger an apptag error, but pi_chk says to check
        # only the reftag, so there should be no error
        # This case will be skipped when the device is formatted with Type 3 PI
        # since Type 3 PI ignores the reftag
        "test_id": 309,
        "fio_opts": {
            "rw": 'read',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "pi_act": 0,
            "apptag": "0x0888",
            "apptag_mask": "0xFFFF",
            },
        "pi_chk": "REFTAG",
        "bs_low": BS_LOW,
        "bs_high": BS_HIGH,
        "skip": "type3",
        "test_class": DifDixTest,
    },
    {
        # Read workload with variable IO sizes
        # pi_act=1
        # this case would trigger an apptag error, but pi_chk says to check
        # only the reftag, so there should be no error
        # This case will be skipped when the device is formatted with Type 3 PI
        # since Type 3 PI ignores the reftag
        "test_id": 310,
        "fio_opts": {
            "rw": 'read',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "pi_act": 1,
            "apptag": "0x0888",
            "apptag_mask": "0xFFFF",
            },
        "pi_chk": "REFTAG",
        "bs_low": BS_LOW,
        "bs_high": BS_HIGH,
        "skip": "type3",
        "test_class": DifDixTest,
    },
    {
        # Read workload with variable IO sizes
        # pi_act=0
        # use apptag mask to ignore apptag mismatch
        "test_id": 311,
        "fio_opts": {
            "rw": 'read',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "pi_act": 0,
            "apptag": "0x0888",
            "apptag_mask": "0x0FFF",
            },
        "pi_chk": "APPTAG,GUARD,REFTAG",
        "bs_low": BS_LOW,
        "bs_high": BS_HIGH,
        "test_class": DifDixTest,
    },
    {
        # Read workload with variable IO sizes
        # pi_act=1
        # use apptag mask to ignore apptag mismatch
        "test_id": 312,
        "fio_opts": {
            "rw": 'read',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "pi_act": 1,
            "apptag": "0x0888",
            "apptag_mask": "0x0FFF",
            },
        "pi_chk": "APPTAG,GUARD,REFTAG",
        "bs_low": BS_LOW,
        "bs_high": BS_HIGH,
        "test_class": DifDixTest,
    },
    {
        # Read workload with variable IO sizes
        # pi_act=0
        # use apptag mask to ignore apptag mismatch
        "test_id": 313,
        "fio_opts": {
            "rw": 'read',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "pi_act": 0,
            "apptag": "0xF888",
            "apptag_mask": "0x0FFF",
            },
        "pi_chk": "APPTAG,GUARD,REFTAG",
        "bs_low": BS_LOW,
        "bs_high": BS_HIGH,
        "test_class": DifDixTest,
    },
    {
        # Read workload with variable IO sizes
        # pi_act=1
        # use apptag mask to ignore apptag mismatch
        "test_id": 314,
        "fio_opts": {
            "rw": 'read',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "pi_act": 1,
            "apptag": "0xF888",
            "apptag_mask": "0x0FFF",
            },
        "pi_chk": "APPTAG,GUARD,REFTAG",
        "bs_low": BS_LOW,
        "bs_high": BS_HIGH,
        "test_class": DifDixTest,
    },
    {
        # Write workload with fixed large IO sizes
        # Set apptag=0xFFFF to disable all checking for Type 1 and 2
        # pi_act=1
        "test_id": 315,
        "fio_opts": {
            "rw": 'write',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "apptag": "0xFFFF",
            "apptag_mask": "0xFFFF",
            "pi_act": 1,
            },
        "pi_chk": "APPTAG,GUARD,REFTAG",
        "bs_low": BS_HIGH,
        "bs_high": BS_HIGH,
        "skip": "type3",
        "test_class": DifDixTest,
    },
    {
        # Read workload with variable IO sizes
        # pi_act=0
        # Data was written with apptag=0xFFFF
        # Reading the data back should disable all checking for Type 1 and 2
        "test_id": 316,
        "fio_opts": {
            "rw": 'read',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "pi_act": 0,
            "apptag": "0x0101",
            "apptag_mask": "0xFFFF",
            },
        "pi_chk": "APPTAG,GUARD,REFTAG",
        "bs_low": BS_LOW,
        "bs_high": BS_HIGH,
        "skip": "type3",
        "test_class": DifDixTest,
    },
    {
        # Read workload with variable IO sizes
        # pi_act=1
        # Data was written with apptag=0xFFFF
        # Reading the data back should disable all checking for Type 1 and 2
        "test_id": 317,
        "fio_opts": {
            "rw": 'read',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "pi_act": 1,
            "apptag": "0x0000",
            "apptag_mask": "0xFFFF",
            },
        "pi_chk": "APPTAG,GUARD,REFTAG",
        "bs_low": BS_LOW,
        "bs_high": BS_HIGH,
        "skip": "type3",
        "test_class": DifDixTest,
    },
#
# Error cases related to block size and metadata size
#
    {
        # Use a min block size that is not a multiple of lba/elba size to
        # trigger an error.
        "test_id": 401,
        "fio_opts": {
            "rw": 'read',
            "number_ios": NUMBER_IOS,
            "pi_act": 0,
            "apptag": "0x8888",
            "apptag_mask": "0x0FFF",
            },
        "pi_chk": "APPTAG,GUARD,REFTAG",
        "bs_low": BS_LOW+0.5,
        "bs_high": BS_HIGH,
        "success": SUCCESS_NONZERO,
        "test_class": DifDixTest,
    },
    {
        # Use metadata size that is too small
        "test_id": 402,
        "fio_opts": {
            "rw": 'read',
            "number_ios": NUMBER_IOS,
            "pi_act": 0,
            "apptag": "0x8888",
            "apptag_mask": "0x0FFF",
            },
        "pi_chk": "APPTAG,GUARD,REFTAG",
        "bs_low": BS_LOW,
        "bs_high": BS_HIGH,
        "mdsize_adjustment": -1,
        "success": SUCCESS_NONZERO,
        "skip": "elba",
        "test_class": DifDixTest,
    },
    {
        # Read workload with variable IO sizes
        # pi_act=0
        # Should still work even if metadata size is too large
        "test_id": 403,
        "fio_opts": {
            "rw": 'read',
            "number_ios": NUMBER_IOS,
            "pi_act": 0,
            "apptag": "0x8888",
            "apptag_mask": "0x0FFF",
            },
        "pi_chk": "APPTAG,GUARD,REFTAG",
        "bs_low": BS_LOW,
        "bs_high": BS_HIGH,
        "mdsize_adjustment": 1,
        "test_class": DifDixTest,
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
    parser.add_argument('-l', '--lbaf', nargs='+', type=int,
                        help='list of lba formats to test')
    parser.add_argument('-i', '--ioengine', default='io_uring_cmd')
    args = parser.parse_args()

    return args


def get_lbafs(args):
    """
    Determine which LBA formats to use. Use either the ones specified on the
    command line or if none are specified query the device and use all lba
    formats with metadata.
    """
    lbaf_list = []
    id_ns_cmd = f"sudo nvme id-ns --output-format=json {args.dut}".split(' ')
    id_ns_output = subprocess.check_output(id_ns_cmd)
    lbafs = json.loads(id_ns_output)['lbafs']
    if args.lbaf:
        for lbaf in args.lbaf:
            lbaf_list.append({'lbaf': lbaf, 'ds': 2 ** lbafs[lbaf]['ds'],
                              'ms': lbafs[lbaf]['ms'], })
            if lbafs[lbaf]['ms'] == 0:
                print(f'Error: lbaf {lbaf} has metadata size zero')
                sys.exit(1)
    else:
        for lbaf_num, lbaf in enumerate(lbafs):
            if lbaf['ms'] != 0:
                lbaf_list.append({'lbaf': lbaf_num, 'ds': 2 ** lbaf['ds'],
                                  'ms': lbaf['ms'], })

    return lbaf_list


def get_guard_pi(lbaf_list, args):
    """
    Find out how many bits of guard protection information are associated with
    each lbaf to be used. If this is not available assume 16-bit guard pi.
    Also record the bytes of protection information associated with the number
    of guard PI bits.
    """
    nvm_id_ns_cmd = f"sudo nvme nvm-id-ns --output-format=json {args.dut}".split(' ')
    try:
        nvm_id_ns_output = subprocess.check_output(nvm_id_ns_cmd)
    except subprocess.CalledProcessError:
        print(f"Non-zero return code from {' '.join(nvm_id_ns_cmd)}; " \
                "assuming all lbafs use 16b Guard Protection Information")
        for lbaf in lbaf_list:
            lbaf['guard_pi_bits'] = 16
    else:
        elbafs = json.loads(nvm_id_ns_output)['elbafs']
        for elbaf_num, elbaf in enumerate(elbafs):
            for lbaf in lbaf_list:
                if lbaf['lbaf'] == elbaf_num:
                    lbaf['guard_pi_bits'] = 16 << elbaf['pif']

    # For 16b Guard Protection Information, the PI requires 8 bytes
    # For 32b and 64b Guard PI, the PI requires 16 bytes
    for lbaf in lbaf_list:
        if lbaf['guard_pi_bits'] == 16:
            lbaf['pi_bytes'] = 8
        else:
            lbaf['pi_bytes'] = 16


def get_capabilities(args):
    """
    Determine what end-to-end data protection features the device supports.
    """
    caps = { 'pil': [], 'pitype': [], 'elba': [] }
    id_ns_cmd = f"sudo nvme id-ns --output-format=json {args.dut}".split(' ')
    id_ns_output = subprocess.check_output(id_ns_cmd)
    id_ns_json = json.loads(id_ns_output)

    mc = id_ns_json['mc']
    if mc & 1:
        caps['elba'].append(1)
    if mc & 2:
        caps['elba'].append(0)

    dpc = id_ns_json['dpc']
    if dpc & 1:
        caps['pitype'].append(1)
    if dpc & 2:
        caps['pitype'].append(2)
    if dpc & 4:
        caps['pitype'].append(3)
    if dpc & 8:
        caps['pil'].append(1)
    if dpc & 16:
        caps['pil'].append(0)

    for _, value in caps.items():
        if len(value) == 0:
            logging.error("One or more end-to-end data protection features unsupported: %s", caps)
            sys.exit(-1)

    return caps


def format_device(args, lbaf, pitype, pil, elba):
    """
    Format device using specified lba format with specified pitype, pil, and
    elba values.
    """

    format_cmd = f"sudo nvme format {args.dut} --lbaf={lbaf['lbaf']} " \
                 f"--pi={pitype} --pil={pil} --ms={elba} --force"
    logging.debug("Format command: %s", format_cmd)
    format_cmd = format_cmd.split(' ')
    format_cmd_result = subprocess.run(format_cmd, capture_output=True, check=False,
                                       encoding=locale.getpreferredencoding())

    # Sometimes nvme-cli may format the device successfully but fail to
    # rescan the namespaces after the format. Continue if this happens but
    # abort if some other error occurs.
    if format_cmd_result.returncode != 0:
        if 'failed to rescan namespaces' not in format_cmd_result.stderr \
                or 'Success formatting namespace' not in format_cmd_result.stdout:
            logging.error(format_cmd_result.stdout)
            logging.error(format_cmd_result.stderr)
            print("Unable to format device; skipping this configuration")
            return False

    logging.debug(format_cmd_result.stdout)
    return True


def difdix_test(test_env, args, lbaf, pitype, elba):
    """
    Adjust test arguments based on values of lbaf, pitype, and elba.  Then run
    the tests.
    """
    for test in TEST_LIST:
        test['force_skip'] = False

        blocksize = lbaf['ds']
        # Set fio blocksize parameter at runtime
        # If we formatted the device in extended LBA mode (e.g., 520-byte
        # sectors), we usually need to add the lba data size and metadata size
        # together for fio's bs parameter. However, if pi_act == 1 and the
        # device is formatted so that the metadata is the same size as the PI,
        # then the device will take care of everything and the application
        # should just use regular power of 2 lba data size even when the device
        # is in extended lba mode.
        if elba:
            if not test['fio_opts']['pi_act'] or lbaf['ms'] != lbaf['pi_bytes']:
                blocksize += lbaf['ms']
            test['fio_opts']['md_per_io_size'] = 0
        else:
        # If we are using a separate buffer for metadata, fio doesn't need to
        # do anything when pi_act==1 and protection information size is equal to
        # metadata size since the device is taking care of it all. If either of
        # the two conditions do not hold, then we do need to allocate a
        # separate metadata buffer.
            if test['fio_opts']['pi_act'] and lbaf['ms'] == lbaf['pi_bytes']:
                test['fio_opts']['md_per_io_size'] = 0
            else:
                test['fio_opts']['md_per_io_size'] = lbaf['ms'] * test['bs_high']

        test['fio_opts']['bsrange'] = f"{blocksize * test['bs_low']}-{blocksize * test['bs_high']}"
        if 'mdsize_adjustment' in test:
            test['fio_opts']['md_per_io_size'] += test['mdsize_adjustment']

        # Set fio pi_chk parameter at runtime. If the device is formatted
        # with Type 3 protection information, this means that the reference
        # tag is not checked and I/O commands may throw an error if they
        # are submitted with the REFTAG bit set in pi_chk. Make sure fio
        # does not set pi_chk's REFTAG bit if the device is formatted with
        # Type 3 PI.
        if 'pi_chk' in test:
            if pitype == 3 and 'REFTAG' in test['pi_chk']:
                test['fio_opts']['pi_chk'] = test['pi_chk'].replace('REFTAG','')
                logging.debug("Type 3 PI: dropping REFTAG bit")
            else:
                test['fio_opts']['pi_chk'] = test['pi_chk']

        if 'skip' in test:
            if pitype == 3 and 'type3' in test['skip']:
                test['force_skip'] = True
                logging.debug("Type 3 PI: skipping test case")
            if elba and 'elba' in test['skip']:
                test['force_skip'] = True
                logging.debug("extended lba format: skipping test case")

        logging.debug("Test %d: pi_act=%d, bsrange=%s, md_per_io_size=%d", test['test_id'],
                      test['fio_opts']['pi_act'], test['fio_opts']['bsrange'],
                      test['fio_opts']['md_per_io_size'])

    return run_fio_tests(TEST_LIST, test_env, args)


def main():
    """
    Run tests using fio's io_uring_cmd ioengine to exercise end-to-end data
    protection capabilities.
    """

    args = parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    artifact_root = args.artifact_root if args.artifact_root else \
        f"nvmept_pi-test-{time.strftime('%Y%m%d-%H%M%S')}"
    os.mkdir(artifact_root)
    print(f"Artifact directory is {artifact_root}")

    if args.fio:
        fio_path = str(Path(args.fio).absolute())
    else:
        fio_path = 'fio'
    print(f"fio path is {fio_path}")

    lbaf_list = get_lbafs(args)
    get_guard_pi(lbaf_list, args)
    caps = get_capabilities(args)
    print("Device capabilities:", caps)

    for test in TEST_LIST:
        test['fio_opts']['filename'] = args.dut
        test['fio_opts']['ioengine'] = args.ioengine

    test_env = {
              'fio_path': fio_path,
              'fio_root': str(Path(__file__).absolute().parent.parent),
              'artifact_root': artifact_root,
              'basename': 'nvmept_pi',
              }

    total = { 'passed':  0, 'failed': 0, 'skipped': 0 }

    try:
        for lbaf, pil, pitype, elba in itertools.product(lbaf_list, caps['pil'], caps['pitype'],
                                                         caps['elba']):
            print(f"\nlbaf: {lbaf}, pil: {pil}, pitype: {pitype}, elba: {elba}")

            if not format_device(args, lbaf, pitype, pil, elba):
                continue

            test_env['artifact_root'] = \
                os.path.join(artifact_root, f"lbaf{lbaf['lbaf']}pil{pil}pitype{pitype}" \
                    f"elba{elba}")
            os.mkdir(test_env['artifact_root'])

            passed, failed, skipped = difdix_test(test_env, args, lbaf, pitype, elba)

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
