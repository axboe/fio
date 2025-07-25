#!/usr/bin/env python3

"""
# io_uring_pi.py
#
# Test metadata support using the io_uring ioengine.
#
# USAGE
# See python3 io_uring_pi.py --help
#
# EXAMPLES (THIS IS A DESTRUCTIVE TEST!!)
# python3 t/io_uring_pi.py --dut /dev/nvme1n1 -f ./fio
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
            "--name=io_uring_pi",
            "--ioengine=io_uring",
            "--direct=1",
            f"--filename={self.fio_opts['filename']}",
            f"--rw={self.fio_opts['rw']}",
            f"--bsrange={self.fio_opts['bsrange']}",
            f"--output={os.path.basename(self.filenames['output'])}",
            f"--md_per_io_size={self.fio_opts['md_per_io_size']}",
            "--pi_act=0",
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

        super().setup(fio_args)


TEST_LIST = [
#
# Write data with pi_act=0 and then read the data back
#
    {
        # Write workload with variable IO sizes
        # pi_act=0
        "test_id": 101,
        "fio_opts": {
            "rw": 'write',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "apptag": "0x8888",
            "apptag_mask": "0xFFFF",
            "pi_act": 0,
            },
        "pi_chk": "GUARD,REFTAG,APPTAG",
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
            "apptag": "0x8888",
            "apptag_mask": "0xFFFF",
            "pi_act": 0,
            },
        "pi_chk": "GUARD,REFTAG,APPTAG",
        "bs_low": BS_LOW,
        "bs_high": BS_LOW,
        "test_class": DifDixTest,
    },
    {
        # Read workload with variable IO size
        # pi_act=0
        "test_id": 103,
        "fio_opts": {
            "rw": 'read',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "apptag": "0x8888",
            "apptag_mask": "0xFFFF",
            "pi_act": 0,
            },
        "pi_chk": "GUARD,REFTAG,APPTAG",
        "bs_low": BS_LOW,
        "bs_high": BS_HIGH,
        "test_class": DifDixTest,
    },
    {
        # Read workload with variable IO size
        # trigger apptag mismatch error
        # pi_act=0
        "test_id": 104,
        "fio_opts": {
            "rw": 'read',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "apptag": "0xA888",
            "apptag_mask": "0xFFFF",
            "pi_act": 0,
            },
        "pi_chk": "GUARD,REFTAG,APPTAG",
        "bs_low": BS_LOW,
        "bs_high": BS_HIGH,
        "success": SUCCESS_NONZERO,
        "test_class": DifDixTest,
    },
    {
        # Read workload with variable IO size
        # fails because apptag mask must be 0xFFFF
        # pi_act=0
        "test_id": 105,
        "fio_opts": {
            "rw": 'read',
            "number_ios": NUMBER_IOS,
            "output-format": "json",
            "apptag": "0xF888",
            "apptag_mask": "0x0FFF",
            "pi_act": 0,
            },
        "pi_chk": "GUARD,REFTAG,APPTAG",
        "bs_low": BS_LOW,
        "bs_high": BS_HIGH,
        "success": SUCCESS_NONZERO,
        "test_class": DifDixTest,
    },
]


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
    parser.add_argument('--dut', help='target device to test '
                        '(e.g., /dev/nvme1n1). WARNING: THIS IS A DESTRUCTIVE TEST', required=True)
    parser.add_argument('-l', '--lbaf', nargs='+', type=int,
                        help='list of lba formats to test')
    args = parser.parse_args()

    return args


def difdix_test(test_env, args, lbaf, pitype):
    """
    Adjust test arguments based on values of lbaf, and pitype.  Then run
    the tests.
    """
    for test in TEST_LIST:
        test['force_skip'] = False

        blocksize = lbaf['ds']
        # Set fio blocksize parameter at runtime
        test['fio_opts']['md_per_io_size'] = lbaf['ms'] * test['bs_high']

        test['fio_opts']['bsrange'] = f"{blocksize * test['bs_low']}-{blocksize * test['bs_high']}"

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

        logging.debug("Test %d: pi_act=%d, bsrange=%s, md_per_io_size=%d", test['test_id'],
                      test['fio_opts']['pi_act'], test['fio_opts']['bsrange'],
                      test['fio_opts']['md_per_io_size'])

    return run_fio_tests(TEST_LIST, test_env, args)


def main():
    args = parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    artifact_root = args.artifact_root if args.artifact_root else \
        f"io_uring_pi-test-{time.strftime('%Y%m%d-%H%M%S')}"
    os.mkdir(artifact_root)
    print(f"Artifact directory is {artifact_root}")

    if args.fio:
        fio_path = str(Path(args.fio).absolute())
    else:
        fio_path = os.path.join(os.path.dirname(__file__), '../fio')
    print(f"fio path is {fio_path}")

    lbaf_list = get_lbafs(args)
    get_guard_pi(lbaf_list, args)
    caps = get_capabilities(args)
    print("Device capabilities:", caps)

    for test in TEST_LIST:
        test['fio_opts']['filename'] = args.dut
    test_env = {
              'fio_path': fio_path,
              'fio_root': str(Path(__file__).absolute().parent.parent),
              'artifact_root': artifact_root,
              'basename': 'io_uring_pi',
              }

    total = { 'passed':  0, 'failed': 0, 'skipped': 0 }

    try:
        for lbaf, pil, pitype in itertools.product(lbaf_list, caps['pil'], caps['pitype']):
            if lbaf['ms'] == 0:
                continue

            print("\n")
            print("-" * 120)
            print(f"lbaf: {lbaf}, pil: {pil}, pitype: {pitype}")
            print("-" * 120)

            if not format_device(args, lbaf, pitype, pil, 0):
                print("Formatting failed")
                continue

            test_env['artifact_root'] = \
                os.path.join(artifact_root, f"lbaf{lbaf['lbaf']}pil{pil}pitype{pitype}")
            os.mkdir(test_env['artifact_root'])

            passed, failed, skipped = difdix_test(test_env, args, lbaf, pitype)

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
