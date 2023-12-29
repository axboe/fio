#!/usr/bin/env python3
"""
# random_seed.py
#
# Test fio's random seed options.
#
# - make sure that randseed overrides randrepeat and allrandrepeat
# - make sure that seeds differ across invocations when [all]randrepeat=0 and randseed is not set
# - make sure that seeds are always the same when [all]randrepeat=1 and randseed is not set
#
# USAGE
# see python3 random_seed.py --help
#
# EXAMPLES
# python3 t/random_seed.py
# python3 t/random_seed.py -f ./fio
#
# REQUIREMENTS
# Python 3.6
#
"""
import os
import sys
import time
import locale
import logging
import argparse
from pathlib import Path
from fiotestlib import FioJobCmdTest, run_fio_tests

class FioRandTest(FioJobCmdTest):
    """fio random seed test."""

    def setup(self, parameters):
        """Setup the test."""

        fio_args = [
            "--debug=random",
            "--name=random_seed",
            "--ioengine=null",
            "--filesize=32k",
            "--rw=randread",
            f"--output={self.filenames['output']}",
        ]
        for opt in ['randseed', 'randrepeat', 'allrandrepeat']:
            if opt in self.fio_opts:
                option = f"--{opt}={self.fio_opts[opt]}"
                fio_args.append(option)

        super().setup(fio_args)

    def get_rand_seeds(self):
        """Collect random seeds from --debug=random output."""
        with open(self.filenames['output'], "r",
                  encoding=locale.getpreferredencoding()) as out_file:
            file_data = out_file.read()

            offsets = 0
            for line in file_data.split('\n'):
                if 'random' in line and 'FIO_RAND_NR_OFFS=' in line:
                    tokens = line.split('=')
                    offsets = int(tokens[len(tokens)-1])
                    break

            if offsets == 0:
                pass
                # find an exception to throw

            seed_list = []
            for line in file_data.split('\n'):
                if 'random' not in line:
                    continue
                if 'rand_seeds[' in line:
                    tokens = line.split('=')
                    seed = int(tokens[-1])
                    seed_list.append(seed)
                    # assume that seeds are in order

            return seed_list


class TestRR(FioRandTest):
    """
    Test object for [all]randrepeat. If run for the first time just collect the
    seeds. For later runs make sure the seeds match or do not match those
    previously collected.
    """
    # one set of seeds is for randrepeat=0 and the other is for randrepeat=1
    seeds = { 0: None, 1: None }

    def check_result(self):
        """Check output for allrandrepeat=1."""

        super().check_result()
        if not self.passed:
            return

        opt = 'randrepeat' if 'randrepeat' in self.fio_opts else 'allrandrepeat'
        rr = self.fio_opts[opt]
        rand_seeds = self.get_rand_seeds()

        if not TestRR.seeds[rr]:
            TestRR.seeds[rr] = rand_seeds
            logging.debug("TestRR: saving rand_seeds for [a]rr=%d", rr)
        else:
            if rr:
                if TestRR.seeds[1] != rand_seeds:
                    self.passed = False
                    print(f"TestRR: unexpected seed mismatch for [a]rr={rr}")
                else:
                    logging.debug("TestRR: seeds correctly match for [a]rr=%d", rr)
                if TestRR.seeds[0] == rand_seeds:
                    self.passed = False
                    print("TestRR: seeds unexpectedly match those from system RNG")
            else:
                if TestRR.seeds[0] == rand_seeds:
                    self.passed = False
                    print(f"TestRR: unexpected seed match for [a]rr={rr}")
                else:
                    logging.debug("TestRR: seeds correctly don't match for [a]rr=%d", rr)
                if TestRR.seeds[1] == rand_seeds:
                    self.passed = False
                    print("TestRR: random seeds unexpectedly match those from [a]rr=1")


class TestRS(FioRandTest):
    """
    Test object when randseed=something controls the generated seeds. If run
    for the first time for a given randseed just collect the seeds. For later
    runs with the same seed make sure the seeds are the same as those
    previously collected.
    """
    seeds = {}

    def check_result(self):
        """Check output for randseed=something."""

        super().check_result()
        if not self.passed:
            return

        rand_seeds = self.get_rand_seeds()
        randseed = self.fio_opts['randseed']

        logging.debug("randseed = %s", randseed)

        if randseed not in TestRS.seeds:
            TestRS.seeds[randseed] = rand_seeds
            logging.debug("TestRS: saving rand_seeds")
        else:
            if TestRS.seeds[randseed] != rand_seeds:
                self.passed = False
                print("TestRS: seeds don't match when they should")
            else:
                logging.debug("TestRS: seeds correctly match")

        # Now try to find seeds generated using a different randseed and make
        # sure they *don't* match
        for key, value in TestRS.seeds.items():
            if key != randseed:
                if value == rand_seeds:
                    self.passed = False
                    print("TestRS: randseeds differ but generated seeds match.")
                else:
                    logging.debug("TestRS: randseeds differ and generated seeds also differ.")


def parse_args():
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--fio', help='path to file executable (e.g., ./fio)')
    parser.add_argument('-a', '--artifact-root', help='artifact root directory')
    parser.add_argument('-d', '--debug', help='enable debug output', action='store_true')
    parser.add_argument('-s', '--skip', nargs='+', type=int,
                        help='list of test(s) to skip')
    parser.add_argument('-o', '--run-only', nargs='+', type=int,
                        help='list of test(s) to run, skipping all others')
    args = parser.parse_args()

    return args


def main():
    """Run tests of fio random seed options"""

    args = parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    artifact_root = args.artifact_root if args.artifact_root else \
        f"random-seed-test-{time.strftime('%Y%m%d-%H%M%S')}"
    os.mkdir(artifact_root)
    print(f"Artifact directory is {artifact_root}")

    if args.fio:
        fio_path = str(Path(args.fio).absolute())
    else:
        fio_path = 'fio'
    print(f"fio path is {fio_path}")

    test_list = [
        {
            "test_id": 1,
            "fio_opts": {
                "randrepeat": 0,
                },
            "test_class": TestRR,
        },
        {
            "test_id": 2,
            "fio_opts": {
                "randrepeat": 0,
                },
            "test_class": TestRR,
        },
        {
            "test_id": 3,
            "fio_opts": {
                "randrepeat": 1,
                },
            "test_class": TestRR,
        },
        {
            "test_id": 4,
            "fio_opts": {
                "randrepeat": 1,
                },
            "test_class": TestRR,
        },
        {
            "test_id": 5,
            "fio_opts": {
                "allrandrepeat": 0,
                },
            "test_class": TestRR,
        },
        {
            "test_id": 6,
            "fio_opts": {
                "allrandrepeat": 0,
                },
            "test_class": TestRR,
        },
        {
            "test_id": 7,
            "fio_opts": {
                "allrandrepeat": 1,
                },
            "test_class": TestRR,
        },
        {
            "test_id": 8,
            "fio_opts": {
                "allrandrepeat": 1,
                },
            "test_class": TestRR,
        },
        {
            "test_id": 9,
            "fio_opts": {
                "randrepeat": 0,
                "randseed": "12345",
                },
            "test_class": TestRS,
        },
        {
            "test_id": 10,
            "fio_opts": {
                "randrepeat": 0,
                "randseed": "12345",
                },
            "test_class": TestRS,
        },
        {
            "test_id": 11,
            "fio_opts": {
                "randrepeat": 1,
                "randseed": "12345",
                },
            "test_class": TestRS,
        },
        {
            "test_id": 12,
            "fio_opts": {
                "allrandrepeat": 0,
                "randseed": "12345",
                },
            "test_class": TestRS,
        },
        {
            "test_id": 13,
            "fio_opts": {
                "allrandrepeat": 1,
                "randseed": "12345",
                },
            "test_class": TestRS,
        },
        {
            "test_id": 14,
            "fio_opts": {
                "randrepeat": 0,
                "randseed": "67890",
                },
            "test_class": TestRS,
        },
        {
            "test_id": 15,
            "fio_opts": {
                "randrepeat": 1,
                "randseed": "67890",
                },
            "test_class": TestRS,
        },
        {
            "test_id": 16,
            "fio_opts": {
                "allrandrepeat": 0,
                "randseed": "67890",
                },
            "test_class": TestRS,
        },
        {
            "test_id": 17,
            "fio_opts": {
                "allrandrepeat": 1,
                "randseed": "67890",
                },
            "test_class": TestRS,
        },
    ]

    test_env = {
              'fio_path': fio_path,
              'fio_root': str(Path(__file__).absolute().parent.parent),
              'artifact_root': artifact_root,
              'basename': 'random',
              }

    _, failed, _ = run_fio_tests(test_list, test_env, args)
    sys.exit(failed)


if __name__ == '__main__':
    main()
