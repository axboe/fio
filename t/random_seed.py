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
import argparse
import subprocess
from pathlib import Path

class FioRandTest():
    """fio random seed test."""

    def __init__(self, artifact_root, test_options, debug):
        """
        artifact_root   root directory for artifacts (subdirectory will be created under here)
        test            test specification
        """
        self.artifact_root = artifact_root
        self.test_options = test_options
        self.debug = debug
        self.filename_stub = None
        self.filenames = {}

        self.test_dir = os.path.abspath(os.path.join(self.artifact_root,
                                     f"{self.test_options['test_id']:03d}"))
        if not os.path.exists(self.test_dir):
            os.mkdir(self.test_dir)

        self.filename_stub = f"random{self.test_options['test_id']:03d}"
        self.filenames['command'] = os.path.join(self.test_dir, f"{self.filename_stub}.command")
        self.filenames['stdout'] = os.path.join(self.test_dir, f"{self.filename_stub}.stdout")
        self.filenames['stderr'] = os.path.join(self.test_dir, f"{self.filename_stub}.stderr")
        self.filenames['exitcode'] = os.path.join(self.test_dir, f"{self.filename_stub}.exitcode")
        self.filenames['output'] = os.path.join(self.test_dir, f"{self.filename_stub}.output")

    def run_fio(self, fio_path):
        """Run a test."""

        fio_args = [
            "--debug=random",
            "--name=random_seed",
            "--ioengine=null",
            "--filesize=32k",
            "--rw=randread",
            f"--output={self.filenames['output']}",
        ]
        for opt in ['randseed', 'randrepeat', 'allrandrepeat']:
            if opt in self.test_options:
                option = f"--{opt}={self.test_options[opt]}"
                fio_args.append(option)

        command = [fio_path] + fio_args
        with open(self.filenames['command'], "w+", encoding=locale.getpreferredencoding()) as command_file:
            command_file.write(" ".join(command))

        passed = True

        try:
            with open(self.filenames['stdout'], "w+", encoding=locale.getpreferredencoding()) as stdout_file, \
                open(self.filenames['stderr'], "w+", encoding=locale.getpreferredencoding()) as stderr_file, \
                open(self.filenames['exitcode'], "w+", encoding=locale.getpreferredencoding()) as exitcode_file:
                proc = None
                # Avoid using subprocess.run() here because when a timeout occurs,
                # fio will be stopped with SIGKILL. This does not give fio a
                # chance to clean up and means that child processes may continue
                # running and submitting IO.
                proc = subprocess.Popen(command,
                                        stdout=stdout_file,
                                        stderr=stderr_file,
                                        cwd=self.test_dir,
                                        universal_newlines=True)
                proc.communicate(timeout=300)
                exitcode_file.write(f'{proc.returncode}\n')
                passed &= (proc.returncode == 0)
        except subprocess.TimeoutExpired:
            proc.terminate()
            proc.communicate()
            assert proc.poll()
            print("Timeout expired")
            passed = False
        except Exception:
            if proc:
                if not proc.poll():
                    proc.terminate()
                    proc.communicate()
            print(f"Exception: {sys.exc_info()}")
            passed = False

        return passed

    def get_rand_seeds(self):
        """Collect random seeds from --debug=random output."""
        with open(self.filenames['output'], "r", encoding=locale.getpreferredencoding()) as out_file:
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

    def check(self):
        """Check test output."""

        raise NotImplementedError()


class TestRR(FioRandTest):
    """
    Test object for [all]randrepeat. If run for the first time just collect the
    seeds. For later runs make sure the seeds match or do not match those
    previously collected.
    """
    # one set of seeds is for randrepeat=0 and the other is for randrepeat=1
    seeds = { 0: None, 1: None }

    def check(self):
        """Check output for allrandrepeat=1."""

        retval = True
        opt = 'randrepeat' if 'randrepeat' in self.test_options else 'allrandrepeat'
        rr = self.test_options[opt]
        rand_seeds = self.get_rand_seeds()

        if not TestRR.seeds[rr]:
            TestRR.seeds[rr] = rand_seeds
            if self.debug:
                print(f"TestRR: saving rand_seeds for [a]rr={rr}")
        else:
            if rr:
                if TestRR.seeds[1] != rand_seeds:
                    retval = False
                    print(f"TestRR: unexpected seed mismatch for [a]rr={rr}")
                else:
                    if self.debug:
                        print(f"TestRR: seeds correctly match for [a]rr={rr}")
                if TestRR.seeds[0] == rand_seeds:
                    retval = False
                    print("TestRR: seeds unexpectedly match those from system RNG")
            else:
                if TestRR.seeds[0] == rand_seeds:
                    retval = False
                    print(f"TestRR: unexpected seed match for [a]rr={rr}")
                else:
                    if self.debug:
                        print(f"TestRR: seeds correctly don't match for [a]rr={rr}")
                if TestRR.seeds[1] == rand_seeds:
                    retval = False
                    print(f"TestRR: random seeds unexpectedly match those from [a]rr=1")

        return retval


class TestRS(FioRandTest):
    """
    Test object when randseed=something controls the generated seeds. If run
    for the first time for a given randseed just collect the seeds. For later
    runs with the same seed make sure the seeds are the same as those
    previously collected.
    """
    seeds = {}

    def check(self):
        """Check output for randseed=something."""

        retval = True
        rand_seeds = self.get_rand_seeds()
        randseed = self.test_options['randseed']

        if self.debug:
            print("randseed = ", randseed)

        if randseed not in TestRS.seeds:
            TestRS.seeds[randseed] = rand_seeds
            if self.debug:
                print("TestRS: saving rand_seeds")
        else:
            if TestRS.seeds[randseed] != rand_seeds:
                retval = False
                print("TestRS: seeds don't match when they should")
            else:
                if self.debug:
                    print("TestRS: seeds correctly match")

        # Now try to find seeds generated using a different randseed and make
        # sure they *don't* match
        for key in TestRS.seeds:
            if key != randseed:
                if TestRS.seeds[key] == rand_seeds:
                    retval = False
                    print("TestRS: randseeds differ but generated seeds match.")
                else:
                    if self.debug:
                        print("TestRS: randseeds differ and generated seeds also differ.")

        return retval


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

    artifact_root = args.artifact_root if args.artifact_root else \
        f"random-seed-test-{time.strftime('%Y%m%d-%H%M%S')}"
    os.mkdir(artifact_root)
    print(f"Artifact directory is {artifact_root}")

    if args.fio:
        fio = str(Path(args.fio).absolute())
    else:
        fio = 'fio'
    print(f"fio path is {fio}")

    test_list = [
        {
            "test_id": 1,
            "randrepeat": 0,
            "test_obj": TestRR,
        },
        {
            "test_id": 2,
            "randrepeat": 0,
            "test_obj": TestRR,
        },
        {
            "test_id": 3,
            "randrepeat": 1,
            "test_obj": TestRR,
        },
        {
            "test_id": 4,
            "randrepeat": 1,
            "test_obj": TestRR,
        },
        {
            "test_id": 5,
            "allrandrepeat": 0,
            "test_obj": TestRR,
        },
        {
            "test_id": 6,
            "allrandrepeat": 0,
            "test_obj": TestRR,
        },
        {
            "test_id": 7,
            "allrandrepeat": 1,
            "test_obj": TestRR,
        },
        {
            "test_id": 8,
            "allrandrepeat": 1,
            "test_obj": TestRR,
        },
        {
            "test_id": 9,
            "randrepeat": 0,
            "randseed": "12345",
            "test_obj": TestRS,
        },
        {
            "test_id": 10,
            "randrepeat": 0,
            "randseed": "12345",
            "test_obj": TestRS,
        },
        {
            "test_id": 11,
            "randrepeat": 1,
            "randseed": "12345",
            "test_obj": TestRS,
        },
        {
            "test_id": 12,
            "allrandrepeat": 0,
            "randseed": "12345",
            "test_obj": TestRS,
        },
        {
            "test_id": 13,
            "allrandrepeat": 1,
            "randseed": "12345",
            "test_obj": TestRS,
        },
        {
            "test_id": 14,
            "randrepeat": 0,
            "randseed": "67890",
            "test_obj": TestRS,
        },
        {
            "test_id": 15,
            "randrepeat": 1,
            "randseed": "67890",
            "test_obj": TestRS,
        },
        {
            "test_id": 16,
            "allrandrepeat": 0,
            "randseed": "67890",
            "test_obj": TestRS,
        },
        {
            "test_id": 17,
            "allrandrepeat": 1,
            "randseed": "67890",
            "test_obj": TestRS,
        },
    ]

    passed = 0
    failed = 0
    skipped = 0

    for test in test_list:
        if (args.skip and test['test_id'] in args.skip) or \
           (args.run_only and test['test_id'] not in args.run_only):
            skipped = skipped + 1
            outcome = 'SKIPPED (User request)'
        else:
            test_obj = test['test_obj'](artifact_root, test, args.debug)
            status = test_obj.run_fio(fio)
            if status:
                status = test_obj.check()
            if status:
                passed = passed + 1
                outcome = 'PASSED'
            else:
                failed = failed + 1
                outcome = 'FAILED'

        print(f"**********Test {test['test_id']} {outcome}**********")

    print(f"{passed} tests passed, {failed} failed, {skipped} skipped")

    sys.exit(failed)


if __name__ == '__main__':
    main()
