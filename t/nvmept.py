#!/usr/bin/env python3
"""
# nvmept.py
#
# Test fio's io_uring_cmd ioengine with NVMe pass-through commands.
#
# USAGE
# see python3 nvmept.py --help
#
# EXAMPLES
# python3 t/nvmept.py --dut /dev/ng0n1
# python3 t/nvmept.py --dut /dev/ng1n1 -f ./fio
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
import argparse
import subprocess
from pathlib import Path

class FioTest():
    """fio test."""

    def __init__(self, artifact_root, test_opts, debug):
        """
        artifact_root   root directory for artifacts (subdirectory will be created under here)
        test            test specification
        """
        self.artifact_root = artifact_root
        self.test_opts = test_opts
        self.debug = debug
        self.filename_stub = None
        self.filenames = {}
        self.json_data = None

        self.test_dir = os.path.abspath(os.path.join(self.artifact_root,
                                     f"{self.test_opts['test_id']:03d}"))
        if not os.path.exists(self.test_dir):
            os.mkdir(self.test_dir)

        self.filename_stub = f"pt{self.test_opts['test_id']:03d}"
        self.filenames['command'] = os.path.join(self.test_dir, f"{self.filename_stub}.command")
        self.filenames['stdout'] = os.path.join(self.test_dir, f"{self.filename_stub}.stdout")
        self.filenames['stderr'] = os.path.join(self.test_dir, f"{self.filename_stub}.stderr")
        self.filenames['exitcode'] = os.path.join(self.test_dir, f"{self.filename_stub}.exitcode")
        self.filenames['output'] = os.path.join(self.test_dir, f"{self.filename_stub}.output")

    def run_fio(self, fio_path):
        """Run a test."""

        fio_args = [
            "--name=nvmept",
            "--ioengine=io_uring_cmd",
            "--cmd_type=nvme",
            "--iodepth=8",
            "--iodepth_batch=4",
            "--iodepth_batch_complete=4",
            f"--filename={self.test_opts['filename']}",
            f"--rw={self.test_opts['rw']}",
            f"--output={self.filenames['output']}",
            f"--output-format={self.test_opts['output-format']}",
        ]
        for opt in ['fixedbufs', 'nonvectored', 'force_async', 'registerfiles',
                    'sqthread_poll', 'sqthread_poll_cpu', 'hipri', 'nowait',
                    'time_based', 'runtime', 'verify', 'io_size']:
            if opt in self.test_opts:
                option = f"--{opt}={self.test_opts[opt]}"
                fio_args.append(option)

        command = [fio_path] + fio_args
        with open(self.filenames['command'], "w+",
                  encoding=locale.getpreferredencoding()) as command_file:
            command_file.write(" ".join(command))

        passed = True

        try:
            with open(self.filenames['stdout'], "w+",
                      encoding=locale.getpreferredencoding()) as stdout_file, \
                open(self.filenames['stderr'], "w+",
                     encoding=locale.getpreferredencoding()) as stderr_file, \
                open(self.filenames['exitcode'], "w+",
                     encoding=locale.getpreferredencoding()) as exitcode_file:
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

        if passed:
            if 'output-format' in self.test_opts and 'json' in \
                    self.test_opts['output-format']:
                if not self.get_json():
                    print('Unable to decode JSON data')
                    passed = False

        return passed

    def get_json(self):
        """Convert fio JSON output into a python JSON object"""

        filename = self.filenames['output']
        with open(filename, 'r', encoding=locale.getpreferredencoding()) as file:
            file_data = file.read()

        #
        # Sometimes fio informational messages are included at the top of the
        # JSON output, especially under Windows. Try to decode output as JSON
        # data, lopping off up to the first four lines
        #
        lines = file_data.splitlines()
        for i in range(5):
            file_data = '\n'.join(lines[i:])
            try:
                self.json_data = json.loads(file_data)
            except json.JSONDecodeError:
                continue
            else:
                return True

        return False

    @staticmethod
    def check_empty(job):
        """
        Make sure JSON data is empty.

        Some data structures should be empty. This function makes sure that they are.

        job         JSON object that we need to check for emptiness
        """

        return job['total_ios'] == 0 and \
                job['slat_ns']['N'] == 0 and \
                job['clat_ns']['N'] == 0 and \
                job['lat_ns']['N'] == 0

    def check_all_ddirs(self, ddir_nonzero, job):
        """
        Iterate over the data directions and check whether each is
        appropriately empty or not.
        """

        retval = True
        ddirlist = ['read', 'write', 'trim']

        for ddir in ddirlist:
            if ddir in ddir_nonzero:
                if self.check_empty(job[ddir]):
                    print(f"Unexpected zero {ddir} data found in output")
                    retval = False
            else:
                if not self.check_empty(job[ddir]):
                    print(f"Unexpected {ddir} data found in output")
                    retval = False

        return retval

    def check(self):
        """Check test output."""

        raise NotImplementedError()


class PTTest(FioTest):
    """
    NVMe pass-through test class. Check to make sure output for selected data
    direction(s) is non-zero and that zero data appears for other directions.
    """

    def check(self):
        if 'rw' not in self.test_opts:
            return True

        job = self.json_data['jobs'][0]
        retval = True

        if self.test_opts['rw'] in ['read', 'randread']:
            retval = self.check_all_ddirs(['read'], job)
        elif self.test_opts['rw'] in ['write', 'randwrite']:
            if 'verify' not in self.test_opts:
                retval = self.check_all_ddirs(['write'], job)
            else:
                retval = self.check_all_ddirs(['read', 'write'], job)
        elif self.test_opts['rw'] in ['trim', 'randtrim']:
            retval = self.check_all_ddirs(['trim'], job)
        elif self.test_opts['rw'] in ['readwrite', 'randrw']:
            retval = self.check_all_ddirs(['read', 'write'], job)
        elif self.test_opts['rw'] in ['trimwrite', 'randtrimwrite']:
            retval = self.check_all_ddirs(['trim', 'write'], job)
        else:
            print(f"Unhandled rw value {self.test_opts['rw']}")
            retval = False

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
    parser.add_argument('--dut', help='target NVMe character device to test '
                        '(e.g., /dev/ng0n1). WARNING: THIS IS A DESTRUCTIVE TEST', required=True)
    args = parser.parse_args()

    return args


def main():
    """Run tests using fio's io_uring_cmd ioengine to send NVMe pass through commands."""

    args = parse_args()

    artifact_root = args.artifact_root if args.artifact_root else \
        f"nvmept-test-{time.strftime('%Y%m%d-%H%M%S')}"
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
            "rw": 'read',
            "timebased": 1,
            "runtime": 3,
            "output-format": "json",
            "test_obj": PTTest,
        },
        {
            "test_id": 2,
            "rw": 'randread',
            "timebased": 1,
            "runtime": 3,
            "output-format": "json",
            "test_obj": PTTest,
        },
        {
            "test_id": 3,
            "rw": 'write',
            "timebased": 1,
            "runtime": 3,
            "output-format": "json",
            "test_obj": PTTest,
        },
        {
            "test_id": 4,
            "rw": 'randwrite',
            "timebased": 1,
            "runtime": 3,
            "output-format": "json",
            "test_obj": PTTest,
        },
        {
            "test_id": 5,
            "rw": 'trim',
            "timebased": 1,
            "runtime": 3,
            "output-format": "json",
            "test_obj": PTTest,
        },
        {
            "test_id": 6,
            "rw": 'randtrim',
            "timebased": 1,
            "runtime": 3,
            "output-format": "json",
            "test_obj": PTTest,
        },
        {
            "test_id": 7,
            "rw": 'write',
            "io_size": 1024*1024,
            "verify": "crc32c",
            "output-format": "json",
            "test_obj": PTTest,
        },
        {
            "test_id": 8,
            "rw": 'randwrite',
            "io_size": 1024*1024,
            "verify": "crc32c",
            "output-format": "json",
            "test_obj": PTTest,
        },
        {
            "test_id": 9,
            "rw": 'readwrite',
            "timebased": 1,
            "runtime": 3,
            "output-format": "json",
            "test_obj": PTTest,
        },
        {
            "test_id": 10,
            "rw": 'randrw',
            "timebased": 1,
            "runtime": 3,
            "output-format": "json",
            "test_obj": PTTest,
        },
        {
            "test_id": 11,
            "rw": 'trimwrite',
            "timebased": 1,
            "runtime": 3,
            "output-format": "json",
            "test_obj": PTTest,
        },
        {
            "test_id": 12,
            "rw": 'randtrimwrite',
            "timebased": 1,
            "runtime": 3,
            "output-format": "json",
            "test_obj": PTTest,
        },
        {
            "test_id": 13,
            "rw": 'randread',
            "timebased": 1,
            "runtime": 3,
            "fixedbufs": 1,
            "nonvectored": 1,
            "force_async": 1,
            "registerfiles": 1,
            "sqthread_poll": 1,
            "output-format": "json",
            "test_obj": PTTest,
        },
        {
            "test_id": 14,
            "rw": 'randwrite',
            "timebased": 1,
            "runtime": 3,
            "fixedbufs": 1,
            "nonvectored": 1,
            "force_async": 1,
            "registerfiles": 1,
            "sqthread_poll": 1,
            "output-format": "json",
            "test_obj": PTTest,
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
            test['filename'] = args.dut
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
