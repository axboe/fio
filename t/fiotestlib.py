#!/usr/bin/env python3
"""
fiotestlib.py

This library contains FioTest objects that provide convenient means to run
different sorts of fio tests.

It also contains a test runner that runs an array of dictionary objects
describing fio tests.
"""

import os
import sys
import json
import locale
import shutil
import logging
import platform
import traceback
import subprocess
from pathlib import Path
from fiotestcommon import get_file, SUCCESS_DEFAULT


class FioTest():
    """Base for all fio tests."""

    def __init__(self, exe_path, success, testnum, artifact_root):
        self.success = success
        self.testnum = testnum
        self.output = {}
        self.passed = True
        self.failure_reason = ''
        self.parameters = None
        self.paths = {
                        'exe': exe_path,
                        'artifacts': artifact_root,
                        'test_dir': os.path.join(artifact_root, \
                                f"{testnum:04d}"),
                        }
        self.filenames = {
                            'cmd': os.path.join(self.paths['test_dir'], \
                                    f"{os.path.basename(self.paths['exe'])}.command"),
                            'stdout': os.path.join(self.paths['test_dir'], \
                                    f"{os.path.basename(self.paths['exe'])}.stdout"),
                            'stderr': os.path.join(self.paths['test_dir'], \
                                    f"{os.path.basename(self.paths['exe'])}.stderr"),
                            'exitcode': os.path.join(self.paths['test_dir'], \
                                    f"{os.path.basename(self.paths['exe'])}.exitcode"),
                            }

    def setup(self, parameters):
        """Setup instance variables for test."""

        self.parameters = parameters
        if not os.path.exists(self.paths['test_dir']):
            os.mkdir(self.paths['test_dir'])

    def run(self):
        """Run the test."""

        raise NotImplementedError()

    def check_result(self):
        """Check test results."""

        raise NotImplementedError()


class FioExeTest(FioTest):
    """Test consists of an executable binary or script"""

    def run(self):
        """Execute the binary or script described by this instance."""

        command = [self.paths['exe']] + self.parameters
        with open(self.filenames['cmd'], "w+",
                  encoding=locale.getpreferredencoding()) as command_file:
            command_file.write(" \\\n ".join(command))

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
                                        cwd=self.paths['test_dir'],
                                        universal_newlines=True)
                proc.communicate(timeout=self.success['timeout'])
                exitcode_file.write(f'{proc.returncode}\n')
                logging.debug("Test %d: return code: %d", self.testnum, proc.returncode)
                self.output['proc'] = proc
        except subprocess.TimeoutExpired:
            proc.terminate()
            proc.communicate()
            assert proc.poll()
            self.output['failure'] = 'timeout'
        except Exception:
            if proc:
                if not proc.poll():
                    proc.terminate()
                    proc.communicate()
            self.output['failure'] = 'exception'
            self.output['exc_info'] = sys.exc_info()

    def check_result(self):
        """Check results of test run."""

        if 'proc' not in self.output:
            if self.output['failure'] == 'timeout':
                self.failure_reason = f"{self.failure_reason} timeout,"
            else:
                assert self.output['failure'] == 'exception'
                self.failure_reason = f'{self.failure_reason} exception: ' + \
                f'{self.output["exc_info"][0]}, {self.output["exc_info"][1]}'

            self.passed = False
            return

        if 'zero_return' in self.success:
            if self.success['zero_return']:
                if self.output['proc'].returncode != 0:
                    self.passed = False
                    self.failure_reason = f"{self.failure_reason} non-zero return code,"
            else:
                if self.output['proc'].returncode == 0:
                    self.failure_reason = f"{self.failure_reason} zero return code,"
                    self.passed = False

        stderr_size = os.path.getsize(self.filenames['stderr'])
        if 'stderr_empty' in self.success:
            if self.success['stderr_empty']:
                if stderr_size != 0:
                    self.failure_reason = f"{self.failure_reason} stderr not empty size {stderr_size},"
                    self.passed = False
            else:
                if stderr_size == 0:
                    self.failure_reason = f"{self.failure_reason} stderr empty,"
                    self.passed = False


class FioJobFileTest(FioExeTest):
    """Test consists of a fio job with options in a job file."""

    def __init__(self, fio_path, fio_job, success, testnum, artifact_root,
                 fio_pre_job=None, fio_pre_success=None,
                 output_format="normal"):
        """Construct a FioJobFileTest which is a FioExeTest consisting of a
        single fio job file with an optional setup step.

        fio_path:           location of fio executable
        fio_job:            location of fio job file
        success:            Definition of test success
        testnum:            test ID
        artifact_root:      root directory for artifacts
        fio_pre_job:        fio job for preconditioning
        fio_pre_success:    Definition of test success for fio precon job
        output_format:      normal (default), json, jsonplus, or terse
        """

        self.fio_job = fio_job
        self.fio_pre_job = fio_pre_job
        self.fio_pre_success = fio_pre_success if fio_pre_success else success
        self.output_format = output_format
        self.precon_failed = False
        self.json_data = None

        super().__init__(fio_path, success, testnum, artifact_root)

    def setup(self, parameters):
        """Setup instance variables for fio job test."""

        self.filenames['fio_output'] = f"{os.path.basename(self.fio_job)}.output"
        fio_args = [
            "--max-jobs=16",
            f"--output-format={self.output_format}",
            f"--output={self.filenames['fio_output']}",
            self.fio_job,
            ]
        if parameters:
            fio_args += parameters

        super().setup(fio_args)

        # Update the filenames from the default
        self.filenames['cmd'] = os.path.join(self.paths['test_dir'],
                                             f"{os.path.basename(self.fio_job)}.command")
        self.filenames['stdout'] = os.path.join(self.paths['test_dir'],
                                                f"{os.path.basename(self.fio_job)}.stdout")
        self.filenames['stderr'] = os.path.join(self.paths['test_dir'],
                                                f"{os.path.basename(self.fio_job)}.stderr")
        self.filenames['exitcode'] = os.path.join(self.paths['test_dir'],
                                                  f"{os.path.basename(self.fio_job)}.exitcode")

    def run_pre_job(self):
        """Run fio job precondition step."""

        precon = FioJobFileTest(self.paths['exe'], self.fio_pre_job,
                            self.fio_pre_success,
                            self.testnum,
                            self.paths['artifacts'],
                            output_format=self.output_format)
        precon.setup(None)
        precon.run()
        precon.check_result()
        self.precon_failed = not precon.passed
        self.failure_reason = precon.failure_reason

    def run(self):
        """Run fio job test."""

        if self.fio_pre_job:
            self.run_pre_job()

        if not self.precon_failed:
            super().run()
        else:
            logging.debug("Test %d: precondition step failed", self.testnum)

    def get_file_fail(self, filename):
        """Safely read a file and fail the test upon error."""
        file_data = None

        try:
            with open(filename, "r", encoding=locale.getpreferredencoding()) as output_file:
                file_data = output_file.read()
        except OSError:
            self.failure_reason += f" unable to read file {filename}"
            self.passed = False

        return file_data

    def check_result(self):
        """Check fio job results."""

        if self.precon_failed:
            self.passed = False
            self.failure_reason = f"{self.failure_reason} precondition step failed,"
            return

        super().check_result()

        if not self.passed:
            return

        if 'json' not in self.output_format:
            return

        file_data = self.get_file_fail(os.path.join(self.paths['test_dir'],
                                                    self.filenames['fio_output']))
        if not file_data:
            return

        #
        # Sometimes fio informational messages are included outside the JSON
        # output, especially under Windows. Try to decode output as JSON data,
        # skipping outside the first { and last }
        #
        lines = file_data.splitlines()
        last = len(lines) - lines[::-1].index("}")
        file_data = '\n'.join(lines[lines.index("{"):last])
        try:
            self.json_data = json.loads(file_data)
        except json.JSONDecodeError:
            self.failure_reason = f"{self.failure_reason} unable to decode JSON data,"
            self.passed = False


class FioJobCmdTest(FioExeTest):
    """This runs a fio job with options specified on the command line."""

    def __init__(self, fio_path, success, testnum, artifact_root, fio_opts, basename=None):

        self.basename = basename if basename else os.path.basename(fio_path)
        self.fio_opts = fio_opts
        self.json_data = None
        self.iops_log_lines = None

        super().__init__(fio_path, success, testnum, artifact_root)

        filename_stub = os.path.join(self.paths['test_dir'], f"{self.basename}{self.testnum:03d}")
        self.filenames['cmd'] = f"{filename_stub}.command"
        self.filenames['stdout'] = f"{filename_stub}.stdout"
        self.filenames['stderr'] = f"{filename_stub}.stderr"
        self.filenames['output'] = os.path.abspath(f"{filename_stub}.output")
        self.filenames['exitcode'] = f"{filename_stub}.exitcode"
        self.filenames['iopslog'] = os.path.abspath(f"{filename_stub}")

    def run(self):
        super().run()

        if 'output-format' in self.fio_opts and 'json' in \
                self.fio_opts['output-format']:
            if not self.get_json():
                print('Unable to decode JSON data')
                self.passed = False

        if any('--write_iops_log=' in param for param in self.parameters):
            self.get_iops_log()

    def get_iops_log(self):
        """Read IOPS log from the first job."""

        log_filename = self.filenames['iopslog'] + "_iops.1.log"
        with open(log_filename, 'r', encoding=locale.getpreferredencoding()) as iops_file:
            self.iops_log_lines = iops_file.read()

    def get_json(self):
        """Convert fio JSON output into a python JSON object"""

        filename = self.filenames['output']
        with open(filename, 'r', encoding=locale.getpreferredencoding()) as file:
            file_data = file.read()

        #
        # Sometimes fio informational messages are included outside the JSON
        # output, especially under Windows. Try to decode output as JSON data,
        # skipping outside the first { and last }
        #
        lines = file_data.splitlines()
        last = len(lines) - lines[::-1].index("}")
        file_data = '\n'.join(lines[lines.index("{"):last])
        try:
            self.json_data = json.loads(file_data)
        except json.JSONDecodeError:
            return False

        return True

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


def run_fio_tests(test_list, test_env, args):
    """
    Run tests as specified in test_list.
    """

    passed = 0
    failed = 0
    skipped = 0

    for config in test_list:
        if (args.skip and config['test_id'] in args.skip) or \
           (args.run_only and config['test_id'] not in args.run_only) or \
           ('force_skip' in config and config['force_skip']):
            skipped = skipped + 1
            print(f"Test {config['test_id']} SKIPPED (User request or override)")
            continue

        if issubclass(config['test_class'], FioJobFileTest):
            if config['pre_job']:
                fio_pre_job = os.path.join(test_env['fio_root'], 't', 'jobs',
                                           config['pre_job'])
            else:
                fio_pre_job = None
            if config['pre_success']:
                fio_pre_success = config['pre_success']
            else:
                fio_pre_success = None
            if 'output_format' in config:
                output_format = config['output_format']
            else:
                output_format = 'normal'
            test = config['test_class'](
                test_env['fio_path'],
                os.path.join(test_env['fio_root'], 't', 'jobs', config['job']),
                config['success'],
                config['test_id'],
                test_env['artifact_root'],
                fio_pre_job=fio_pre_job,
                fio_pre_success=fio_pre_success,
                output_format=output_format)
            desc = config['job']
            parameters = config['parameters'] if 'parameters' in config else None
        elif issubclass(config['test_class'], FioJobCmdTest):
            if not 'success' in config:
                config['success'] = SUCCESS_DEFAULT
            test = config['test_class'](test_env['fio_path'],
                                        config['success'],
                                        config['test_id'],
                                        test_env['artifact_root'],
                                        config['fio_opts'],
                                        test_env['basename'])
            desc = config['test_id']
            parameters = config
        elif issubclass(config['test_class'], FioExeTest):
            exe_path = os.path.join(test_env['fio_root'], config['exe'])
            parameters = []
            if config['parameters']:
                parameters = [p.format(fio_path=test_env['fio_path'], nvmecdev=args.nvmecdev)
                              for p in config['parameters']]
            if Path(exe_path).suffix == '.py' and platform.system() == "Windows":
                parameters.insert(0, exe_path)
                exe_path = "python.exe"
            if config['test_id'] in test_env['pass_through']:
                parameters += test_env['pass_through'][config['test_id']].split()
            test = config['test_class'](
                    exe_path,
                    config['success'],
                    config['test_id'],
                    test_env['artifact_root'])
            desc = config['exe']
        else:
            print(f"Test {config['test_id']} FAILED: unable to process test config")
            failed = failed + 1
            continue

        if 'requirements' in config and not args.skip_req:
            reqs_met = True
            for req in config['requirements']:
                reqs_met, reason = req()
                logging.debug("Test %d: Requirement '%s' met? %s", config['test_id'], reason,
                              reqs_met)
                if not reqs_met:
                    break
            if not reqs_met:
                print(f"Test {config['test_id']} SKIPPED ({reason}) {desc}")
                skipped = skipped + 1
                continue

        try:
            test.setup(parameters)
            test.run()
            test.check_result()
        except KeyboardInterrupt:
            break
        except Exception as e:
            test.passed = False
            test.failure_reason += str(e)
            logging.debug("Test %d exception:\n%s\n", config['test_id'], traceback.format_exc())
        if test.passed:
            result = "PASSED"
            passed = passed + 1
            if hasattr(args, 'cleanup') and args.cleanup:
                shutil.rmtree(test_env['artifact_root'] + f"/{config['test_id']:04d}", ignore_errors=True)
        else:
            result = f"FAILED: {test.failure_reason}"
            failed = failed + 1
            contents, _ = get_file(test.filenames['stderr'])
            logging.debug("Test %d: stderr:\n%s", config['test_id'], contents)
            contents, _ = get_file(test.filenames['stdout'])
            logging.debug("Test %d: stdout:\n%s", config['test_id'], contents)
        print(f"Test {config['test_id']} {result} {desc}")

    print(f"{passed} test(s) passed, {failed} failed, {skipped} skipped")

    return passed, failed, skipped
