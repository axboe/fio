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
import logging
import platform
import traceback
import subprocess
from pathlib import Path


class FioTest():
    """Base for all fio tests."""

    def __init__(self, exe_path, parameters, success):
        self.exe_path = exe_path
        self.parameters = parameters
        self.success = success
        self.output = {}
        self.artifact_root = None
        self.testnum = None
        self.test_dir = None
        self.passed = True
        self.failure_reason = ''
        self.command_file = None
        self.stdout_file = None
        self.stderr_file = None
        self.exitcode_file = None

    def setup(self, artifact_root, testnum):
        """Setup instance variables for test."""

        self.artifact_root = artifact_root
        self.testnum = testnum
        self.test_dir = os.path.join(artifact_root, f"{testnum:04d}")
        if not os.path.exists(self.test_dir):
            os.mkdir(self.test_dir)

        self.command_file = os.path.join( self.test_dir,
                                         f"{os.path.basename(self.exe_path)}.command")
        self.stdout_file = os.path.join( self.test_dir,
                                        f"{os.path.basename(self.exe_path)}.stdout")
        self.stderr_file = os.path.join( self.test_dir,
                                        f"{os.path.basename(self.exe_path)}.stderr")
        self.exitcode_file = os.path.join( self.test_dir,
                                          f"{os.path.basename(self.exe_path)}.exitcode")

    def run(self):
        """Run the test."""

        raise NotImplementedError()

    def check_result(self):
        """Check test results."""

        raise NotImplementedError()


class FioExeTest(FioTest):
    """Test consists of an executable binary or script"""

    def __init__(self, exe_path, parameters, success):
        """Construct a FioExeTest which is a FioTest consisting of an
        executable binary or script.

        exe_path:       location of executable binary or script
        parameters:     list of parameters for executable
        success:        Definition of test success
        """

        FioTest.__init__(self, exe_path, parameters, success)

    def run(self):
        """Execute the binary or script described by this instance."""

        command = [self.exe_path] + self.parameters
        command_file = open(self.command_file, "w+",
                            encoding=locale.getpreferredencoding())
        command_file.write(f"{command}\n")
        command_file.close()

        stdout_file = open(self.stdout_file, "w+",
                           encoding=locale.getpreferredencoding())
        stderr_file = open(self.stderr_file, "w+",
                           encoding=locale.getpreferredencoding())
        exitcode_file = open(self.exitcode_file, "w+",
                             encoding=locale.getpreferredencoding())
        try:
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
        finally:
            stdout_file.close()
            stderr_file.close()
            exitcode_file.close()

    def check_result(self):
        """Check results of test run."""

        if 'proc' not in self.output:
            if self.output['failure'] == 'timeout':
                self.failure_reason = f"{self.failure_reason} timeout,"
            else:
                assert self.output['failure'] == 'exception'
                self.failure_reason = '{0} exception: {1}, {2}'.format(
                    self.failure_reason, self.output['exc_info'][0],
                    self.output['exc_info'][1])

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

        stderr_size = os.path.getsize(self.stderr_file)
        if 'stderr_empty' in self.success:
            if self.success['stderr_empty']:
                if stderr_size != 0:
                    self.failure_reason = f"{self.failure_reason} stderr not empty,"
                    self.passed = False
            else:
                if stderr_size == 0:
                    self.failure_reason = f"{self.failure_reason} stderr empty,"
                    self.passed = False


class FioJobTest(FioExeTest):
    """Test consists of a fio job"""

    def __init__(self, fio_path, fio_job, success, fio_pre_job=None,
                 fio_pre_success=None, output_format="normal"):
        """Construct a FioJobTest which is a FioExeTest consisting of a
        single fio job file with an optional setup step.

        fio_path:           location of fio executable
        fio_job:            location of fio job file
        success:            Definition of test success
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
        self.fio_output = f"{os.path.basename(self.fio_job)}.output"
        self.fio_args = [
            "--max-jobs=16",
            f"--output-format={self.output_format}",
            f"--output={self.fio_output}",
            self.fio_job,
            ]
        FioExeTest.__init__(self, fio_path, self.fio_args, success)

    def setup(self, artifact_root, testnum):
        """Setup instance variables for fio job test."""

        super().setup(artifact_root, testnum)

        self.command_file = os.path.join(self.test_dir,
                                         f"{os.path.basename(self.fio_job)}.command")
        self.stdout_file = os.path.join(self.test_dir,
                                        f"{os.path.basename(self.fio_job)}.stdout")
        self.stderr_file = os.path.join(self.test_dir,
                                        f"{os.path.basename(self.fio_job)}.stderr")
        self.exitcode_file = os.path.join(self.test_dir,
                                          f"{os.path.basename(self.fio_job)}.exitcode")

    def run_pre_job(self):
        """Run fio job precondition step."""

        precon = FioJobTest(self.exe_path, self.fio_pre_job,
                            self.fio_pre_success,
                            output_format=self.output_format)
        precon.setup(self.artifact_root, self.testnum)
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

    @classmethod
    def get_file(cls, filename):
        """Safely read a file."""
        file_data = ''
        success = True

        try:
            with open(filename, "r", encoding=locale.getpreferredencoding()) as output_file:
                file_data = output_file.read()
        except OSError:
            success = False

        return file_data, success

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

        file_data = self.get_file_fail(os.path.join(self.test_dir, self.fio_output))
        if not file_data:
            return

        #
        # Sometimes fio informational messages are included at the top of the
        # JSON output, especially under Windows. Try to decode output as JSON
        # data, skipping everything until the first {
        #
        lines = file_data.splitlines()
        file_data = '\n'.join(lines[lines.index("{"):])
        try:
            self.json_data = json.loads(file_data)
        except json.JSONDecodeError:
            self.failure_reason = f"{self.failure_reason} unable to decode JSON data,"
            self.passed = False


def run_fio_tests(test_list, test_env, args):
    """
    Run tests as specified in test_list.
    """

    passed = 0
    failed = 0
    skipped = 0

    for config in test_list:
        if (args.skip and config['test_id'] in args.skip) or \
           (args.run_only and config['test_id'] not in args.run_only):
            skipped = skipped + 1
            print(f"Test {config['test_id']} SKIPPED (User request)")
            continue

        if issubclass(config['test_class'], FioJobTest):
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
                fio_pre_job=fio_pre_job,
                fio_pre_success=fio_pre_success,
                output_format=output_format)
            desc = config['job']
        elif issubclass(config['test_class'], FioExeTest):
            exe_path = os.path.join(test_env['fio_root'], config['exe'])
            if config['parameters']:
                parameters = [p.format(fio_path=test_env['fio_path'], nvmecdev=args.nvmecdev)
                              for p in config['parameters']]
            else:
                parameters = []
            if Path(exe_path).suffix == '.py' and platform.system() == "Windows":
                parameters.insert(0, exe_path)
                exe_path = "python.exe"
            if config['test_id'] in test_env['pass_through']:
                parameters += test_env['pass_through'][config['test_id']].split()
            test = config['test_class'](exe_path, parameters,
                                        config['success'])
            desc = config['exe']
        else:
            print(f"Test {config['test_id']} FAILED: unable to process test config")
            failed = failed + 1
            continue

        if not args.skip_req:
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
            test.setup(test_env['artifact_root'], config['test_id'])
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
        else:
            result = f"FAILED: {test.failure_reason}"
            failed = failed + 1
            contents, _ = FioJobTest.get_file(test.stderr_file)
            logging.debug("Test %d: stderr:\n%s", config['test_id'], contents)
            contents, _ = FioJobTest.get_file(test.stdout_file)
            logging.debug("Test %d: stdout:\n%s", config['test_id'], contents)
        print(f"Test {config['test_id']} {result} {desc}")

    print(f"{passed} test(s) passed, {failed} failed, {skipped} skipped")

    return passed, failed, skipped
