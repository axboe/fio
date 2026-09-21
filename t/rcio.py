#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2026 Sandisk Corporation or its affiliates.

"""
Tests for fio's RCIO feature using temporary regular files and null/psync.

USAGE:
  python t/rcio.py [-f fio-executable]

This script is also invoked by t/run-fio-tests.py. Run on Linux only.
Tests that trace or inject system calls are skipped if strace is unavailable.
"""

import argparse
import json
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import sys
import time

from fiotestcommon import SUCCESS_DEFAULT, SUCCESS_NONZERO
from fiotestlib import FioJobCmdTest, run_fio_tests


def limit_state_file_size():
    """Force write failure without filling the filesystem."""
    signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    resource.setrlimit(resource.RLIMIT_FSIZE, (8, 8))


class FioRcioTest(FioJobCmdTest):
    """RCIO command tests, with optional steps sharing one target and snapshot."""

    def setup(self, parameters):
        """Set up the command and retain artifacts in the standard test directory."""
        self.config = parameters
        directory = Path(self.paths['test_dir']).absolute()
        directory.mkdir(parents=True, exist_ok=True)
        self.target = Path(parameters.get('target', directory / 'target'))
        self.state = Path(parameters.get('state', directory / 'state.bin'))
        if 'target' not in parameters:
            if self.state.exists():
                self.state.unlink()
            with self.target.open('wb') as target:
                target.truncate(1024 * 1024)
        self.original = self.state.read_bytes() if self.state.exists() else None
        self.ready = directory / 'ready'
        if self.ready.exists():
            self.ready.unlink()
        options = {
            'name': 'rcio', 'ioengine': 'null', 'thread': 1,
            'filename': self.target, 'size': '1M', 'bs': '4k',
            'rcio_bs': '4k', 'eta': 'never', 'rw': 'randwrite',
        }
        options.update(self.fio_opts)
        if parameters.get('early_reject'):
            self.target.unlink()
            options['ioengine'] = 'psync'
            if options.get('nrfiles', 1) > 1:
                options['filename'] = f'{self.target}:{self.target}.second'
            if options.get('rcio_state_file'):
                options['rcio_state_file'] = self.state
        if 'iolog' in parameters:
            del options['filename']
            iolog = directory / 'replay.iolog'
            iolog.write_text(
                ('fio version 2 iolog\n{target} add\n{target} open\n' +
                 parameters['iolog'] + '{target} close\n').format(
                     target=self.target), encoding='utf-8')
            options['read_iolog'] = iolog
        if parameters.get('persist'):
            options['rcio_state_file'] = self.state
        if 'signal' in parameters:
            options['exec_prerun'] = f'touch {self.ready}'
        fio_args = [f'--{key}={value}' for key, value in options.items()]
        fio_args.append(f"--output={self.filenames['output']}")
        if 'jobs' in parameters:
            jobfile = directory / 'jobs.fio'
            jobfile.write_text(parameters['jobs'].format(
                target=self.target, state=self.state), encoding='utf-8')
            fio_args = ['--eta=never', f"--output={self.filenames['output']}",
                        str(jobfile)]
            if 'output-format' in self.fio_opts:
                fio_args.insert(0, f"--output-format={self.fio_opts['output-format']}")
        super().setup(fio_args)

    def run(self):
        """Use the standard runner except when injecting faults or signals."""
        if 'steps' in self.config:
            for number, config in enumerate(self.config['steps'], 1):
                step = FioRcioTest(
                    self.paths['exe'],
                    dict(config.get('success', SUCCESS_DEFAULT), timeout=30),
                    number, self.paths['test_dir'], config.get('fio_opts', {}),
                    self.basename)
                step.setup(dict(config, target=self.target, state=self.state))
                step.run()
                step.check_result()
                if not step.passed:
                    self.passed = False
                    self.failure_reason += (
                        f" step {number} ({step.paths['test_dir']}):"
                        f" {step.failure_reason}")
                    break
            return

        if 'trace' in self.config:
            self.trace = Path(self.paths['test_dir']).absolute() / 'flush.trace'
            prefix = ['-f', '-yy', '-o', str(self.trace),
                      '-e', 'trace=fsync,rename']
            if self.config['trace'] == 'failure':
                prefix += ['-P', str(self.target), '-e', 'inject=fsync:error=EIO']
            elif self.config['trace'] == 'short':
                prefix += ['-e', 'trace=pwrite64,fsync,rename',
                           '-e', 'inject=pwrite64:retval=2048:when=1']
            self.parameters = prefix + [self.paths['exe']] + self.parameters
            self.paths['exe'] = shutil.which('strace')

        if not any(key in self.config for key in ('limit', 'signal', 'invalidate')):
            super().run()
            return

        snapshot = self.state.open('rb') if self.config.get('invalidate') else None
        try:
            if snapshot:
                self.parameters.append(
                    f'--rcio_state_file=/proc/self/fd/{snapshot.fileno()}')
            if self.config.get('limit'):
                # The child limit must not truncate the result artifacts.
                self.parameters.remove(f"--output={self.filenames['output']}")
            command = [self.paths['exe']] + self.parameters
            Path(self.filenames['cmd']).write_text(
                " \\\n ".join(command), encoding='utf-8')
            with open(self.filenames['stdout'], 'w', encoding='utf-8') as stdout, \
                    open(self.filenames['stderr'], 'w', encoding='utf-8') as stderr:
                process = subprocess.Popen(
                    command, cwd=self.paths['test_dir'],
                    stdout=subprocess.PIPE if self.config.get('limit') else stdout,
                    stderr=subprocess.PIPE if self.config.get('limit') else stderr,
                    preexec_fn=limit_state_file_size if self.config.get('limit') else None,
                    pass_fds=(snapshot.fileno(),) if snapshot else ())
                try:
                    if 'signal' in self.config:
                        deadline = time.monotonic() + 10
                        while True:
                            if process.poll() is not None:
                                raise RuntimeError('job exited before prerun')
                            if self.ready.exists():
                                status = Path(f'/proc/{process.pid}/status').read_text(
                                    encoding='utf-8')
                                ignored = next(line.split()[1] for line in
                                               status.splitlines()
                                               if line.startswith('SigIgn:'))
                                # system() temporarily ignores SIGINT during prerun.
                                if not int(ignored, 16) & (1 << (signal.SIGINT - 1)):
                                    break
                            if time.monotonic() >= deadline:
                                raise RuntimeError('job did not reach prerun')
                            time.sleep(0.01)
                        if self.state.exists():
                            raise RuntimeError('snapshot was not invalidated before I/O')
                        process.send_signal(self.config['signal'])
                    captured_stdout, captured_stderr = process.communicate(
                        timeout=self.success['timeout'])
                    if self.config.get('limit'):
                        stdout.write(captured_stdout.decode())
                        stderr.write(captured_stderr.decode())
                        Path(self.filenames['output']).write_bytes(
                            captured_stdout + captured_stderr)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=10)
                self.output['proc'] = process
                Path(self.filenames['exitcode']).write_text(
                    f'{process.returncode}\n', encoding='utf-8')
        finally:
            if snapshot:
                snapshot.close()

    def check_result(self):
        """Check process status, snapshot publication and exact output shape."""
        if 'steps' in self.config:
            return
        super().check_result()
        if not self.passed:
            return
        if self.config.get('early_reject') and (
                self.target.exists() or
                self.target.with_suffix('.second').exists()):
            self.passed = False
            self.failure_reason += ' target created before option rejection,'
        output = Path(self.filenames['output']).read_text(encoding='utf-8')
        for text in self.config.get('contains', []):
            if text not in output:
                self.passed = False
                self.failure_reason += f" missing output: {text!r},"
        for text in self.config.get('excludes', []):
            if text in output:
                self.passed = False
                self.failure_reason += f" unexpected output: {text!r},"
        if 'snapshot' in self.config and self.state.is_file() != self.config['snapshot']:
            self.passed = False
            self.failure_reason += ' unexpected snapshot presence,'
        if self.config.get('unchanged') and self.state.read_bytes() != self.original:
            self.passed = False
            self.failure_reason += ' original snapshot changed,'
        if list(self.state.parent.glob('state.bin.tmp.*')):
            self.passed = False
            self.failure_reason += ' temporary snapshot leaked,'
        if 'output-format' in self.fio_opts:
            # The shared JSON reader tolerates surrounding text; RCIO must not.
            report = json.loads(output)
            for name, directions in self.config.get('job_io_bytes', {}).items():
                jobs = [job for job in report['jobs'] if job['jobname'] == name]
                if len(jobs) != 1 or any(
                        jobs[0][direction]['io_bytes'] != count
                        for direction, count in directions.items()):
                    self.passed = False
                    self.failure_reason += f' unexpected I/O counts for {name},'
            job = report['jobs'][0]
            if 'region_direction' in self.config:
                ios = job[self.config['region_direction']]['total_ios']
                if ios < 8 or ios % 8:
                    self.passed = False
                    self.failure_reason += f' incomplete region run: {ios} I/Os,'
            if 'write_bytes' in self.config:
                if job['write']['io_bytes'] != self.config['write_bytes']:
                    self.passed = False
                    self.failure_reason += ' unexpected precondition write count,'
        if self.config.get('trace') == 'success':
            calls = self.trace.read_text(encoding='utf-8')
            if calls.index(f'<{self.target}>') >= calls.index('rename('):
                self.passed = False
                self.failure_reason += ' target not flushed before publication,'
        if self.config.get('trace') == 'short':
            calls = self.trace.read_text(encoding='utf-8')
            if '2048 (INJECTED)' not in calls:
                self.passed = False
                self.failure_reason += ' short transfer was not injected,'


SAVE = {
    'persist': True, 'snapshot': True,
    'contains': ['(256/256 valid)'],
}
TRIM = {
    'fio_opts': {'rw': 'randtrim'}, 'persist': True, 'snapshot': True,
    'contains': ['(0/256 valid)'],
}
INCOMPLETE = 'run incomplete or device state uncertain'
GLOBAL = (
    '[global]\nfilename={target}\nsize=1M\n'
    'ioengine=null\nthread=1\nbs=4k\nrcio_bs=4k\n'
)


TEST_LIST = [
    {
        'test_id': 1,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {},
        'steps': [
            SAVE,
            {
                'jobs': GLOBAL + (
                    '[first]\n'
                    'rw=randwrite\n'
                    '[late]\n'
                    'stonewall\n'
                    'rw=randread\n'
                    'rcio_state_file={state}\n'
                ),
                'success': SUCCESS_NONZERO,
                'contains': ['cannot attach rcio_state_file'],
                'excludes': ['loaded state from'],
                'unchanged': True,
            },
        ],
    },
    {
        'test_id': 2,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {},
        'jobs': GLOBAL + (
            '[precondition]\n'
            'rw=randwrite\n'
            'rcio_precondition=1\n'
            'rcio_state_file={state}\n'
            '[trim]\n'
            'stonewall\n'
            'rw=randtrim\n'
        ),
        'snapshot': True,
        'contains': ['(0/256 valid)'],
    },
    {
        'test_id': 3,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_NONZERO, timeout=30),
        'fio_opts': {
            'rcio_precondition': 1,
            'io_size': '2M',
        },
        'persist': True,
        'snapshot': False,
        'contains': [INCOMPLETE],
    },
    {
        'test_id': 4,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {},
        'jobs': GLOBAL + (
            '[precondition]\n'
            'rw=randwrite\n'
            'io_size=512k\n'
            'rcio_state_file={state}\n'
            '[trim]\n'
            'stonewall\n'
            'rw=randtrim:8\n'
            'bs=512\n'
            'time_based=1\n'
            'runtime=1\n'
            'flow=8\n'
            'flow_id=1\n'
            'rcio_state_file={state}\n'
            '[write]\n'
            'rw=randwrite\n'
            'time_based=1\n'
            'runtime=1\n'
            'flow=1\n'
            'flow_id=1\n'
            '[read]\n'
            'rw=randread:8\n'
            'bs=512\n'
            'time_based=1\n'
            'runtime=1\n'
            'flow=16\n'
            'flow_id=1\n'
        ),
        'snapshot': True,
    },
    {
        'test_id': 5,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {},
        'steps': [
            SAVE,
            {
                'fio_opts': {
                    'rcio_precondition': 1,
                },
                'persist': True,
                'snapshot': True,
                'contains': ['skipping precondition (state loaded)'],
            },
        ],
    },
    {
        'test_id': 6,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {},
        'steps': [
            SAVE,
            {
                'fio_opts': {
                    'rw': 'randtrim',
                },
                'invalidate': True,
                'success': SUCCESS_NONZERO,
                'contains': ['cannot invalidate'],
                'excludes': ['saved state to'],
                'unchanged': True,
            },
        ],
    },
    {
        'test_id': 7,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {},
        'steps': [
            SAVE,
            {
                'fio_opts': {
                    'rw': 'randtrim',
                },
                'persist': True,
                'limit': True,
                'success': SUCCESS_NONZERO,
                'snapshot': False,
                'contains': ['loaded state from', 'failed to save state'],
            },
            {
                'fio_opts': {
                    'rcio_precondition': 1,
                },
                'persist': True,
                'snapshot': True,
                'contains': ['preconditioning required'],
                'excludes': ['skipping precondition'],
            },
        ],
    },
    {
        'test_id': 8,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {},
        'steps': [
            SAVE,
            TRIM,
            {
                'fio_opts': {
                    'rw': 'randwrite:8',
                    'bs': 512,
                    'io_size': 512,
                },
                'persist': True,
                'success': SUCCESS_NONZERO,
                'snapshot': False,
                'contains': [INCOMPLETE],
            },
        ],
    },
    {
        'test_id': 9,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {},
        'steps': [
            SAVE,
            TRIM,
            {
                'fio_opts': {
                    'rw': 'randwrite:8',
                    'bs': 512,
                    'rate_iops': 3,
                    'iodepth': 16,
                    'time_based': 1,
                    'runtime': 1,
                    'output-format': 'json',
                },
                'persist': True,
                'snapshot': True,
                'region_direction': 'write',
            },
        ],
    },
    {
        'test_id': 10,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {},
        'steps': [
            SAVE,
            {
                'fio_opts': {
                    'rw': 'randtrim:8',
                    'bs': 512,
                    'io_size': 512,
                },
                'persist': True,
                'success': SUCCESS_NONZERO,
                'snapshot': False,
                'contains': [INCOMPLETE],
            },
        ],
    },
    {
        'test_id': 11,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {},
        'steps': [
            SAVE,
            {
                'fio_opts': {
                    'rw': 'randtrim:8',
                    'bs': 512,
                    'rate_iops': 3,
                    'iodepth': 16,
                    'time_based': 1,
                    'runtime': 1,
                    'output-format': 'json',
                },
                'persist': True,
                'snapshot': True,
                'region_direction': 'trim',
            },
        ],
    },
    {
        'test_id': 12,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {},
        'steps': [
            SAVE,
            TRIM,
            {
                'fio_opts': {
                    'ioengine': 'psync',
                },
                'persist': True,
                'limit': True,
                'success': SUCCESS_NONZERO,
                'snapshot': False,
                'contains': [INCOMPLETE],
                'excludes': ['saved state to'],
            },
        ],
    },
    {
        'test_id': 13,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {},
        'steps': [
            SAVE,
            TRIM,
            {
                'fio_opts': {
                    'ioengine': 'psync',
                    'continue_on_error': 'write',
                },
                'persist': True,
                'limit': True,
                'success': SUCCESS_NONZERO,
                'snapshot': False,
                'contains': [INCOMPLETE],
                'excludes': ['saved state to'],
            },
        ],
    },
    {
        'test_id': 14,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {},
        'steps': [
            {
                'fio_opts': {
                    'rcio_precondition': 1,
                    'output-format': 'json',
                },
                'persist': True,
                'snapshot': True,
                'write_bytes': 1048576,
            },
            {
                'fio_opts': {
                    'rcio_precondition': 1,
                    'output-format': 'json',
                },
                'persist': True,
                'snapshot': True,
                'write_bytes': 0,
            },
        ],
    },
    {
        'test_id': 15,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {},
        'steps': [
            {
                'fio_opts': {
                    'rcio_precondition': 1,
                    'output-format': 'json+',
                },
                'persist': True,
                'snapshot': True,
                'write_bytes': 1048576,
            },
            {
                'fio_opts': {
                    'rcio_precondition': 1,
                    'output-format': 'json+',
                },
                'persist': True,
                'snapshot': True,
                'write_bytes': 0,
            },
        ],
    },
    {
        'test_id': 16,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {
            'ioengine': 'psync',
        },
        'persist': True,
        'trace': 'success',
        'snapshot': True,
        'contains': [],
        'force_skip': False,
    },
    {
        'test_id': 17,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_NONZERO, timeout=30),
        'fio_opts': {
            'ioengine': 'psync',
        },
        'persist': True,
        'trace': 'failure',
        'snapshot': False,
        'contains': ['rcio: target flush failed'],
        'force_skip': False,
    },
    {
        'test_id': 18,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {},
        'steps': [
            SAVE,
            {
                'fio_opts': {
                    'verify': 'crc32c',
                    'experimental_verify': 1,
                },
                'persist': True,
                'success': SUCCESS_NONZERO,
                'unchanged': True,
                'contains': ['random RCIO writes do not support'],
            },
        ],
    },
    {
        'test_id': 19,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {},
        'steps': [
            SAVE,
            {
                'fio_opts': {
                    'verify': 'crc32c',
                    'verify_only': 1,
                },
                'persist': True,
                'success': SUCCESS_NONZERO,
                'unchanged': True,
                'contains': ['random RCIO writes do not support'],
            },
        ],
    },
    {
        'test_id': 20,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_NONZERO, timeout=30),
        'fio_opts': {
            'rw': 'write',
            'rate': '4k',
            'rcio_precondition': 1,
        },
        'persist': True,
        'signal': signal.SIGINT,
        'snapshot': False,
        'excludes': ['saved state to'],
    },
    {
        'test_id': 21,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {},
        'steps': [
            SAVE,
            {
                'fio_opts': {
                    'rw': 'write',
                    'rate': '4k',
                    'time_based': 1,
                    'runtime': 30,
                },
                'persist': True,
                'signal': signal.SIGKILL,
                'snapshot': False,
                'success': {
                    'zero_return': False,
                    'stderr_empty': True,
                    'timeout': 600,
                },
                'excludes': ['saved state to'],
            },
        ],
    },
    {
        'test_id': 22,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_NONZERO, timeout=30),
        'fio_opts': {
            'rw': 'randread',
            'percentage_random': 0,
        },
        'contains': ['requires percentage_random=100'],
    },
    {
        'test_id': 23,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_NONZERO, timeout=30),
        'fio_opts': {
            'rw': 'randwrite',
            'percentage_random': 99,
        },
        'contains': ['requires percentage_random=100'],
    },
    {
        'test_id': 24,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_NONZERO, timeout=30),
        'fio_opts': {
            'rw': 'randtrim',
            'percentage_random': 50,
        },
        'contains': ['requires percentage_random=100'],
    },
    {
        'test_id': 25,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {
            'rw': 'randwrite',
            'percentage_random': '0,100,0',
        },
    },
    {
        'test_id': 26,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {
            'rw': 'write',
            'percentage_random': '0',
        },
    },
    {
        'test_id': 27,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_NONZERO, timeout=30),
        'fio_opts': {
            'rw': 'randrw',
            'percentage_random': '99,100',
        },
        'contains': ['requires percentage_random=100'],
    },
    {
        'test_id': 28,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_NONZERO, timeout=30),
        'fio_opts': {
            'rw': 'randrw',
            'percentage_random': '100,99',
        },
        'contains': ['requires percentage_random=100'],
    },
    {
        'test_id': 29,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {
            'rw': 'randread',
            'file_service_type': 'zipf:1.2',
            'time_based': 1,
            'runtime': 1,
        },
    },
    {
        'test_id': 30,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {
            'rw': 'randtrim',
            'file_service_type': 'pareto:0.2',
            'time_based': 1,
            'runtime': 1,
        },
    },
    {
        'test_id': 31,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {
            'rw': 'randwrite',
            'file_service_type': 'normal:0.5',
            'time_based': 1,
            'runtime': 1,
        },
    },
    {
        'test_id': 32,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {
            'ioengine': 'psync',
            'io_size': '4k',
        },
        'persist': True,
        'trace': 'short',
        'snapshot': True,
        'contains': ['(1/256 valid)'],
        'force_skip': False,
    },
    {
        'test_id': 33,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {
            'offset': '4k',
            'io_size': '1020k',
            'filesize': '1M',
            'allow_file_create': 0,
            'file_append': 0,
        },
        'persist': True,
        'snapshot': True,
        'contains': ['(255/255 valid)'],
    },
    {
        'test_id': 34,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {},
        'steps': [
            SAVE,
            {
                'fio_opts': {
                    'rw': 'write',
                    'filesize': '1M',
                },
                'iolog': '{target} write 512 512\n',
                'persist': True,
                'success': SUCCESS_NONZERO,
                'unchanged': True,
                'contains': ['read_iolog is not supported with rcio_bs'],
                'excludes': ['loaded state from', 'saved state to'],
            },
        ],
    },
    {
        'test_id': 35,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {
            'rw': 'write',
            'filesize': '1M',
            'rcio_bs': 0,
        },
        'iolog': '{target} write 512 512\n',
    },
    {
        'test_id': 36,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_NONZERO, timeout=30),
        'fio_opts': {
            'rw': 'write:-8k',
            'filesize': '1025k',
            'io_size': '8k',
        },
        'persist': True,
        'snapshot': False,
        'contains': ['reverse RCIO requires region-aligned wrap geometry'],
    },
    {
        'test_id': 37,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {
            'rw': 'write:-8k',
            'filesize': '1M',
            'io_size': '8k',
        },
        'persist': True,
        'snapshot': True,
        'contains': ['(2/256 valid)'],
    },
    {
        'test_id': 38,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_NONZERO, timeout=30),
        'fio_opts': {
            'rw': 'trim:-8k',
            'filesize': '1025k',
            'io_size': '8k',
        },
        'persist': True,
        'snapshot': False,
        'contains': ['reverse RCIO requires region-aligned wrap geometry'],
    },
    {
        'test_id': 39,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {
            'rw': 'trim:-8k',
            'filesize': '1M',
            'io_size': '8k',
        },
        'persist': True,
        'snapshot': True,
        'contains': ['(0/256 valid)'],
    },
    {
        'test_id': 40,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {},
        'steps': [
            SAVE,
            {
                'jobs': GLOBAL + (
                    '[precondition]\n'
                    'rw=randwrite\n'
                    'rcio_precondition=1\n'
                    'rcio_state_file={state}\n'
                    '[trim]\n'
                    'stonewall\n'
                    'rw=randtrim\n'
                    'thread=0\n'
                ),
                'snapshot': True,
                'contains': ['loaded state from', 'skipping precondition',
                             '(0/256 valid)'],
            },
            SAVE,
            {
                'jobs': GLOBAL + (
                    '[trim]\n'
                    'rw=trim\n'
                    'thread=0\n'
                    'rcio_state_file={state}\n'
                    '[precondition]\n'
                    'stonewall\n'
                    'rw=randwrite\n'
                    'rcio_precondition=1\n'
                    'rcio_state_file={state}\n'
                ),
                'snapshot': True,
                'contains': ['loaded state from', 'skipping precondition',
                             '(0/256 valid)'],
            },
        ],
    },
    {
        'test_id': 41,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {
            'rw': 'randwrite',
            'thread': 0,
        },
    },
    {
        'test_id': 42,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {
            'rw': 'write:4k',
            'offset': 0,
            'filesize': '1M',
            'io_size': '2M',
        },
        'persist': True,
        'snapshot': True,
        'contains': [],
    },
    {
        'test_id': 43,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_NONZERO, timeout=30),
        'fio_opts': {
            'rw': 'write:4k',
            'offset': 512,
            'filesize': '1M',
            'io_size': '2M',
        },
        'persist': True,
        'snapshot': False,
        'contains': ['sequential RCIO skips require a region-aligned file offset'],
    },
    {
        'test_id': 44,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_NONZERO, timeout=30),
        'fio_opts': {
            'ioengine': 'psync',
            'unlink': 1,
        },
        'persist': True,
        'snapshot': False,
        'contains': [INCOMPLETE],
    },
    {
        'test_id': 45,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_NONZERO, timeout=30),
        'fio_opts': {},
        'jobs': GLOBAL + (
            '[precondition]\n'
            'rw=randwrite\n'
            'rcio_state_file={state}\n'
            '[reader]\n'
            'stonewall\n'
            'rw=randread\n'
            'ioengine=psync\n'
            'unlink=1\n'
        ),
        'snapshot': False,
        'contains': [INCOMPLETE],
    },
    {
        'test_id': 46,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {},
        'steps': [
            {
                'fio_opts': {
                    'ioengine': 'psync',
                    'io_size': '512k',
                    'loops': 2,
                    'unlink_each_loop': 1,
                },
                'persist': True,
                'success': SUCCESS_NONZERO,
                'snapshot': False,
                'contains': ['unlink_each_loop is not supported with RCIO '
                             'regular files'],
            },
            {
                'fio_opts': {
                    'ioengine': 'psync',
                    'io_size': '512k',
                    'loops': 2,
                    'unlink_each_loop': 1,
                    'rcio_bs': 0,
                },
                'snapshot': False,
            },
        ],
    },
    {
        'test_id': 47,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {
            'ioengine': 'psync',
            'rw': 'write',
            'io_size': '4k',
            'rcio_precondition': 1,
            'output-format': 'json',
        },
        'persist': True,
        'trace': 'short',
        'snapshot': True,
        'write_bytes': 4096,
    },
    {
        'test_id': 48,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {
            'ioengine': 'posixaio',
            'rw': 'write',
            'io_size': '4k',
            'rcio_precondition': 1,
            'output-format': 'json',
        },
        'persist': True,
        'trace': 'short',
        'snapshot': True,
        'write_bytes': 4096,
    },
    {
        'test_id': 49,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {},
        'steps': [
            SAVE,
            {
                'jobs': GLOBAL + (
                    '[load]\n'
                    'rw=randread\n'
                    'rcio_state_file={state}\n'
                    '[precondition]\n'
                    'stonewall\n'
                    'filename={target}:{target}.fresh\n'
                    'filesize=1M\n'
                    'rw=write\n'
                    'rcio_precondition=1\n'
                ),
                'success': SUCCESS_NONZERO,
                'snapshot': False,
                'contains': ['precondition job mixes loaded and fresh RCIO trackers'],
                'excludes': ['skipping precondition'],
            },
            SAVE,
            {
                'jobs': GLOBAL + (
                    '[load]\n'
                    'rw=randread\n'
                    'rcio_state_file={state}\n'
                    '[precondition]\n'
                    'stonewall\n'
                    'filename={target}.fresh:{target}\n'
                    'filesize=1M\n'
                    'rw=write\n'
                    'rcio_precondition=1\n'
                ),
                'success': SUCCESS_NONZERO,
                'snapshot': False,
                'contains': ['precondition job mixes loaded and fresh RCIO trackers'],
                'excludes': ['skipping precondition'],
            },
        ],
    },
    {
        'test_id': 50,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {},
        'contains': ['rcio_bs sets norandommap=1'],
    },
    {
        'test_id': 51,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {'norandommap': 1},
        'excludes': ['rcio_bs sets norandommap=1'],
    },
    {
        'test_id': 52,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_NONZERO, timeout=30),
        'fio_opts': {'norandommap': 0},
        'contains': ['rcio_bs requires norandommap=1'],
    },
    {
        'test_id': 53,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {'rw': 'write'},
        'contains': ['rcio_bs sets norandommap=1'],
    },
    {
        'test_id': 54,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_NONZERO, timeout=30),
        'fio_opts': {'rw': 'write', 'norandommap': 0},
        'contains': ['rcio_bs requires norandommap=1'],
    },
    {
        'test_id': 55,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {'rcio_bs': 0, 'norandommap': 0},
        'excludes': ['rcio_bs sets norandommap=1',
                     'rcio_bs requires norandommap=1'],
    },
]


for test_id, (options, error) in enumerate([
    ({'zonemode': 'zbd'}, 'not supported with zonemode'),
    ({'zonemode': 'strided', 'zonesize': '1M'},
     'not supported with zonemode'),
    ({'rw': 'trimwrite'}, 'not supported with trimwrite/randtrimwrite'),
    ({'rw': 'randtrimwrite'}, 'not supported with trimwrite/randtrimwrite'),
    ({'bs_is_seq_rand': 1}, 'bs_is_seq_rand is not supported'),
    ({'percentage_random': 99}, 'requires percentage_random=100'),
    ({'experimental_verify': 1},
     'do not support experimental_verify or verify_only'),
    ({'verify_only': 1}, 'do not support experimental_verify or verify_only'),
    ({'trim_backlog': 1}, 'not supported with trim_backlog'),
    ({'rw': 'randwrite:2', 'rw_sequencer': 'identical', 'bs': '2k'},
     'not supported with rw_sequencer=identical'),
    ({'rw': 'randrw:2', 'bs': '2k'},
     'not supported with mixed read/write directions or multiple files'),
    ({'rw': 'randwrite:2', 'bs': '2k', 'nrfiles': 2},
     'not supported with mixed read/write directions or multiple files'),
    ({'rw': 'write:512'}, 'skip must be a multiple of rcio_bs'),
    ({'rw': 'randread', 'bs': '8k'}, 'maximum read block size'),
    ({'bs': '2k'}, 'requires a fixed write block size'),
    ({'rw': 'randtrim', 'bs': '2k'}, 'requires a fixed trim block size'),
    ({'rcio_bs': '6k'}, 'must be a multiple of block alignment'),
    ({'unlink_each_loop': 1}, 'unlink_each_loop is not supported'),
    ({'bsrange': '2k-4k'}, 'requires a fixed write block size'),
    ({'nrfiles': 2, 'rcio_state_file': '/unused-rcio-state'},
     'rcio_state_file is not supported with multiple files'),
    ({'rw': 'randtrim', 'num_range': 2},
     'rcio_bs does not support multi-range trim'),
], 56):
    TEST_LIST.append({
        'test_id': test_id,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_NONZERO, timeout=30),
        'fio_opts': options,
        'early_reject': True,
        'contains': [error],
    })

TEST_LIST.append({
    'test_id': 77,
    'test_class': FioRcioTest,
    'success': dict(SUCCESS_NONZERO, timeout=30),
    'fio_opts': {},
    'early_reject': True,
    'iolog': '{target} write 0 4096\n',
    'contains': ['read_iolog is not supported with rcio_bs'],
})

TEST_LIST += [
    {
        'test_id': 78,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {},
        'steps': [
            {
                'jobs': GLOBAL.replace('thread=1', 'thread=0') + (
                    'rcio_state_file={state}\n'
                    '[precondition]\n'
                    'rw=randwrite\n'
                    'io_size=512k\n'
                    '[read]\n'
                    'stonewall\n'
                    'rw=randread\n'
                    '[trim]\n'
                    'stonewall\n'
                    'rw=randtrim\n'
                ),
                'snapshot': True,
                'contains': ['(0/256 valid)'],
            },
            dict(SAVE, fio_opts={'thread': 0}),
            {
                'jobs': GLOBAL.replace('thread=1', 'thread=0') + (
                    'rcio_state_file={state}\n'
                    '[precondition]\n'
                    'rw=randwrite\n'
                    'rcio_precondition=1\n'
                    '[read]\n'
                    'stonewall\n'
                    'rw=randread\n'
                ),
                'snapshot': True,
                'contains': ['skipping precondition', '(256/256 valid)'],
            },
        ],
    },
    {
        'test_id': 79,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {},
        'steps': [
            {
                'fio_opts': {'thread': 0, 'numjobs': 4, 'io_size': '256k'},
                'persist': True,
                'snapshot': True,
                'contains': ['(256/256 valid)'],
            },
            {
                'fio_opts': {'thread': 0, 'numjobs': 4, 'io_size': '256k',
                             'rw': 'randtrim'},
                'persist': True,
                'snapshot': True,
                'contains': ['(0/256 valid)'],
            },
        ],
    },
    {
        'test_id': 80,
        'test_class': FioRcioTest,
        'success': dict(SUCCESS_DEFAULT, timeout=30),
        'fio_opts': {'output-format': 'json'},
        'jobs': GLOBAL.replace('thread=1', 'thread=0').replace(
            'ioengine=null', 'ioengine=psync') + (
                '[precondition]\n'
                'rw=randwrite\n'
                'io_size=512k\n'
                '[read]\n'
                'stonewall\n'
                'rw=randread\n'
                '[trim]\n'
                'stonewall\n'
                'rw=randtrim\n'
                'ioengine=null\n'
            ),
        'job_io_bytes': {
            'precondition': {'write': 512 * 1024},
            'read': {'read': 1024 * 1024},
            'trim': {'trim': 512 * 1024},
        },
    },
]


def parse_args():
    """Parse command-line arguments like the other fio feature test suites."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-f', '--fio',
                        help='path to fio executable (default: fio in PATH)')
    parser.add_argument('-s', '--skip', nargs='+', type=int,
                        help='list of test(s) to skip')
    parser.add_argument('-a', '--artifact-root', help='artifact root directory')
    parser.add_argument('-o', '--run-only', nargs='+', type=int,
                        help='list of test(s) to run, skipping all others')
    return parser.parse_args()


def main():
    """Run RCIO tests with fio's standard test runner."""
    args = parse_args()
    fio_path = str(Path(args.fio).absolute()) if args.fio else 'fio'
    artifact_root = args.artifact_root if args.artifact_root else \
            f"rcio-test-{time.strftime('%Y%m%d-%H%M%S')}"
    Path(artifact_root).mkdir(parents=True, exist_ok=True)
    print(f"Artifact directory is {str(Path(artifact_root).absolute())}")
    test_env = {
        'fio_path': fio_path,
        'fio_root': str(Path(__file__).absolute().parent.parent),
        'artifact_root': artifact_root,
        'basename': 'rcio',
    }
    if not shutil.which('strace'):
        for config in TEST_LIST:
            if config.get('trace'):
                config['force_skip'] = True
                print(f"Test {config['test_id']} requires strace; skipping")
    _, failed, _ = run_fio_tests(TEST_LIST, test_env, args)
    sys.exit(failed)


if __name__ == '__main__':
    main()
