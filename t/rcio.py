#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2026 Sandisk Corporation or its affiliates.

"""Test core RCIO region transitions and configuration validation."""

import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import time

from fiotestcommon import SUCCESS_DEFAULT, SUCCESS_NONZERO
from fiotestlib import FioJobCmdTest, run_fio_tests


GLOBAL = """\
[global]
ioengine=null
thread=1
filename={target}
size=32k
bs=4k
rcio_size=4k
rw=randwrite
"""

TRANSITIONS = [
    ('empty', 'read', 0),
    ('write', 'write', 4),
    ('read', 'read', 8),
    ('fill', 'write', 4),
    ('trim', 'trim', 4),
    ('rewrite', 'write', 4),
]


class FioRcioTest(FioJobCmdTest):
    """Check RCIO workload results and selected region offsets."""

    def setup(self, parameters):
        self.config = parameters
        directory = Path(self.paths['test_dir']).absolute()
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / 'target'
        with target.open('wb') as file:
            file.truncate(32768)
        if parameters.get('alias'):
            os.link(target, directory / 'alias')
        jobs = parameters.get('jobs', '[rcio]\n' + ''.join(
            f'{key}={value}\n' for key, value in self.fio_opts.items()))
        jobfile = directory / 'jobs.fio'
        jobfile.write_text((GLOBAL + jobs).format(
            target=target, directory=directory), encoding='utf-8')
        super().setup(['--output-format=json',
                       f"--output={self.filenames['output']}", str(jobfile)])

    def check_result(self):
        super().check_result()
        if not self.passed:
            return
        output = Path(self.filenames['output']).read_text(encoding='utf-8')
        if self.config.get('error'):
            stderr = Path(self.filenames['stderr']).read_text(encoding='utf-8')
            if self.config['error'] not in output + stderr:
                self.passed = False
                self.failure_reason += f" missing error {self.config['error']!r},"
            return
        jobs = {job['jobname']: job for job in json.loads(output)['jobs']}
        for name, direction, count in self.config['bytes']:
            if jobs[name][direction]['io_bytes'] != count:
                self.passed = False
                self.failure_reason += f' unexpected {name} {direction} bytes,'
        if not self.config.get('transitions'):
            return

        def offsets(name):
            lines = (Path(self.paths['test_dir']) / f'{name}.log').read_text(
                encoding='utf-8').splitlines()
            result = []
            for line in lines:
                parts = line.rsplit(' ', 3)
                if (len(parts) == 4 and parts[-3] in ('read', 'write', 'trim')
                        and int(parts[-1]) == 4096):
                    result.append(int(parts[-2]))
            return result

        written, read, filled, trimmed, rewritten = [
            offsets(name) for name in ('write', 'read', 'fill', 'trim', 'rewrite')]
        if (len(written) != 4 or len(set(written)) != 4 or
                len(read) != 8 or not set(read).issubset(written) or
                len(filled) != 4 or
                set(written + filled) != set(range(0, 32768, 4096)) or
                len(trimmed) != 4 or len(set(trimmed)) != 4 or
                len(rewritten) != 4 or set(rewritten) != set(trimmed)):
            self.passed = False
            self.failure_reason += ' incorrect region transitions,'


TEST_LIST = [
    {
        'test_id': 1,
        'transitions': True,
        'jobs': ''.join(
            f'[{name}]\nstonewall\nrw=rand{direction}\n'
            f'io_size={max(1, count) * 4096}\n'
            f'write_iolog={{directory}}/{name}.log\n'
            for name, direction, count in TRANSITIONS),
        'bytes': [(name, direction, count * 4096)
                  for name, direction, count in TRANSITIONS],
    },
    {
        'test_id': 2,
        'error': 'RCIO jobs must use one target and range',
        'jobs': '[first]\n[second]\noffset=4k\n',
    },
    {
        'test_id': 13,
        'alias': True,
        'error': 'non-RCIO job shares the RCIO target',
        'jobs': '[tracked]\n[untracked]\n'
                'filename={directory}/alias\nrcio_size=0\n',
    },
    {
        'test_id': 15,
        'fio_opts': {'rcio_size': 0, 'thread': 0,
                     'random_distribution': 'zipf'},
        'bytes': [('rcio', 'write', 32768)],
    },
]

for test_id, options, error in [
    (5, {'thread': 0}, 'requires thread=1'),
    (6, {'norandommap': 0}, 'requires norandommap=1'),
    (7, {'bs': '2k'}, 'requires fixed full-region blocks'),
    (10, {'rw': 'write'}, 'requires random I/O'),
    (16, {'offset': '2k', 'size': '28k'}, 'must contain whole, aligned regions'),
]:
    TEST_LIST.append({'test_id': test_id, 'fio_opts': options, 'error': error})

for config in TEST_LIST:
    config['test_class'] = FioRcioTest
    config.setdefault('fio_opts', {})
    config['success'] = dict(
        SUCCESS_NONZERO if config.get('error') else SUCCESS_DEFAULT, timeout=30)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-f', '--fio', help='path to fio executable')
    parser.add_argument('-a', '--artifact-root', help='artifact root directory')
    parser.add_argument('-s', '--skip', nargs='+', type=int)
    parser.add_argument('-o', '--run-only', nargs='+', type=int)
    args = parser.parse_args()

    fio_path = str(Path(args.fio).absolute()) if args.fio else shutil.which('fio')
    if not fio_path:
        parser.error('fio executable not found in PATH')
    artifact_root = args.artifact_root or f"rcio-test-{time.strftime('%Y%m%d-%H%M%S')}"
    os.mkdir(artifact_root)
    print(f"Artifact directory is {artifact_root}")
    test_env = {
        'fio_path': fio_path,
        'fio_root': str(Path(__file__).absolute().parent.parent),
        'artifact_root': artifact_root,
        'basename': 'rcio',
    }
    _, failed, _ = run_fio_tests(TEST_LIST, test_env, args)
    sys.exit(failed)


if __name__ == '__main__':
    main()
