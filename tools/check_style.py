#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check changes with git diff --check and optional clang-format."""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys

# include coverage to c and header files
SOURCE_PATHS = (':(top,glob)**/*.c', ':(top,glob)**/*.h')
UPSTREAM_REFS = ('origin/master', 'master')


def git(repo, *arguments):
    return subprocess.check_output(['git', '-C', str(repo), *arguments],
                                   stderr=subprocess.PIPE)


def default_base(repo):
    for ref in UPSTREAM_REFS:
        try:
            return git(repo, 'merge-base', 'HEAD', ref).decode().strip(), ref
        except subprocess.CalledProcessError:
            continue
    raise RuntimeError('cannot find {}; use --base <commit>'.format(
        ' or '.join(UPSTREAM_REFS)))


def check_format(repo, base, staged, names, binary):
    if not names:
        print('OK: No changed lines to format')
        return 0
    if not (repo / '.clang-format').is_file():
        raise RuntimeError('No .clang-format found in repository root')
    if shutil.which(binary) is None:
        raise RuntimeError('clang-format not found: {} (install it or set '
                           'CLANG_FORMAT)'.format(binary))
    command = ['git', '-C', str(repo), '-c', 'color.ui=false',
               'clang-format', '--diff',
               '--binary', binary, '--style=file', '--extensions=c,h']
    if staged:
        command.append('--staged')
    command.extend([base, '--', *names])
    result = subprocess.run(command, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    output = result.stdout.decode('utf-8', errors='replace')
    if result.stderr:
        print(result.stderr.decode('utf-8', errors='replace'),
              end='', file=sys.stderr)
    has_diff = any(line.startswith('diff --git ')
                   for line in output.splitlines())
    if has_diff:
        print('WARNING: clang-format suggests changes on changed lines:')
        print(output, end='' if output.endswith('\n') else '\n')
        return 1
    if result.returncode:
        raise RuntimeError('git clang-format failed; install git-clang-format '
                           'and check the diagnostics above.\n' + output)
    print('OK: clang-format check passed')
    return 0


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path,
                        default=Path(__file__).resolve().parents[1],
                        help='repository directory (default: fio source tree)')
    parser.add_argument('--base',
                        help='base commit (default: merge-base of HEAD and '
                             'origin/master, or master)')
    parser.add_argument('--staged', action='store_true',
                        help='check index content only, ignoring unstaged '
                             'edits')
    parser.add_argument('--format', action='store_true',
                        help='also check changed C/header lines with '
                             'clang-format')
    parser.add_argument('--clang-format',
                        default=os.environ.get('CLANG_FORMAT', 'clang-format'),
                        help='clang-format executable (or set CLANG_FORMAT)')
    return parser.parse_args()


def check(args):
    repo = Path(os.fsdecode(git(args.repo, 'rev-parse', '--show-toplevel'))
                .rstrip('\n'))
    if args.base:
        label = args.base
        base = git(repo, 'rev-parse', '--verify', '--end-of-options',
                   args.base + '^{commit}').decode().strip()
    else:
        base, ref = default_base(repo)
        label = 'merge-base with ' + ref
    diff = ['diff', '--no-ext-diff', '--no-textconv', '--no-renames',
            '--no-color']
    if args.staged:
        diff.append('--cached')
    raw_names = git(repo, *diff, '--name-only', '-z', '--diff-filter=ACMT',
                    base, '--', *SOURCE_PATHS)
    names = [os.fsdecode(name) for name in raw_names.split(b'\0') if name]
    print('FIO Style Checker ({}, base {} = {})'.format(
        'staged changes' if args.staged else 'tracked changes', label,
        base[:12]))
    result = subprocess.run(['git', '-C', str(repo), *diff, '--check',
                             base, '--', *SOURCE_PATHS],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode not in (0, 2):
        result.check_returncode()
    if result.stdout:
        print(result.stdout.decode('utf-8', errors='replace'), end='')
    if result.stderr:
        print(result.stderr.decode('utf-8', errors='replace'),
              end='', file=sys.stderr)
    failed = result.returncode != 0
    print('{}: git diff --check'.format(
        'FAIL' if failed else 'PASS'))
    warnings = 0
    if args.format:
        warnings = check_format(repo, base, args.staged, names,
                                args.clang_format)
    else:
        print('SKIP: clang-format check (enable with --format or '
              'make style FORMAT=1)')
    print('{}: {} file(s), {} clang-format warning(s)'.format(
        'FAIL' if failed else 'OK', len(names), warnings))
    if not names:
        print('No changed files found; use --base <commit> to check '
              'a different range.')
    print('Untracked files are excluded; git add new files to check them.')
    return 1 if failed else 0


def main():
    args = parse_args()
    try:
        return check(args)
    except subprocess.CalledProcessError as error:
        print('ERROR: {}'.format(error.stderr.decode('utf-8', errors='replace')
                                 .strip()), file=sys.stderr)
    except (OSError, RuntimeError) as error:
        print('ERROR: {}'.format(error), file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main())
