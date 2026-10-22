#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check basic style on changed lines, with optional clang-format checks."""

import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


HUNK = re.compile(rb'^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@', re.M)
EXCLUDED = ('.git', 'build', 'mock-tests/build')
SOURCE_SUFFIXES = ('.c', '.h')
TEXT_SUFFIXES = SOURCE_SUFFIXES + ('.md', '.rst', '.fio', '.py', '.sh')
UPSTREAM_REFS = ('origin/master', 'master')
SPACE_INDENT = re.compile(rb'^ {8,}\S')
SPACE_BEFORE_TAB = re.compile(rb'^\t* +\t')


def git(repo, *arguments):
    return subprocess.check_output(['git', '-C', str(repo), *arguments],
                                   stderr=subprocess.PIPE)


def supported(name):
    path = Path(name)
    if any(name == prefix or name.startswith(prefix + '/')
           for prefix in EXCLUDED):
        return False
    return path.suffix in TEXT_SUFFIXES or path.name == 'Makefile'


def default_base(repo):
    for ref in UPSTREAM_REFS:
        try:
            return git(repo, 'merge-base', 'HEAD', ref).decode().strip(), ref
        except subprocess.CalledProcessError:
            continue
    raise RuntimeError('cannot find {}; use --base <commit>'.format(
        ' or '.join(UPSTREAM_REFS)))


def changed_lines(patch):
    lines = set()
    for match in HUNK.finditer(patch):
        start = int(match.group(1))
        count = int(match.group(2)) if match.group(2) else 1
        lines.update(range(start, start + count))
    return lines


def base_content(repo, base, name):
    try:
        return git(repo, 'show', '{}:{}'.format(base, name))
    except subprocess.CalledProcessError:
        return None  # new file


def check_content(name, content, changed, old_content):
    findings = []
    source = Path(name).suffix in SOURCE_SUFFIXES
    lines = content.split(b'\n')
    if content.endswith(b'\n'):
        lines.pop()
    for number in sorted(changed):
        if not 1 <= number <= len(lines):
            continue
        line = lines[number - 1]
        if line != line.rstrip(b' \t\r\v\f'):
            findings.append(('ERROR', number, 'trailing whitespace'))
        if not source:
            continue
        if len(line.decode('utf-8', errors='replace').expandtabs(8)) > 80:
            findings.append(('WARNING', number, 'line exceeds 80 columns'))
        if line.lstrip().startswith((b'*', b'/*', b'//')):
            continue
        if SPACE_INDENT.match(line):
            findings.append(('WARNING', number,
                             'code indent should use tabs where possible'))
        elif SPACE_BEFORE_TAB.match(line):
            findings.append(('WARNING', number, 'space before tab in indent'))
    # Only report a missing final newline that this change introduced.
    if (content and not content.endswith(b'\n') and
            (not old_content or old_content.endswith(b'\n'))):
        findings.append(('ERROR', len(lines),
                         'missing newline at end of file'))
    return findings


def check_format(repo, base, staged, names, binary):
    if not names:
        print('OK: No changed C/header lines to format')
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
    parser.add_argument('-v', '--verbose', action='store_true',
                        default=os.environ.get('VERBOSE', '0') == '1',
                        help='show all findings instead of five per file')
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
    diff = ['diff', '--no-ext-diff', '--no-textconv', '--no-renames']
    if args.staged:
        diff.append('--cached')
    raw_names = git(repo, *diff, '--name-only', '-z', '--diff-filter=ACMT',
                    base, '--')
    names = [os.fsdecode(name) for name in raw_names.split(b'\0') if name]
    names = [name for name in names if supported(name)]
    print('FIO Style Checker ({}, base {} = {})'.format(
        'staged changes' if args.staged else 'tracked changes', label,
        base[:12]))
    errors = 0
    warnings = 0
    checked = 0
    format_names = []
    for name in names:
        if args.staged:
            mode = git(repo, 'ls-files', '--stage', '-z', '--',
                       name).split(b' ', 1)[0]
            if mode not in (b'100644', b'100755'):
                continue
            content = git(repo, 'show', ':' + name)
        else:
            path = repo / name
            if path.is_symlink() or not path.is_file():
                continue
            content = path.read_bytes()
        if b'\0' in content:
            continue
        patch = git(repo, *diff, '--unified=0', '--no-color', base, '--', name)
        changed = changed_lines(patch)
        findings = check_content(name, content, changed,
                                 base_content(repo, base, name))
        errors += sum(level == 'ERROR' for level, _, _ in findings)
        warnings += sum(level == 'WARNING' for level, _, _ in findings)
        for level, number, message in (findings if args.verbose
                                       else findings[:5]):
            print('{}: {}:{}: {}'.format(level, name, number, message))
        if not args.verbose and len(findings) > 5:
            print('... {} more findings in {}; use VERBOSE=1'.format(
                len(findings) - 5, name))
        if changed and Path(name).suffix in SOURCE_SUFFIXES:
            format_names.append(name)
        checked += 1
    if args.format:
        warnings += check_format(repo, base, args.staged, format_names,
                                 args.clang_format)
    else:
        print('SKIP: clang-format check (enable with --format or '
              'make style FORMAT=1)')
    print('{}: {} file(s), {} error(s), {} warning(s)'.format(
        'FAIL' if errors else 'OK', checked, errors, warnings))
    if not checked:
        print('No changed files found; use --base <commit> to check '
              'a different range.')
    print('Untracked files are excluded; git add new files to check them.')
    return 1 if errors else 0


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
