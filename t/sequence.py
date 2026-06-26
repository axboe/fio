#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

"""
# sequence.py
#
# Test random_distribution=sequence and random_sequence_stride.
#
"""

import os
import sys
import time
import argparse
from pathlib import Path
from fiotestlib import FioJobCmdTest, run_fio_tests


class SequenceTest(FioJobCmdTest):
    """Test random_distribution=sequence."""

    def setup(self, parameters):
        fio_args = [
                    "--name=sequence",
                    "--rw=randread",
                    f"--write_iops_log={self.filenames['iopslog']}",
                    f"--output={self.filenames['output']}",
                    f"--random_distribution=sequence:{self.fio_opts['random_sequence']}",
                    f"--bs={self.fio_opts['bs']}",
                    f"--size={self.fio_opts['size']}",
                    f"--io_size={self.fio_opts['io_size']}",
                    "--log_offset=1",
                    "--ioengine=null",
                   ]
        if 'random_sequence_stride' in self.fio_opts:
            fio_args.append(f"--random_sequence_stride={self.fio_opts['random_sequence_stride']}")

        super().setup(fio_args)

    def check_result(self):
        super().check_result()
        if not self.passed:
            return

        seq_str = self.fio_opts['random_sequence']
        expected_seq = [int(x) for x in seq_str.split(',')]
        seq_len = len(expected_seq)
        bs = self.fio_opts['bs']
        stride = self.fio_opts.get('random_sequence_stride', 0)

        lines = self.iops_log_lines.split('\n')
        io_count = 0

        for line in lines:
            if len(line) == 0:
                continue

            tokens = line.split(',')
            offset = int(tokens[4])

            idx = io_count % seq_len
            if stride:
                group_idx = io_count // seq_len
                expected_block = group_idx * seq_len + expected_seq[idx]
            else:
                expected_block = expected_seq[idx]

            expected_offset = expected_block * bs

            if offset != expected_offset:
                print(f"IO {io_count}: Expected offset {expected_offset} (block {expected_block}), got {offset}")
                self.passed = False
                return

            io_count += 1


TEST_LIST = [
    {
        "test_id": 1,
        "fio_opts": {
            "random_sequence": "2,0,1",
            "bs": 4096,
            "size": "48k",
            "io_size": "24k",
            "random_sequence_stride": 0,
            },
        "test_class": SequenceTest,
    },
    {
        "test_id": 2,
        "fio_opts": {
            "random_sequence": "2,0,1",
            "bs": 4096,
            "size": "48k",
            "io_size": "24k",
            "random_sequence_stride": 1,
            },
        "test_class": SequenceTest,
    },
]


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--fio', help='path to file executable (e.g., ./fio)')
    parser.add_argument('-a', '--artifact-root', help='artifact root directory')
    parser.add_argument('-s', '--skip', nargs='+', type=int,
                        help='list of test(s) to skip')
    parser.add_argument('-o', '--run-only', nargs='+', type=int,
                        help='list of test(s) to run, skipping all others')
    return parser.parse_args()


def main():
    """Run sequence tests."""
    args = parse_args()

    if args.fio:
        fio_path = str(Path(args.fio).absolute())
    else:
        fio_path = os.path.join(os.path.dirname(__file__), '../fio')
    print(f"fio path is {fio_path}")

    artifact_root = args.artifact_root if args.artifact_root else \
        f"sequence-test-{time.strftime('%Y%m%d-%H%M%S')}"
    os.mkdir(artifact_root)
    print(f"Artifact directory is {artifact_root}")

    test_env = {
              'fio_path': fio_path,
              'fio_root': str(Path(__file__).absolute().parent.parent),
              'artifact_root': artifact_root,
              'basename': 'sequence',
              }

    _, failed, _ = run_fio_tests(TEST_LIST, test_env, args)
    sys.exit(failed)


if __name__ == '__main__':
    main()
