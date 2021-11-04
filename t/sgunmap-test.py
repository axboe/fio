#!/usr/bin/env python3
# Note: this script is python2 and python 3 compatible.
#
# sgunmap-test.py
#
# Limited functionality test for trim workloads using fio's sg ioengine
# This checks only the three sets of reported iodepths
#
# !!!WARNING!!!
# This script carries out destructive tests. Be sure that
# there is no data you want to keep on the supplied devices.
#
# USAGE
# sgunmap-test.py char-device block-device fio-executable
#
# EXAMPLE
# t/sgunmap-test.py /dev/sg1 /dev/sdb ./fio
#
# REQUIREMENTS
# Python 2.6+
#
# TEST MATRIX
# For both char-dev and block-dev these are the expected
# submit/complete IO depths
#
#                       blockdev                chardev
#                       iodepth                 iodepth
# R QD1                 sub/comp: 1-4=100%      sub/comp: 1-4=100%
# W QD1                 sub/comp: 1-4=100%      sub/comp: 1-4=100%
# T QD1                 sub/comp: 1-4=100%      sub/comp: 1-4=100%
#
# R QD16, batch8        sub/comp: 1-4=100%      sub/comp: 1-4=100%
# W QD16, batch8        sub/comp: 1-4=100%      sub/comp: 1-4=100%
# T QD16, batch8        sub/comp: 1-4=100%      sub/comp: 5-8=100%
#
# R QD16, batch16       sub/comp: 1-4=100%      sub/comp: 1-4=100%
# W QD16, batch16       sub/comp: 1-4=100%      sub/comp: 1-4=100%
# T QD16, batch16       sub/comp: 1-4=100%      sub/comp: 9-16=100%
#

from __future__ import absolute_import
from __future__ import print_function
import sys
import json
import argparse
import traceback
import subprocess


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('chardev',
                        help='character device target (e.g., /dev/sg0)')
    parser.add_argument('blockdev',
                        help='block device target (e.g., /dev/sda)')
    parser.add_argument('fio',
                        help='path to fio executable (e.g., ./fio)')
    args = parser.parse_args()

    return args

#
# With block devices,
#     iodepth = 1 always
#     submit = complete = 1-4 always
# With character devices,
# RW
#     iodepth = qd
#     submit = 1-4
#     complete = 1-4 except for the IOs in flight
#                when the job is ending
# T
#     iodepth = qd
#     submit = qdbatch
#     complete = qdbatch except for the IOs in flight
#                when the job is ending
#


def check(jsondata, parameters, block, qd, qdbatch, rw):
    iodepth = jsondata['iodepth_level']
    submit = jsondata['iodepth_submit']
    complete = jsondata['iodepth_complete']

    try:
        if block:
            assert iodepth['1'] == 100.0
            assert submit['4'] == 100.0
            assert complete['4'] == 100.0
        elif 'read' in rw or 'write' in rw:
            assert iodepth[str(qd)] > 99.9
            assert submit['4'] == 100.0
            assert complete['4'] > 99.9
        else:
            if qdbatch <= 4:
                batchkey = '4'
            elif qdbatch > 64:
                batchkey = '>=64'
            else:
                batchkey = str(qdbatch)
            if qd >= 64:
                qdkey = ">=64"
            else:
                qdkey = str(qd)
            assert iodepth[qdkey] > 99
            assert submit[batchkey] == 100.0
            assert complete[batchkey] > 99
    except AssertionError:
        print("Assertion failed")
        traceback.print_exc()
        print(jsondata)
        return

    print("**********passed*********")


def runalltests(args, qd, batch):
    block = False
    for dev in [args.chardev, args.blockdev]:
        for rw in ["randread", "randwrite", "randtrim"]:
            parameters = ["--name=test",
                           "--time_based",
                           "--runtime=30s",
                           "--output-format=json",
                           "--ioengine=sg",
                           "--rw={0}".format(rw),
                           "--filename={0}".format(dev),
                           "--iodepth={0}".format(qd),
                           "--iodepth_batch={0}".format(batch)]

            print(parameters)
            output = subprocess.check_output([args.fio] + parameters)
            jsondata = json.loads(output)
            jobdata = jsondata['jobs'][0]
            check(jobdata, parameters, block, qd, batch, rw)
        block = True


def runcdevtrimtest(args, qd, batch):
    parameters = ["--name=test",
                   "--time_based",
                   "--runtime=30s",
                   "--output-format=json",
                   "--ioengine=sg",
                   "--rw=randtrim",
                   "--filename={0}".format(args.chardev),
                   "--iodepth={0}".format(qd),
                   "--iodepth_batch={0}".format(batch)]

    print(parameters)
    output = subprocess.check_output([args.fio] + parameters)
    jsondata = json.loads(output)
    jobdata = jsondata['jobs'][0]
    check(jobdata, parameters, False, qd, batch, "randtrim")


if __name__ == '__main__':
    args = parse_args()

    runcdevtrimtest(args, 32, 2)
    runcdevtrimtest(args, 32, 4)
    runcdevtrimtest(args, 32, 8)
    runcdevtrimtest(args, 64, 4)
    runcdevtrimtest(args, 64, 8)
    runcdevtrimtest(args, 64, 16)
    runcdevtrimtest(args, 128, 8)
    runcdevtrimtest(args, 128, 16)
    runcdevtrimtest(args, 128, 32)

    runalltests(args, 1, 1)
    runalltests(args, 16, 2)
    runalltests(args, 16, 16)
