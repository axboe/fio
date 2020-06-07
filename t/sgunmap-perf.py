#!/usr/bin/env python3
#
# sgunmap-test.py
#
# Basic performance testing using fio's sg ioengine
#
# USAGE
# sgunmap-perf.py char-device block-device fio-executable
#
# EXAMPLE
# t/sgunmap-perf.py /dev/sg1 /dev/sdb ./fio
#
# REQUIREMENTS
# Python 2.6+
#
#

from __future__ import absolute_import
from __future__ import print_function
import sys
import json
import argparse
import subprocess
from six.moves import range


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('cdev',
                        help='character device target (e.g., /dev/sg0)')
    parser.add_argument('bdev',
                        help='block device target (e.g., /dev/sda)')
    parser.add_argument('fioc',
                        help='path to candidate fio executable (e.g., ./fio)')
    parser.add_argument('fior',
                        help='path to reference fio executable (e.g., ./fio)')
    args = parser.parse_args()

    return args


def fulldevice(fio, dev, ioengine='psync', rw='trim', bs='1M'):
    parameters = ["--name=test",
                  "--output-format=json",
                  "--random_generator=lfsr",
                  "--bs={0}".format(bs),
                  "--rw={0}".format(rw),
                  "--ioengine={0}".format(ioengine),
                  "--filename={0}".format(dev)]

    output = subprocess.check_output([fio] + parameters)
    jsondata = json.loads(output)
    jobdata = jsondata['jobs'][0]
    return jobdata


def runtest(fio, dev, rw, qd, batch, bs='512', runtime='30s'):
    parameters = ["--name=test",
                  "--random_generator=tausworthe64",
                  "--time_based",
                  "--runtime={0}".format(runtime),
                  "--output-format=json",
                  "--ioengine=sg",
                  "--blocksize={0}".format(bs),
                  "--rw={0}".format(rw),
                  "--filename={0}".format(dev),
                  "--iodepth={0}".format(qd),
                  "--iodepth_batch={0}".format(batch)]

    output = subprocess.check_output([fio] + parameters)
    jsondata = json.loads(output)
    jobdata = jsondata['jobs'][0]
#    print(parameters)

    return jobdata


def runtests(fio, dev, qd, batch, rw, bs='512', trials=5):
    iops = []
    for x in range(trials):
        jd = runtest(fio, dev, rw, qd, batch, bs=bs)
        total = jd['read']['iops'] + jd['write']['iops'] + jd['trim']['iops']
#       print(total)
        iops.extend([total])
    return iops, (sum(iops) / trials)

if __name__ == '__main__':
    args = parse_args()

    print("Trimming full device {0}".format(args.cdev))
    fulldevice(args.fior, args.cdev, ioengine='sg')

    print("Running rand read tests on {0}"
        " with fio candidate build {1}".format(args.cdev, args.fioc))
    randread, rrmean = runtests(args.fioc, args.cdev, 16, 1, 'randread',
        trials=5)
    print("IOPS mean {0}, trials {1}".format(rrmean, randread))

    print("Running rand read tests on {0}"
        " with fio reference build {1}".format(args.cdev, args.fior))
    randread, rrmean = runtests(args.fior, args.cdev, 16, 1, 'randread',
        trials=5)
    print("IOPS mean {0}, trials {1}".format(rrmean, randread))

    print("Running rand write tests on {0}"
        " with fio candidate build {1}".format(args.cdev, args.fioc))
    randwrite, rwmean = runtests(args.fioc, args.cdev, 16, 1, 'randwrite',
        trials=5)
    print("IOPS mean {0}, trials {1}".format(rwmean, randwrite))

    print("Running rand write tests on {0}"
        " with fio reference build {1}".format(args.cdev, args.fior))
    randwrite, rwmean = runtests(args.fior, args.cdev, 16, 1, 'randwrite',
        trials=5)
    print("IOPS mean {0}, trials {1}".format(rwmean, randwrite))
