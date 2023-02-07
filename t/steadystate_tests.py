#!/usr/bin/env python3
#
# steadystate_tests.py
#
# Test option parsing and functionality for fio's steady state detection feature.
#
# steadystate_tests.py --read file-for-read-testing --write file-for-write-testing ./fio
#
# REQUIREMENTS
# Python 2.6+
# SciPy
#
# KNOWN ISSUES
# only option parsing and read tests are carried out
# On Windows this script works under Cygwin but not from cmd.exe
# On Windows I encounter frequent fio problems generating JSON output (nothing to decode)
# min runtime:
# if ss attained: min runtime = ss_dur + ss_ramp
# if not attained: runtime = timeout

from __future__ import absolute_import
from __future__ import print_function
import os
import sys
import json
import pprint
import argparse
import subprocess
from scipy import stats

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('fio', help='path to fio executable')
    args = parser.parse_args()

    return args


def check(data, iops, slope, pct, limit, dur, criterion):
    measurement = 'iops' if iops else 'bw'
    data = data[measurement]
    mean = sum(data) / len(data)
    if slope:
        x = list(range(len(data)))
        m, intercept, r_value, p_value, std_err = stats.linregress(x,data)
        m = abs(m)
        if pct:
            target = (m / mean * 100) if mean != 0 else 0
            criterion = criterion[:-1]
        else:
            target = m
    else:
        maxdev = 0
        for x in data:
            maxdev = max(abs(mean-x), maxdev)
        if pct:
            target = maxdev / mean * 100
            criterion = criterion[:-1]
        else:
            target = maxdev

    criterion = float(criterion)
    if criterion == 0.0:
        objsame = False
    else:
        objsame = abs(target - criterion) / criterion < 0.005
    return (objsame, target < limit, mean, target)


if __name__ == '__main__':
    args = parse_args()

    pp = pprint.PrettyPrinter(indent=4)

    passed = 0
    failed = 0

#
# test option parsing
#
    parsing = [ { 'args': ["--parse-only", "--debug=parse", "--ss_dur=10s", "--ss=iops:10", "--ss_ramp=5"],
                  'output': "set steady state IOPS threshold to 10.000000" },
                { 'args': ["--parse-only", "--debug=parse", "--ss_dur=10s", "--ss=iops:10%", "--ss_ramp=5"],
                  'output': "set steady state threshold to 10.000000%" },
                { 'args': ["--parse-only", "--debug=parse", "--ss_dur=10s", "--ss=iops:.1%", "--ss_ramp=5"],
                  'output': "set steady state threshold to 0.100000%" },
                { 'args': ["--parse-only", "--debug=parse", "--ss_dur=10s", "--ss=bw:10%", "--ss_ramp=5"],
                  'output': "set steady state threshold to 10.000000%" },
                { 'args': ["--parse-only", "--debug=parse", "--ss_dur=10s", "--ss=bw:.1%", "--ss_ramp=5"],
                  'output': "set steady state threshold to 0.100000%" },
                { 'args': ["--parse-only", "--debug=parse", "--ss_dur=10s", "--ss=bw:12", "--ss_ramp=5"],
                  'output': "set steady state BW threshold to 12" },
              ]
    for test in parsing:
        output = subprocess.check_output([args.fio] + test['args'])
        if test['output'] in output.decode():
            print("PASSED '{0}' found with arguments {1}".format(test['output'], test['args']))
            passed = passed + 1
        else:
            print("FAILED '{0}' NOT found with arguments {1}".format(test['output'], test['args']))
            failed = failed + 1

#
# test some read workloads
#
# if ss active and attained,
#   check that runtime is less than job time
#   check criteria
#   how to check ramp time?
#
# if ss inactive
#   check that runtime is what was specified
#
    reads = [ {'s': True, 'timeout': 100, 'numjobs': 1, 'ss_dur': 5, 'ss_ramp': 3, 'iops': True, 'slope': True, 'ss_limit': 0.1, 'pct': True},
              {'s': False, 'timeout': 20, 'numjobs': 2},
              {'s': True, 'timeout': 100, 'numjobs': 3, 'ss_dur': 10, 'ss_ramp': 5, 'iops': False, 'slope': True, 'ss_limit': 0.1, 'pct': True},
              {'s': True, 'timeout': 10, 'numjobs': 3, 'ss_dur': 10, 'ss_ramp': 500, 'iops': False, 'slope': True, 'ss_limit': 0.1, 'pct': True},
              {'s': True, 'timeout': 10, 'numjobs': 3, 'ss_dur': 10, 'ss_ramp': 500, 'iops': False, 'slope': True, 'ss_limit': 0.1, 'pct': True, 'ss_interval': 5},
            ]

    jobnum = 0
    for job in reads:

        tf = "steadystate_job{0}.json".format(jobnum)
        parameters = [ "--max-jobs=16", "--name=job{0}".format(jobnum) ]
        parameters.extend([ "--thread",
                            "--output-format=json",
                            "--output={0}".format(tf),
                            "--ioengine=null",
                            "--size=1G",
                            "--rw=randrw",
                            "--rwmixread=100",
                            "--stonewall",
                            "--group_reporting",
                            "--numjobs={0}".format(job['numjobs']),
                            "--time_based",
                            "--runtime={0}".format(job['timeout']) ])
        if job['s']:
           if job['iops']:
               ss = 'iops'
           else:
               ss = 'bw'
           if job['slope']:
               ss += "_slope"
           ss += ":" + str(job['ss_limit'])
           if job['pct']:
               ss += '%'
           parameters.extend([ '--ss_dur={0}'.format(job['ss_dur']),
                               '--ss={0}'.format(ss),
                               '--ss_ramp={0}'.format(job['ss_ramp']) ])

        output = subprocess.call([args.fio] + parameters)
        with open(tf, 'r') as source:
            jsondata = json.loads(source.read())
            source.close()

        for jsonjob in jsondata['jobs']:
            line = "{0}".format(jsonjob['job options']['name'])
            if job['s']:
                if jsonjob['steadystate']['attained'] == 1:
                    # check runtime >= ss_dur + ss_ramp, check criterion, check criterion < limit
                    mintime = (job['ss_dur'] + job['ss_ramp']) * 1000
                    actual = jsonjob['read']['runtime']
                    if mintime > actual:
                        line = 'FAILED ' + line + ' ss attained, runtime {0} < ss_dur {1} + ss_ramp {2}'.format(actual, job['ss_dur'], job['ss_ramp'])
                        failed = failed + 1
                    else:
                        line = line + ' ss attained, runtime {0} > ss_dur {1} + ss_ramp {2},'.format(actual, job['ss_dur'], job['ss_ramp'])
                        objsame, met, mean, target = check(data=jsonjob['steadystate']['data'],
                            iops=job['iops'],
                            slope=job['slope'],
                            pct=job['pct'],
                            limit=job['ss_limit'],
                            dur=job['ss_dur'],
                            criterion=jsonjob['steadystate']['criterion'])
                        if not objsame:
                            line = 'FAILED ' + line + ' fio criterion {0} != calculated criterion {1} '.format(jsonjob['steadystate']['criterion'], target)
                            failed = failed + 1
                        else:
                            if met:
                                line = 'PASSED ' + line + ' target {0} < limit {1}'.format(target, job['ss_limit'])
                                passed = passed + 1
                            else:
                                line = 'FAILED ' + line + ' target {0} < limit {1} but fio reports ss not attained '.format(target, job['ss_limit'])
                                failed = failed + 1
                else:
                    # check runtime, confirm criterion calculation, and confirm that criterion was not met
                    expected = job['timeout'] * 1000
                    actual = jsonjob['read']['runtime']
                    if abs(expected - actual) > 50:
                        line = 'FAILED ' + line + ' ss not attained, expected runtime {0} != actual runtime {1}'.format(expected, actual)
                    else:
                        line = line + ' ss not attained, runtime {0} != ss_dur {1} + ss_ramp {2},'.format(actual, job['ss_dur'], job['ss_ramp'])
                        objsame, met, mean, target = check(data=jsonjob['steadystate']['data'],
                            iops=job['iops'],
                            slope=job['slope'],
                            pct=job['pct'],
                            limit=job['ss_limit'],
                            dur=job['ss_dur'],
                            criterion=jsonjob['steadystate']['criterion'])
                        if not objsame:
                            if actual > (job['ss_dur'] + job['ss_ramp'])*1000:
                                line = 'FAILED ' + line + ' fio criterion {0} != calculated criterion {1} '.format(jsonjob['steadystate']['criterion'], target)
                                failed = failed + 1
                            else:
                                line = 'PASSED ' + line + ' fio criterion {0} == 0.0 since ss_dur + ss_ramp has not elapsed '.format(jsonjob['steadystate']['criterion'])
                                passed = passed + 1
                        else:
                            if met:
                                line = 'FAILED ' + line + ' target {0} < threshold {1} but fio reports ss not attained '.format(target, job['ss_limit'])
                                failed = failed + 1
                            else:
                                line = 'PASSED ' + line + ' criterion {0} > threshold {1}'.format(target, job['ss_limit'])
                                passed = passed + 1
            else:
                expected = job['timeout'] * 1000
                actual = jsonjob['read']['runtime']
                if abs(expected - actual) > 50:
                    result = 'FAILED '
                    failed = failed + 1
                else:
                    result = 'PASSED '
                    passed = passed + 1
                line = result + line + ' no ss, expected runtime {0} ~= actual runtime {1}'.format(expected, actual)
            print(line)
            if 'steadystate' in jsonjob:
                pp.pprint(jsonjob['steadystate'])
        jobnum += 1

    print("{0} test(s) PASSED, {1} test(s) FAILED".format(passed,failed))
    sys.exit(failed)
