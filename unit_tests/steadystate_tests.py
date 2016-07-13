#!/usr/bin/python
#
# steadystate_tests.py
#
# Test option parsing and functonality for fio's steady state detection feature.
#
# steadystate_tests.py ./fio file-for-read-testing file-for-write-testing
#
# REQUIREMENTS
# Python 2.6+
# SciPy
#
# KNOWN ISSUES
# only option parsing and read tests are carried out
# the read test fails when ss_ramp > timeout because it tries to calculate the stopping criterion and finds that
#     it does not match what fio reports
# min runtime:
# if ss attained: min runtime = ss_dur + ss_ramp
# if not attained: runtime = timeout

import os
import json
import tempfile
import argparse
import subprocess
from scipy import stats

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('fio',
                        help='path to fio executable');
    parser.add_argument('read',
                        help='target for read testing')
    parser.add_argument('write',
                        help='target for write testing')
    args = parser.parse_args()

    return args


def check(data, iops, slope, pct, limit, dur, criterion):
    measurement = 'iops' if iops else 'bw'
    data = data[measurement]
    mean = sum(data) / len(data)
    if slope:
        x = range(len(data))
        m, intercept, r_value, p_value, std_err = stats.linregress(x,data)
        m = abs(m)
        if pct:
            target = m / mean * 100
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
    return (abs(target - criterion) / criterion < 0.005), target < limit, mean, target


if __name__ == '__main__':
    args = parse_args()

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
        output = subprocess.check_output([args.fio] + test['args']);
        if test['output'] in output:
            print "PASSED '{0}' found with arguments {1}".format(test['output'], test['args'])
        else:
            print "FAILED '{0}' NOT found with arguments {1}".format(test['output'], test['args'])

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
    reads = [ [ {'s': True, 'timeout': 100, 'numjobs': 1, 'ss_dur': 5, 'ss_ramp': 3, 'iops': True, 'slope': True, 'ss_limit': 0.1, 'pct': True},
                {'s': False, 'timeout': 20, 'numjobs': 2},
                {'s': True, 'timeout': 100, 'numjobs': 3, 'ss_dur': 10, 'ss_ramp': 5, 'iops': False, 'slope': True, 'ss_limit': 0.1, 'pct': True},
                {'s': True, 'timeout': 10, 'numjobs': 3, 'ss_dur': 10, 'ss_ramp': 500, 'iops': False, 'slope': True, 'ss_limit': 0.1, 'pct': True} ],
            ]

    accum = []
    suitenum = 0
    for suite in reads:
        jobnum = 0
        for job in suite:
            parameters = [ "--name=job{0}".format(jobnum),
                           "--thread",
                           "--filename={0}".format(args.read),
                           "--rw=randrw", "--rwmixread=100", "--stonewall",
                           "--group_reporting", "--numjobs={0}".format(job['numjobs']),
                           "--time_based", "--runtime={0}".format(job['timeout']) ]
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
            accum.extend(parameters)
            jobnum += 1

        tf = tempfile.NamedTemporaryFile(delete=False)
	tf.close()
        output = subprocess.check_output([args.fio, 
                                          "--output-format=json", 
                                          "--output={0}".format(tf.name)] + accum)
        with open(tf.name, 'r') as source:
            jsondata = json.loads(source.read())
        os.remove(tf.name)
        jobnum = 0
        for job in jsondata['jobs']:
            line = "suite {0}, {1}".format(suitenum, job['job options']['name'])
            if suite[jobnum]['s']:
                if job['steadystate']['attained'] == 1:
                    # check runtime >= ss_dur + ss_ramp, check criterion, check criterion < limit
                    mintime = (suite[jobnum]['ss_dur'] + suite[jobnum]['ss_ramp']) * 1000
                    actual = job['read']['runtime']
                    if mintime > actual:
                        line = 'FAILED ' + line + ' ss attained, runtime {0} < ss_dur {1} + ss_ramp {2}'.format(actual, suite[jobnum]['ss_dur'], suite[jobnum]['ss_ramp'])
                    else:
                        line = line + ' ss attained, runtime {0} > ss_dur {1} + ss_ramp {2},'.format(actual, suite[jobnum]['ss_dur'], suite[jobnum]['ss_ramp'])
                        objsame, met, mean, target = check(data=job['steadystate']['data'],
                            iops=suite[jobnum]['iops'],
                            slope=suite[jobnum]['slope'],
                            pct=suite[jobnum]['pct'],
                            limit=suite[jobnum]['ss_limit'],
                            dur=suite[jobnum]['ss_dur'],
                            criterion=job['steadystate']['criterion'])
                        if not objsame:
                            line = 'FAILED ' + line + ' fio criterion {0} != calculated criterion {1}, data: {2} '.format(job['steadystate']['criterion'], target, job['steadystate'])
                        else:
                            if met:
                                line = 'PASSED ' + line + ' target {0} < limit {1}, data {2}'.format(target, suite[jobnum]['ss_limit'], job['steadystate'])
                            else:
                                line = 'FAILED ' + line + ' target {0} < limit {1} but fio reports ss not attained, data: {2}'.format(target, suite[jobnum]['ss_limit'], job['steadystate'])
                    
                else:
                    # check runtime, confirm criterion calculation, and confirm that criterion was not met
                    expected = suite[jobnum]['timeout'] * 1000
                    actual = job['read']['runtime']
                    if abs(expected - actual) > 10:
                        line = 'FAILED ' + line + ' ss not attained, expected runtime {0} != actual runtime {1}'.format(expected, actual)
                    else:
                        line = line + ' ss not attained, runtime {0} != ss_dur {1} + ss_ramp {2},'.format(actual, suite[jobnum]['ss_dur'], suite[jobnum]['ss_ramp'])
                        objsame, met, mean, target = check(data=job['steadystate']['data'],
                            iops=suite[jobnum]['iops'],
                            slope=suite[jobnum]['slope'],
                            pct=suite[jobnum]['pct'],
                            limit=suite[jobnum]['ss_limit'],
                            dur=suite[jobnum]['ss_dur'],
                            criterion=job['steadystate']['criterion'])
                        if not objsame:
                            if actual > (suite[jobnum]['ss_dur'] + suite[jobnum]['ss_ramp'])*1000:
                                line = 'FAILED ' + line + ' fio criterion {0} != calculated criterion {1}, data: {2} '.format(job['steadystate']['criterion'], target, job['steadystate'])
                            else:
                                line = 'PASSED ' + line + ' fio criterion {0} == 0.0 since ss_dur + ss_ramp has not elapsed, data: {1} '.format(job['steadystate']['criterion'], job['steadystate'])
                        else:
                            if met:
                                line = 'FAILED ' + line + ' target {0} < threshold {1} but fio reports ss not attained, data: {2}'.format(target, suite[jobnum]['ss_limit'], job['steadystate'])
                            else:
                                line = 'PASSED ' + line + ' criterion {0} > threshold {1}, data {2}'.format(target, suite[jobnum]['ss_limit'], job['steadystate'])
            else:
                expected = suite[jobnum]['timeout'] * 1000
                actual = job['read']['runtime']
                if abs(expected - actual) < 10:
                    result = 'PASSED '
                else:
                    result = 'FAILED '
                line = result + line + ' no ss, expected runtime {0} ~= actual runtime {1}'.format(expected, actual)
            print line
            jobnum += 1
        suitenum += 1
