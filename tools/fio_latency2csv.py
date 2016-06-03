#!/usr/bin/python
#
# fio_latency2csv.py
#
# This tool converts fio's json+ completion latency data to CSV format.
# For example:
#
# fio_latency2csv.py fio-jsonplus.output fio-latency.csv
#

import os
import json
import argparse


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('source',
                        help='fio json+ output file containing completion '
                             'latency data')
    parser.add_argument('dest',
                        help='destination file stub for latency data in CSV '
                             'format. job number will be appended to filename')
    args = parser.parse_args()

    return args


# from stat.c
def plat_idx_to_val(idx, FIO_IO_U_PLAT_BITS=6, FIO_IO_U_PLAT_VAL=64):
    # MSB <= (FIO_IO_U_PLAT_BITS-1), cannot be rounded off. Use
    # all bits of the sample as index
    if (idx < (FIO_IO_U_PLAT_VAL << 1)):
        return idx

    # Find the group and compute the minimum value of that group
    error_bits = (idx >> FIO_IO_U_PLAT_BITS) - 1
    base = 1 << (error_bits + FIO_IO_U_PLAT_BITS)

    # Find its bucket number of the group
    k = idx % FIO_IO_U_PLAT_VAL

    # Return the mean of the range of the bucket
    return (base + ((k + 0.5) * (1 << error_bits)))


def percentile(idx, run_total):
    total = run_total[len(run_total)-1]
    if total == 0:
        return 0

    return float(run_total[x]) / total


if __name__ == '__main__':
    args = parse_args()

    with open(args.source, 'r') as source:
        jsondata = json.loads(source.read())

    bins = {}
    bin_const = {}
    run_total = {}
    ddir_list = ['read', 'write', 'trim']
    const_list = ['FIO_IO_U_PLAT_NR', 'FIO_IO_U_PLAT_BITS',
                  'FIO_IO_U_PLAT_VAL']

    for jobnum in range(0,len(jsondata['jobs'])):
        prev_ddir = None
        for ddir in ddir_list:
            bins[ddir] = jsondata['jobs'][jobnum][ddir]['clat']['bins']

            bin_const[ddir] = {}
            for const in const_list:
                bin_const[ddir][const] = bins[ddir].pop(const)
                if prev_ddir:
                    assert bin_const[ddir][const] == bin_const[prev_ddir][const]
            prev_ddir = ddir

            run_total[ddir] = [0 for x in
                               range(bin_const[ddir]['FIO_IO_U_PLAT_NR'])]
            run_total[ddir][0] = bins[ddir]['0']
            for x in range(1, bin_const[ddir]['FIO_IO_U_PLAT_NR']):
                run_total[ddir][x] = run_total[ddir][x-1] + bins[ddir][str(x)]
        
        stub, ext = os.path.splitext(args.dest)
        outfile = stub + '_job' + str(jobnum) + ext

        with open(outfile, 'w') as output:
            output.write("clat (usec),")
            for ddir in ddir_list:
                output.write("{0},".format(ddir))
            output.write("\n")

            for x in range(bin_const['read']['FIO_IO_U_PLAT_NR']):
                output.write("{0},".format(plat_idx_to_val(x,
                                          bin_const['read']['FIO_IO_U_PLAT_BITS'],
                                          bin_const['read']['FIO_IO_U_PLAT_VAL'])))
                for ddir in ddir_list:
                    output.write("{0},".format(percentile(x, run_total[ddir])))
                output.write("\n")
