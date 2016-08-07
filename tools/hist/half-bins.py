#!/usr/bin/env python2.7
""" Cut the number bins in half in fio histogram output. Example usage:

        $ half-bins.py -c 2 output_clat_hist.1.log > smaller_clat_hist.1.log

    Which merges e.g. bins [0 .. 3], [4 .. 7], ..., [1212 .. 1215] resulting in
    304 = 1216 / (2**2) merged bins per histogram sample.

    @author Karl Cronburg <karl.cronburg@gmail.com>
"""
import sys

def main(ctx):
    stride = 1 << ctx.coarseness
    with open(ctx.FILENAME, 'r') as fp:
        for line in fp.readlines():
            vals = line.split(', ')
            sys.stdout.write("%s, %s, %s, " % tuple(vals[:3]))

            hist = list(map(int, vals[3:]))
            for i in range(0, len(hist) - stride, stride):
                sys.stdout.write("%d, " % sum(hist[i : i + stride],))
            sys.stdout.write("%d\n" % sum(hist[len(hist) - stride:]))

if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    arg = p.add_argument
    arg( 'FILENAME', help='clat_hist file for which we will reduce'
                         ' (by half or more) the number of bins.')
    arg('-c', '--coarseness',
       default=1,
       type=int,
       help='number of times to reduce number of bins by half, '
            'e.g. coarseness of 4 merges each 2^4 = 16 consecutive '
            'bins.')
    main(p.parse_args())

