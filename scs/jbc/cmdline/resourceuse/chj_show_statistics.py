# ------------------------------------------------------------------------------
# Python API to access CodeHawk Java Analyzer analysis results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2018 Kestrel Technology LLC
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ------------------------------------------------------------------------------

import argparse
import os
import subprocess
import time

"""
Prints out:
(1) a list of all distinct features belonging to the given featureset
    with the number of times each feature appears in the index;
(2) a list of different number of occurrences for each frequency, e.g.,
    the (partial) results:
    frequency    count
    --------------------------------------------------
       1         2142      0.635
       2          544      0.161
       3          103      0.031
       ............
      -------------------------------------------------
      total      4492
    means:
     2142 distinct features appear only once,
      544 distinct features appear twice,
      103 distinct features appear three times, 
     etc.
     4492 distinct features in total
"""

from contextlib import contextmanager

from scs.jbc.stats.FeatureStats import FeatureStats
from scs.jbc.retrieval.IndexJar import IndexJar

import scs.jbc.cmdline.resourceuse.ResourceUseFeaturesRecorder as RF


def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('indexedfeaturesjar',help='indexedcorpus jarfile')
    parser.add_argument('fs',help='feature set of interest')
    parser.add_argument('--packages',nargs='*',default=[],
                        help='only include counts from these packages')
    args = parser.parse_args()
    return args

@contextmanager
def timing():
    t0 = time.time()
    yield
    print('Completed in ' + str(time.time() - t0) + ' secs')


if __name__ == '__main__':

    args = parse()

    if not (args.fs in RF.featuresets):
        print('*' * 80)
        print('feature set ' + args.fs + ' not found; feature sets available: ')
        w = max ( [ len(k) for k in RF.featuresets ]) + 3
        for (k,v) in RF.featuresets.items():
            print('  ' + k.ljust(w) + v)
        print('*' * 80)
        exit(0)
        
    with timing():
        print('\nLoading the indexed features ...')
        indexjar = IndexJar(args.indexedfeaturesjar)
        pckmd5s = [ hashlib.md5(p).hexdigest() for p in args.packages ]
        if not pckmd5s:
            pckmd5s = indexjar.get_all_pckmd5s()
        stats = FeatureStats(indexjar,pckmd5s)
        counts = stats.get_counts(args.fs)
        print('freqency   term')
        print('-' * 50)
        for t in sorted(counts,key=lambda t:counts[t],reverse=True):
            #if counts[t][0] > 2:
                print(str(counts[t][0]).rjust(8) + '   ' +
                    # '{:>.3f}'.format(counts[t][1]).rjust(6) + '  ' +
                    str(t))

        histogram = {}
        for t in counts:
            count = counts[t][0]
            if not count in histogram: histogram[count] = 0
            histogram[count] += 1

        total = sum( [ histogram[x] for x in histogram ])

        if total > 0:
            print('\nfrequency    count')
            print('-' * 50)
            for t in sorted(histogram):
                perc = float(histogram[t]) / float(total)
                print(str(t).rjust(8) + '   ' + str(histogram[t]).rjust(8)
                          + '   ' + '{:>.3f}'.format(perc).rjust(8))
            print('-' * 50)
            print('total'.ljust(8) + '   ' + str(total).rjust(8))
    
              
