# ------------------------------------------------------------------------------
# Python API to access CodeHawk Java Analyzer analysis results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2017 Kestrel Technology LLC
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

from contextlib import contextmanager

from jbcmlscs.stats.JStats import JStats
from jbcmlscs.retrieval.JIndexJar import JIndexJar

def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('indexedfeaturesjar',help='indexedcorpus jarfile')
    parser.add_argument('fs',help='feature of interest')
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
    with timing():
        print('\nLoading the indexed features ...')
        jindexjar = JIndexJar(args.indexedfeaturesjar)
        pckmd5s = [ hashlib.md5(p).hexdigest() for p in args.packages ]
        if not pckmd5s:
            pckmd5s = jindexjar.getallpckmd5s()
        jstats = JStats(jindexjar,pckmd5s)
        counts = jstats.getcounts(args.fs)
        for t in sorted(counts,key=lambda(t):counts[t],reverse=True):
            if t.startswith('self-ms'): continue
            print(str(counts[t][0]).rjust(6) + '   ' +
                  # '{:>.3f}'.format(counts[t][1]).rjust(6) + '  ' +
                  str(t))
    
              
