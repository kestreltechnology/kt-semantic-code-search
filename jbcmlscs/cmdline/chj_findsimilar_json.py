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
import hashlib
import json
import os
import subprocess
import time

from contextlib import contextmanager

from jbcmlscs.retrieval.JIndexJar import JIndexJar
from jbcmlscs.similarity.JPattern import JPattern
from jbcmlscs.similarity.JFindSimilar import JFindSimilar

def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('indexedfeaturesjar',help='indexedcorpus jarfile')
    parser.add_argument('pattern',help='json file with feature patterns')
    parser.add_argument('--packages',nargs='*',
                        help='restrict query to the class files with these package names')
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
        print('\nLoading the corpus ...')
        jindexjar = JIndexJar(args.indexedfeaturesjar)
        pcks = jindexjar.getallpckmd5s(args.packages)
        jpattern = JPattern(args.pattern)
        jquery = JFindSimilar(jindexjar,jpattern,pcks)
    with timing():
        print('\n\nConstructing the query matrices ...')
        jquery.search()
    weightings = jquery.getweightings()
    similarityresults = jquery.getsimilarityresults_structured()
    print('\n\nTerm weights based on their prevalence in the corpus:')

    results = {}
    results['methods'] = []
    results['weights'] = []
    
    for r in sorted(weightings):
        w = weightings[r]
        weighting = {}
        weighting['score'] = w[0]
        weighting['feature'] = w[1]
        weighting['featureset'] = w[2]
        results['weights'].append(weighting)

    print('\n\nMost similar methods:')
    for (r,package,classname,methodname,signature,jarnames) in similarityresults:
        m = {}
        m['score'] = r
        m['package'] = package
        m['classname'] = classname
        m['methodname'] = methodname
        m['signature'] = signature
        m['jarnames'] = ','.join(jarnames)
        results['methods'].append(m)

    print(json.dumps(results,indent=4,sort_keys=True))
              
