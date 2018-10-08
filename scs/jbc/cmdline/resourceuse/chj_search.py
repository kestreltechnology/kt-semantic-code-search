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
import hashlib
import os
import subprocess
import time

from contextlib import contextmanager

import scs.jbc.util.fileutil as UF

from scs.jbc.retrieval.IndexJar import IndexJar
from scs.jbc.similarity.SearchTerms import SearchTerms
from scs.jbc.similarity.FindSimilar import FindSimilar

import scs.jbc.cmdline.resourceuse.ResourceUseFeaturesRecorder as RF


def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('indexedfeaturesjar',help='indexedcorpus jarfile')
    for (k,v) in sorted(RF.featuresets.items()):
        parser.add_argument('--' + k,nargs='*',help=v)
    args = parser.parse_args()
    return args

@contextmanager
def timing():
    t0 = time.time()
    yield
    print('Completed in ' + str(time.time() - t0) + ' secs')


if __name__ == '__main__':

    args = parse()
    indexedfeatures = UF.get_algorithms_indexedfeatures(args.indexedfeaturesjar)
    if indexedfeatures is None:
        indexedfeatures = args.indexedfeaturesjar
        if not os.path.isfile(indexedfeatures):
            print('*' * 80)            
            print('Indexed features jar file ' + indexedfeatures + ' not found')
            print('*' * 80)            
            exit(-1)

    pattern = {}
    for k in args.__dict__:
        if k == 'indexedfeaturesjar': continue
        if args.__dict__[k] is None: continue
        pattern[k] = { t:1 for t in args.__dict__[k] }
    
    with timing():
        print('\nLoading the corpus ...')
        indexjar = IndexJar(indexedfeatures)
        pcks = indexjar.get_all_pckmd5s()
        pattern = SearchTerms(pattern)
        query = FindSimilar(indexjar,pattern,pcks)
    with timing():
        print('\n\nConstructing the query matrices ...')
        query.search()
    weightings = query.get_weightings()
    similarityresults = query.get_similarity_results()
    print('\n\nTerm weights based on their prevalence in the corpus:')
    for r in sorted(weightings):
        w = weightings[r]
        print('  ' + str(w[0]).ljust(20) + str(w[1]).ljust(20)  + ' (' + w[2] + ')')

    print('\n\nMost similar methods:')
    for (r,name) in similarityresults:
        print(str(r) + ': ' + name)
              
