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

from jbcmlscs.retrieval.JIndexJar import JIndexJar
from jbcmlscs.similarity.JSearchTerms import JSearchTerms
from jbcmlscs.similarity.JFindSimilar import JFindSimilar

def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('indexedfeaturesjar',help='indexedcorpus jarfile')
    parser.add_argument('--exprs',nargs='*',help='expressions to search for')
    parser.add_argument('--loops',nargs='*',help='expressions that appear in loops')
    parser.add_argument('--assigns',nargs="*",help='assignment expressions')
    parser.add_argument('--loopassigns',nargs='*',help='assignment expressions within loops')
    parser.add_argument('--loopexprs',nargs='*',help='expression within a loop')
    parser.add_argument('--literals',nargs='*',help='literals')
    parser.add_argument('--conditions',nargs='*',help='conditions')
    parser.add_argument('--loopconditions',nargs='*',help='conditional statements in a loop')
    parser.add_argument('--signatures',nargs='*',help='method signatures')
    parser.add_argument('--returns',nargs='*',help='return expression')
    parser.add_argument('--packages',nargs='*',
                        help='restrict query to the class files with these package names')
    parser.add_argument('--docformat',default='full',
                        choices=['full','columns','methodname','methodsig','classmethodsig'])
    args = parser.parse_args()
    return args

@contextmanager
def timing():
    t0 = time.time()
    yield
    print('Completed in ' + str(time.time() - t0) + ' secs')


if __name__ == '__main__':

    args = parse()

    pattern = {}
    if not args.returns is None:
        pattern['return'] = { t:1 for t in args.returns }
    if not args.loopconditions is None:
        pattern['inloop-conditions'] = { t:1 for t in args.loopconditions }
    if not args.loopexprs is None:
        pattern['inloop-exprs'] = { t:1 for t in args.loopexprs }
    if not args.conditions is None:
        pattern['conditions'] = { t:1 for t in args.conditions }
    if not args.literals is None:
        pattern['literals'] = { t:1 for t in args.literals }
    if not args.loopassigns is None:
        pattern['inloop-assigns'] = { t:1 for t in args.loopassigns }
    if not args.assigns is None:
        pattern['assigns'] = { t:1 for t in args.assigns }
    if not args.exprs is None:
        pattern['exprs'] = { t:1 for t in args.exprs }
    if not args.loops is None:
        pattern['inloop-exprs'] = { t:1 for t in args.loops }
    if not args.signatures is None and len(args.signatures) > 0:
        pattern['signatures'] = { s:1 for s in args.signatures }
    with timing():
        print('\nLoading the corpus ...')
        jindexjar = JIndexJar(args.indexedfeaturesjar)
        pcks = jindexjar.getallpckmd5s(args.packages)
        jpattern = JSearchTerms(pattern)
        jquery = JFindSimilar(jindexjar,jpattern,pcks)
    with timing():
        print('\n\nConstructing the query matrices ...')
        jquery.search()
    weightings = jquery.getweightings()
    similarityresults = jquery.getsimilarityresults(docformat=args.docformat)
    print('\n\nTerm weights based on their prevalence in the corpus:')
    for r in sorted(weightings):
        w = weightings[r]
        print('  ' + str(w[0]).ljust(20) + str(w[1]).ljust(20)  + ' (' + w[2] + ')')

    print('\n\nMost similar methods:')
    for (r,name) in similarityresults:
        print(str(r) + ': ' + name)
              
