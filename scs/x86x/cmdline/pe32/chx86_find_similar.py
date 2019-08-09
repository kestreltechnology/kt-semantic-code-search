# ------------------------------------------------------------------------------
# Python API to access CodeHawk Binary Analyzer analysis results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2019 Kestrel Technology LLC
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
import json

from scs.x86x.retrieval.SearchIndex import SearchIndex
from scs.x86x.similarity.Pattern import Pattern
from scs.x86x.similarity.SearchTerms import SearchTerms
from scs.x86x.similarity.FindSimilar import FindSimilar
from scs.x86x.similarity.PropertyFormatter import PropertyFormatter

def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('indexpath',help='directory that holds the indexed features')
    parser.add_argument('pattern',help='json file with features patterns')
    args = parser.parse_args()
    return args

def find_similar(indexpath,pattern):
    searchindex = SearchIndex(indexpath)
    pattern = Pattern(pattern)
    searchterms = SearchTerms(pattern.searchterms)
    query = FindSimilar(searchindex,searchterms)
    query.search()
    weightings = query.weightings
    similarityresults = query.get_similarity_results_structured()
    
    for r in sorted(weightings):
        w = weightings[r]
        print('  ' + str(w[0]).ljust(20) + str(w[1].ljust(20) + ' (' + w[2] + ')'))

    results = {}
    results['exes'] = []
    results['weights'] = []

    print('\n\nMost similar executables (' + str(len(similarityresults)) + '):')
    for (r,xexe) in similarityresults:
        m = {}
        m['score'] = r
        m['name'] = xexe
        results['exes'].append(m)

    for m in sorted(results['exes'],key=lambda m:m['score'],reverse=True):
        print(str(m['score']).ljust(25) + ': ' + ','.join([ str(x) for x in m['name']]))

    propertyformats = PropertyFormatter(pattern.propertyformats)
    properties = query.get_similarity_results_properties(propertyformats)

    print(propertyformats.format_properties(len(results['exes']),properties))


if __name__ == '__main__':

    args = parse()

    with open(args.pattern,'r') as fp:
        pattern = json.load(fp)

    find_similar(args.indexpath, pattern)
