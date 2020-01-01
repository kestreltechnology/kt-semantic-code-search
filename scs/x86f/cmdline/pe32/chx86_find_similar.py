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

import scs.x86f.util.fileutil as UF

from scs.x86f.retrieval.SearchIndex import SearchIndex
from scs.x86f.similarity.Pattern import Pattern
from scs.x86f.similarity.SearchTerms import SearchTerms
from scs.x86f.similarity.FindSimilar import FindSimilar
from scs.x86f.similarity.PropertyFormatter import PropertyFormatter

def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('indexpath',help='directory that holds the indexed features')
    parser.add_argument('pattern',help='json file with features patterns')
    parser.add_argument('--expand',action='store_true',
                            help='show documents for properties')
    parser.add_argument('--mincutoff',type=float,default='0.01',
                            help='minimum score to be included in the results')
    parser.add_argument('--maxcutoff',type=float,default='1.0',
                            help='maximum score to be included in the results')
    args = parser.parse_args()
    return args

def find_similar(indexpath,pattern):
    searchindex = SearchIndex(indexpath)
    pattern = Pattern(pattern)
    searchterms = SearchTerms(pattern.searchterms)
    query = FindSimilar(searchindex,searchterms)
    query.search()
    weightings = query.weightings
    similarityresults = query.get_similarity_results_structured(args.mincutoff,args.maxcutoff)
    
    for r in sorted(weightings):
        w = weightings[r]
        print('  ' + str(w[0]).ljust(20) + str(w[1].ljust(20) + ' (' + w[2] + ')'))

    results = {}
    results['functions'] = []
    results['weights'] = []

    print('\n\nMost similar functions (' + str(len(similarityresults)) + '):')
    for (r,d) in similarityresults:
        m = {}
        m['score'] = r
        m['doc'] = (d[0][0]['name'],d[1])
        results['functions'].append(m)

    for m in sorted(results['functions'],key=lambda m:(m['score'],m['doc']),reverse=True):
        print(str(m['score']).ljust(25) + ': ' + m['doc'][0] + ':' + m['doc'][1])
        
    propertyformats = PropertyFormatter(pattern.propertyformats)
    properties = query.get_similarity_results_doc_properties(propertyformats,
                                                             args.mincutoff,args.maxcutoff)

    print(propertyformats.format_properties(len(results['functions']),properties,args.expand))


if __name__ == '__main__':

    args = parse()

    with open(args.pattern,'r') as fp:
        pattern = json.load(fp)

    find_similar(args.indexpath, pattern)
