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
import os
import re

import scs.x86f.util.fileutil as UF
from scs.x86f.util.Config import Config

from scs.x86f.retrieval.SearchIndex import SearchIndex
from scs.x86f.similarity.Pattern import Pattern
from scs.x86f.similarity.SearchTerms import SearchTerms
from scs.x86f.similarity.FindSimilar import FindSimilar
from scs.x86f.similarity.PropertyFormatter import PropertyFormatter

def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('indexpath',help='directory that holds the indexed features')
    parser.add_argument('cluster',help='name of cluster')
    parser.add_argument('--expand',action='store_true',
                            help='show documents for properties')
    parser.add_argument('--mincutoff',type=float,default=0.4,
                            help='minimum score to be included in the results')
    parser.add_argument('--maxcutoff',type=float,default=1.0,
                            help='maximum score to be included in the results')
    parser.add_argument('--verbose',help='print scores',action='store_true')
    args = parser.parse_args()
    return args

def find_similar(pname,indexpath,pattern,mincutoff):
    searchindex = SearchIndex(indexpath)
    pattern = Pattern(pattern)
    searchterms = SearchTerms(pattern.searchterms)
    query = FindSimilar(searchindex,searchterms)
    query.search()
    weightings = query.weightings
    similarityresults = query.get_similarity_results_structured(mincutoff)

    result = {}

    for (r,d) in similarityresults:
        (xrecs,fn) = d
        xrec = xrecs[0]
        xname = xrec['name']
        if not xname in result:
            xentry = result[xname] = {}
            xentry['file'] = xrec['file']
            xentry['path'] = xrec['path']
            xentry['functions'] = {}
        result[xname]['functions'][fn] = r
                    
    return result

if __name__ == '__main__':

    args = parse()
    gvmapped = 0

    result = {}  #  xname -> fname -> reffn -> score

    reffile = UF.get_query_patterns(args.cluster)
    qpatterns = reffile['query-patterns']

    for p in sorted(qpatterns):
        print('Pattern ' + p)
        qfeatures = qpatterns[p]['featuresets']
        pattern = {}
        searchterms = pattern['search-terms'] = {}
        for fs in qfeatures:
            searchterms[fs] = qfeatures[fs]
        pattern['property-formats'] = {}
        score = qpatterns[p].get('score',0.9)
        refresult = find_similar(p,args.indexpath,pattern,score)

        for xname in refresult:
            if not xname in  result:
                xentry = result[xname] = {}
                xentry['file'] = refresult[xname]['file']
                xentry['path'] = refresult[xname]['path']
                xentry['functions'] = {}
            for fname in refresult[xname]['functions']:
                result[xname]['functions'].setdefault(fname,{})
                result[xname]['functions'][fname][p] = refresult[xname]['functions'][fname]

    mapping = {} # xname -> fname -> reffn

    projectpath = Config().myprojectdir        

    for xname in sorted(result):

        mapfilename = UF.get_fn_map_filename(
            projectpath,{'path':result[xname]['path'],'file':result[xname]['file']})

        if os.path.isfile(mapfilename):
            with open(mapfilename,'r')  as fp:
                prevmap = json.load(fp)
        else:
            prevmap = {}
            prevmap['globalvars'] = {}
            prevmap['functions'] = {}

        mapping.setdefault(xname,{})
        mapping[xname]['functions'] = {}
        mapping[xname]['globalvars'] = {}
        if args.verbose:  print('\n' + xname)
        for fname in sorted(result[xname]['functions']):
            refscore = args.mincutoff
            reffunction = None
            for reffn in sorted(result[xname]['functions'][fname]):
                score = result[xname]['functions'][fname][reffn]
                if score > refscore:
                    refscore = score
                    reffunction = reffn
            if not reffunction is None:
                fmap = mapping[xname]['functions'][fname] = {}
                fmap['reffn'] = args.cluster + '_' + reffunction
                fmap['score'] = refscore
                if args.verbose:
                    print('  ' + fname + ': ' + reffunction + ': (' + str(refscore) + ')')

        with open (mapfilename,'w')  as fp:
            json.dump(mapping[xname],fp,indent=2,sort_keys=True)

    patternsmapped = sum( [ len(result[x]['functions']) for x in result ])

    print('Patterns mapped: ' + str(patternsmapped))

        
