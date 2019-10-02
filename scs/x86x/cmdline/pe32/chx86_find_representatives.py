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

import scs.x86x.util.fileutil as UF

from scs.x86x.retrieval.SearchIndex import SearchIndex
from scs.x86x.similarity.Pattern import Pattern
from scs.x86x.similarity.SearchTerms import SearchTerms
from scs.x86x.similarity.FindSimilar import FindSimilar
from scs.x86x.similarity.PropertyFormatter import PropertyFormatter

def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('indexpath',help='directory that holds the indexed features')
    parser.add_argument('pattern',help='json file with features patterns')
    parser.add_argument('listing',help='list of md5s')
    parser.add_argument('save',help='location to save properties to')
    parser.add_argument('searchterm',help='name of property to get representatives of')
    parser.add_argument('--iocproperties',nargs='*',default=[])
    parser.add_argument('--mincutoff',type=float,default='0.01',
                            help='minimum score to be included in the results')
    parser.add_argument('--maxcutoff',type=float,default='1.0',
                            help='maximum score to be included in the results')
    args = parser.parse_args()
    return args

def structure_properties(propdict, results, pattern, searchterm):
    propdict['rep'] = min([ x['name'][0] for x in results['exes'] ])
    md5s = pattern.searchterms[searchterm]
    propdict['text-md5s'] = next(iter(pattern.searchterms['named_section_md5s']))[6:] if len(md5s) == 1 else len(md5s)
    propdict['count'] = len(results['exes'])

    propdict['imported_functions'] = propdict['imported_functions'][0]
    return (propdict)

def find_similar(indexpath,pattern,iocfeatures,savefile,key,searchterm):
    searchindex = SearchIndex(indexpath)
    pattern = Pattern(pattern)
    pattern.searchterms['named_section_md5s'] = { key : 1 }

    searchterms = SearchTerms(pattern.searchterms)
    query = FindSimilar(searchindex,searchterms)
    query.search()
    weightings = query.weightings
    similarityresults = query.get_similarity_results_structured(args.mincutoff,args.maxcutoff)
    
    for r in sorted(weightings):
        w = weightings[r]
        print('  ' + str(w[0]).ljust(20) + str(w[1].ljust(20) + ' (' + w[2] + ')'))

    results = {}
    results['exes'] = []
    results['weights'] = []

    for (r,xexe) in similarityresults:
        m = {}
        m['score'] = r
        m['name'] = xexe
        results['exes'].append(m)

    propertyformats = PropertyFormatter(pattern.propertyformats)
    for fs in iocfeatures: propertyformats.add_spec(fs)
    properties = query.get_similarity_results_properties(propertyformats,
                                                             args.mincutoff,args.maxcutoff)
    propdict = propertyformats.format_properties_as_dict(len(results['exes']),properties)
    propdict = structure_properties(propdict, results, pattern, searchterm)
    return propdict

if __name__ == '__main__':

    args = parse()

    if len(args.iocproperties) > 0:
        iocfeaturenames = UF.get_ioc_featurenames_file()
        iocfeatures = []
        for c in args.iocproperties:
            if c in iocfeaturenames:
                iocfeatures.extend([ 'ioc_' + n for n in iocfeaturenames[c]])
    else:
        iocfeatures = []

    with open(args.pattern,'r') as fp:
        pattern = json.load(fp)

    with open(args.listing,'r') as md5file:
        md5list = json.load(md5file)[args.searchterm]

    clusters = {}
    for key in md5list:
        listing = find_similar(args.indexpath, pattern, iocfeatures, args.save, key, args.searchterm)

        namesize = 3
        name = 'K' + listing['text-md5s'][:namesize]
        while name in clusters:
            namesize += 1
            name = 'K' + listing['text-md5s'][:namesize]
        clusters[name] = listing

    with open(args.save,'w') as dumpfile:
        json.dump(clusters, dumpfile, indent=3)
