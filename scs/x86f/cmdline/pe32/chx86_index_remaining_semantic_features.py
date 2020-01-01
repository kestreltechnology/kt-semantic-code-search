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

import scs.x86f.util.fileutil as UF

from scs.x86f.features.SemanticFeatures import SemanticFeatures
from scs.x86f.features.SemanticFeaturesRecorder import SemanticFeaturesRecorder
from scs.x86f.features.SemanticFeaturesRecorderAC import SemanticFeaturesRecorderAC
from scs.x86f.index.IndexAdministrator import IndexAdministrator

def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('nameprefix',help='prefix of project files')
    parser.add_argument('indexpath',help='directory to save the indexed features')
    parser.add_argument('--exclude_clusters','-x',nargs='*',default=[],
                            help='exclude executables from these clusters')
    parser.add_argument('--include_clusters','-i',nargs='*',default=[],
                            help='only include executables from these clusters'),
    parser.add_argument('--ac',help='abstract context-dependent features',
                            action='store_true')
    args = parser.parse_args()
    return args


def satisfies_spec(r,includes,excludes):
    if len(includes) > 0:
        for i in includes:
            if (not 'clusters' in r) or all([ not c.startswith(i) for c in r['clusters'] ]):
                return False
        else:
            return True
    if len(excludes) > 0:
        if not 'clusters' in r: return True
        for x in excludes:
            if any([ c.startswith(x) for c in r['clusters'] ]):
                return False
        else:
            return True
    return True


if __name__ == '__main__':

    args = parse()
    config = UF.Config()
    projectpath = config.myprojectdir

    indexadmin = IndexAdministrator(args.indexpath)
    
    for root,dirs, files in os.walk(projectpath):
        dirs[:] = [ d for d in dirs if not (d.endswith('ch') or d.endswith('chu') or d.endswith('chs')) ]
        for name in files:
            if name.startswith(args.nameprefix) and name.endswith('.json'):
                filename = os.path.join(root,name)
                with open(filename,'r') as fp:
                    projectfile = json.load(fp)
                    executables = projectfile['executables']
                    for key in executables:
                        xrec = executables[key]
                        xrecname = xrec['sha256'][:3] + ':' + key
                        if 'noanalysis' in xrec: continue
                        if not satisfies_spec(xrec,args.include_clusters,
                                                  args.exclude_clusters): continue
                        fnfeatures = UF.get_semantic_fn_features(root,xrec)
                        fnmap = UF.get_fn_map(root,xrec)
                        if len(fnmap) > 0:
                            excludefns = fnmap['functions'].keys()
                        else:
                            excludefns = []
                        if fnfeatures is None or len(fnfeatures) == 0: continue
                        print('Indexing ' + key)
                        if args.ac:
                            recorder = SemanticFeaturesRecorderAC()
                        else:
                            recorder = SemanticFeaturesRecorder(fnmap)
                        features = SemanticFeatures(fnfeatures)
                        indexadmin.index_semantic_features(
                            xrecname,xrec,[ recorder ],features,excludefns=excludefns)
    indexadmin.save_features()
    
