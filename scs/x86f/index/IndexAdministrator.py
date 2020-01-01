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

import scs.x86f.util.fileutil as UF

from scs.x86f.index.XMd5Index import XMd5Index
from scs.x86f.index.XMd5XRef import XMd5XRef
from scs.x86f.index.FnNameIndex import FnNameIndex
from scs.x86f.index.Vocabulary import Vocabulary
from scs.x86f.index.Postings import Postings


class IndexAdministrator(object):

    def __init__(self,indexpath):
        self.indexpath = indexpath
        self.xmd5index = XMd5Index(self.indexpath)
        self.xmd5xref = XMd5XRef(self.indexpath)
        self.fnameindex = FnNameIndex(self.indexpath)
        self.vocabulary = Vocabulary(self.indexpath)
        self.data = Postings(self.indexpath)

    def index_semantic_features(self,name,xrec,recorders,features,excludefns=[]):
        xmd5 = xrec['md5']
        xmd5ix = self.xmd5index.add_xmd5(xmd5)
        self.xmd5xref.add_xref(xmd5ix,xrec,name)
        def f(fn,fnfeatures):
            if fn in excludefns: return
            fname = str(xmd5ix) + ':' + fn
            fnameix = self.fnameindex.add_fn_name(fname)
            for r in recorders:
                r.reset()
                r.record(fnfeatures)
                for fs in r.results:
                    for (term,count) in r.results[fs].items():
                        termix = self.vocabulary.add_term(fs,term)
                        self.data.add_posting(fs,fnameix,termix,count)
        features.iter(f)

    def index_reference_features(self,cluster,recorder,reffeatures):
        xmd5ix = self.xmd5index.add_xmd5(cluster)
        xrec = { 'file': cluster, 'path': cluster}
        self.xmd5xref.add_xref(xmd5ix,xrec,cluster)
        def f(fn,fnmd5,fnfeatures):
            fnmd5ix = self.fnmd5index.add_fn_md5(fnmd5)
            self.fnmd5xref.add_xref(fnmd5ix,xmd5ix,fn)
            recorder.reset()
            recorder.record(fnfeatures)
            for fs in recorder.results:
                for (term,count) in recorder.results[fs].items():
                    termix = self.vocabulary.add_term(fs,term)
                    self.data.add_posting(fs,fnmd5ix,termix,count)
        reffeatures.iter(f)
            
                
    def save_features(self):
        UF.create_index_directories(self.indexpath)
        self.xmd5index.save()
        self.xmd5xref.save()
        self.fnameindex.save()
        self.vocabulary.save()
        self.data.save()
                                            

    
