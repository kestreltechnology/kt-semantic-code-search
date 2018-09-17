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

import scs.jbc.util.fileutil as UF

class PackageDigest():
    """Maintains an index from package index to a document count and term postings.

    For each feature set it maintains a list of terms that appear in the set of
    documents in this package. The purpose of the package digests is to determine
    if the document postings for this package should be loaded for a particular
    query. 

    Index format:  pckix -> (doccount, fs -> termix list)
    """

    def __init__(self,indexpath,digest=None):
        self.indexpath = indexpath
        if digest is None:
            self.digest = UF.load_package_digest(self.indexpath)
        else:
            self.digest = digest
        self.digestsets = {}     # pck-ix -> fs -> term-ix set

    def set_digest(self,pckix,digest): self.digest[pckix] = digest

    def _get_pck_digest(self,pckix,fs):
        if pckix in self.digestsets and fs in self.digestsets[pckix]: return
        if pckix in self.digest and fs in self.digest[pckix]['terms']:
            if not pckix in self.digestsets:
                self.digestsets[pckix] = {}
            self.digestsets[pckix][fs] = set(self.digest[pckix]['terms'][fs])
        elif pckix in self.digest:
            if not pckix in self.digestsets:
                self.digestsets[pckix] = {}
            self.digestsets[pckix][fs] = set([])
        else:
            self.digestsets[pckix] = {}
            self.digestsets[pckix][fs] = set([])

    def add_term(self,pckix,fs,termix):
        self._get_pck_digest(pckix,fs)
        self.digestsets[pckix][fs].add(termix)

    def add_doc(self,pckix):
        self._initialize_package(pckix)
        self.digest[pckix]['docs'] += 1

    def intersects(self,pckix,fs,terms):
        return (str(pckix) in self.digest
                    and fs in self.digest[str(pckix)]['terms']
                    and len(set(self.digest[str(pckix)]['terms'][fs]) & terms) > 0)
        

    def has_term(self,pckix,fs,termix):
        self._get_pck_digest(pckix)
        return fs in self.digestsets[pckix] and termix in self.digestsets[pckix][fs]

    def size(self,pckix): return self.digest[pckix]['docs']

    def save(self):
        self._update_digest()
        UF.save_package_digest(self.indexpath, self.digest)

    def __str__(self):
        lines = []
        self._update_digest()
        for pckix in self.digest:
            docs = str(self.digest[pckix]['docs'])
            fsets = str(len(self.digest[pckix]['terms']))
            terms = str(sum([ len(self.digest[pckix]['terms'][fs]) for fs in self.digest[pckix]['terms'] ]))
            lines.append(str(pckix).rjust(4) + ': ' + docs.rjust(8) + fsets.rjust(8) + terms.rjust(8))
        return '\n'.join(lines)
        
    def _update_digest(self):
        for pckix in self.digestsets:
            for fs in self.digestsets[pckix]:
                self.digest[pckix]['terms'][fs] = list(self.digestsets[pckix][fs])        

    def _initialize_package(self,pckix):
        if pckix in self.digest: return
        self.digest[pckix] = {}
        self.digest[pckix]['docs'] = 0
        self.digest[pckix]['terms'] = {}
