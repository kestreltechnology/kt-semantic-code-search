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

structureweights = {
    'md5': 4,
    'loopdepth': 4,
    'loops': 3,
    'blocks': 2,
    'instrs': 1
    }

class SemanticReferenceFeaturesRecorder(object):

    def __init__(self):
        self.results = {}
        self.featuresets = []

    def reset(self):
        self.results = {}

    def add_term(self,featureset,term,n=1):
        self.results.setdefault(featureset,{})
        self.results[featureset].setdefault(term,0)
        self.results[featureset][term] += n

    def record(self,fnfeaturesets):
        featurecount = sum([ len(fnfeaturesets[fs])
                                 for fs in fnfeaturesets if not (fs == 'structure')])
        for fs in fnfeaturesets:
            if fs == 'dllcalls':
                self.record_dllcalls(fnfeaturesets[fs])
            if fs == 'structure':
                self.record_structure(fnfeaturesets[fs],featurecount)
            else:
                for term in fnfeaturesets[fs]:
                    self.add_term(fs,term,fnfeaturesets[fs][term])

    def record_dllcalls(self,fnfeatures):
        for term in fnfeatures:
            if term.endswith('A') or term.endswith('W'):
                stemmedterm = term[:-1]
            else:
                stemmedterm = term
            self.add_term('dllcalls',stemmedterm,fnfeatures[term])

    def record_structure(self,fnfeatures,featurecount):
        weights = structureweights
        if featurecount < 5:
            weights['md5'] = 1
        for fs in fnfeatures:
            self.add_term(fs,str(fnfeatures[fs]),weights[fs])
