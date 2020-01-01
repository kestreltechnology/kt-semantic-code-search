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
    
class SemanticFeaturesRecorder(object):

    def __init__(self,fnmap):
        self.fnmap = { f: fnmap['functions'][f]['reffn']
                           for f in fnmap['functions'] } if 'functions' in  fnmap else {}
        self.gvmap = { g: fnmap['globalvars'][g]
                           for g in fnmap['globalvars'] } if 'globalvars' in fnmap else {}
        self.results = {}
        self.featuresets = []
        self.substitution = {}

    def reset(self):
        self.results = {}

    def substitute(self,term):
        for t in sorted(self.substitution,reverse=True):  # ensure App: is encountered before 0x
            term = term.replace(t,self.substitution[t])
        return term            

    def has_canonical_function_name(self,faddr):
        return faddr in self.fnmap

    def normalize_term(self,p):
        if 'App:' in p:
            for f in  self.fnmap:
                p = p.replace('App:' + f,self.fnmap[f])
        if 'gv_' in p:
            for g in self.gvmap:
                p = p.replace(g,self.gvmap[g])
        if 'App:' in p or 'gv_' in p:
            return None
        return p

    def add_term(self,featureset,term,n=1):
        self.results.setdefault(featureset,{})
        self.results[featureset].setdefault(term,0)
        self.results[featureset][term] += n

    def record(self,fnfeaturesets):
        for fs in sorted(fnfeaturesets):    # appcalls and dllcalls before predicates
            features = fnfeaturesets[fs] 
            if fs == 'dllcalls':
                self.record_dllcalls(features)
            elif fs == 'appcalls':
                self.record_appcalls(features)
            elif fs in ['predicates', 'returnexprs', 'structuredrhs', 'structuredlhs',
                            'unresolvedcalls' ]:
                self.record_expressions(fs,features)
            elif fs == 'structure':
                self.record_structure(features)
            elif fs == 'unresolvedcalls':
                self.record_unresolved_calls(features)
            else:
                for term in fnfeaturesets[fs]:
                    self.add_term(fs,term,fnfeaturesets[fs][term])

    def record_dllcalls(self,features):
        for term in features:
            if term.endswith('A') or term.endswith('W'):
                stemmedterm = term[:-1]
                termfn = term.split(':')[1]
                stemmedtermfn = stemmedterm.split(':')[1]
                self.substitution[termfn] = stemmedtermfn
            else:
                stemmedterm = term
            self.add_term('dllcalls',stemmedterm,features[term])

    def record_appcalls(self,features):
        for term in features:
            if self.has_canonical_function_name(term):
                cterm = self.fnmap[term]
                self.substitution[term] = cterm
                self.substitution['App:' + term] = cterm
                self.add_term('appcalls',cterm,features[term])

    def record_expressions(self,fs,features):
        for term in features:
            if 'App:' in term or 'gv_' in term:
                cterm = self.normalize_term(term)
                if cterm is None: return
            else:
                cterm = self.substitute(term)
            self.add_term(fs,cterm,features[term])

    def record_structure(self,features):
        weights = structureweights
        for fs in features:
            self.add_term(fs,str(features[fs]),weights[fs])

