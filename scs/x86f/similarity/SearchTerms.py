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


import json

class SearchTerms(object):

    def __init__(self,searchterms):
        self.searchterms = searchterms        #   featureset -> term -> weight

    def get_featuresets(self): return self.searchterms.keys()

    def get_expanded_pattern(self,vocabulary): 
        xpattern = {}
        for fs in sorted(self.searchterms):
            xpattern[fs] = []
            featureset = self.searchterms[fs]
            for t in self.searchterms[fs]:
                if fs in vocabulary:
                    tx = vocabulary[fs].get_termix(t)
                    for i in range(featureset[t]):
                        xpattern[fs].append(tx)
        self.expandedpattern = xpattern
        return xpattern

    def get_term_count(self):
        count = 0
        for fs in self.searchterms:
            for term in self.searchterms[fs]:
                count += int(self.searchterms[fs][term])
        return count

    def get_feature_terms(self,fs,vocabulary):
        result = set([])
        for t in self.searchterms[fs]:
            tx = vocabulary.get_termix(t)
            result.add(tx)
        return result
