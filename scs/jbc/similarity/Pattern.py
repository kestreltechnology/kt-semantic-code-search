# ------------------------------------------------------------------------------
# Python API to access CodeHawk Java Analyzer analysis results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2018 Kestrel Technology LLC
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

class Pattern():

    def __init__(self,fname):
        with open(fname,'r') as fp:
            self.pattern = json.load(fp)

    def get_featuresets(self):
        return self.pattern.keys()

    def get_expanded_pattern(self,vocabulary): 
        xpattern = {}
        for fs in sorted(self.pattern):
            xpattern[fs] = []
            for t in self.pattern[fs]:
                if fs in vocabulary:
                    tx = vocabulary[fs].gettermix(t)
                    for i in range(self.pattern[fs][t]):
                        xpattern[fs].append(tx)
        self.expandedpattern = xpattern
        return xpattern

    def get_term_count(self):
        count = 0
        for fs in self.pattern:
            for term in self.pattern[fs]:
                count += int(self.pattern[fs][term])
        return count

    # returns set(term-ix)
    def get_feature_terms(self,fs,vocabulary):
        result = set([])
        for t in self.pattern[fs]:
            tx = vocabulary.gettermix(t)
            result.add(tx)
        return result

