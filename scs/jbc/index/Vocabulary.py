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

import scs.jbc.util.fileutil as UF

class Vocabulary():
    """Maintains a relationship between feature names and termix.

    Format of the index: featureset name -> feature name (term) -> termix
    """

    def __init__(self,indexpath):
        self.indexpath = indexpath
        self.featuresets = UF.load_vocabulary(self.indexpath)
        self.startlengths = {}
        for fs in self.featuresets:
            self.startlengths[fs] = len(self.featuresets[fs])  
                        
    def get_length(self,featureset): 
        return len(self.featuresets[featureset])

    def get_start_length(self,featureset):
        if not featureset in self.startlengths: self.startlengths[featureset] = 0
        return self.startlengths[featureset]

    def add_term(self,featureset,term):
        if not featureset in self.featuresets: self.featuresets[featureset] = {}
        ftermset = self.featuresets[featureset]
        termix = ftermset.setdefault(term,len(ftermset))
        return termix

    def save(self): UF.save_vocabulary(self.indexpath,self.featuresets)
