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

import jbcmlscs.util.fileutil as UF

class JData:

    def __init__(self,indexpath,pckmd5):
        self.indexpath = indexpath
        self.pckmd5 = pckmd5          # package md5
        self.data = UF.loaddatafiles(self.indexpath,pckmd5)   # featureset -> docix -> termix -> data (freq)

    def getsize(self,fs):
        return sum( [ len(self.data[fs][x]) for x in self.data[fs] ] )

    def addfeature(self,featureset,docix,termix,freq):
        if freq > 0:
            if not featureset in self.data: 
                self.data[featureset] = {}
            if not docix in self.data[featureset]: 
                self.data[featureset][docix] = {}
            self.data[featureset][docix][termix] = freq

    def digest(self,size):
        digest = {}        # fs -> set(termix)
        digest['docs'] = size
        digest['terms'] = {}
        for fs in self.data:
            digest['terms'][fs] = set([])
            for docix in self.data[fs]:
                for termix in self.data[fs][docix]:
                    digest['terms'][fs].add(int(termix))
        for fs in digest['terms']:
            digest['terms'][fs] = list(digest['terms'][fs])
        return digest

    def save(self): 
        UF.savedatafiles(self.indexpath,self.pckmd5,self.data)
