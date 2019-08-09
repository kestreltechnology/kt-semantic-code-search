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

import scs.x86x.util.fileutil as UF

class Postings(object):

    def __init__(self,indexpath):
        self.indexpath = indexpath
        self.data = UF.load_postings_files(self.indexpath) # fs -> docix -> termix -> founnt

    def add_posting(self,featureset,docix,termix,count):
        if count > 0:
            pfeatures = self.data.setdefault(featureset,{})
            pdocs = pfeatures.setdefault(docix,{})
            pdocs[termix] = count

    def get_termix_count(self,featureset):
        result = {}  #  termix -> count
        if featureset in self.data:
            for docix in self.data[featureset]:
                for termix in self.data[featureset][docix]:
                    result.setdefault(termix,0)
                    result[termix] += self.data[featureset][docix][termix]
        return result

    def save(self):
        UF.save_postings_files(self.indexpath,self.data)
