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

tfidf_featuresets = [  "branch-conditions-v" ,
                       "branch-conditions-vmcfs" ,
                       "branch-conditions-vmcfsi" ,
                       "method-assignments-v",
                       "method-assignments-vmcfs" ,
                       "method-assignments-vmcfsi" ,
                       "literals" ,
                       "api-types" ,
                       "attrs" ,
                       "sizes" ,
                       "libcalls",
                        "libcalls-sig"]

class JFeatureSet():

    def __init__(self,xnode):
        self.xnode = xnode

    def getname(self): return self.xnode.get('name')

    def istfidf(self): return self.getname() in tfidf_featuresets

    def getkeyvaluepairs(self):
        result = []
        for bnode in self.xnode.findall('block'):
            for knode in bnode.findall('kv'):
                result.append((knode.get('k'),int(knode.get('v'))))
        return result
