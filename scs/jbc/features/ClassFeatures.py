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

from scs.jbc.features.MethodFeatures import MethodFeatures
from scs.jbc.features.ClassDictionary import ClassDictionary


class ClassFeatures:

    def __init__(self,xnode):
        self.xnode = xnode
        self.dictionary = ClassDictionary(self,self.xnode.find('dictionary'))
        self.name = self.xnode.get('name')
        self.package = self.xnode.get('package')
        self.md5 = self.xnode.get('md5')
        self.methods = []
        self._initialize()

    def iter(self,f):
        for m in self.methods: f(m)

    def _initialize(self):
        if len(self.methods) > 0: return
        for x in self.xnode.find('methods').findall('method'):
            self.methods.append(MethodFeatures(self,x))

