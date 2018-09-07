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

import jbcmlscs.util.fileutil as UF

from jbcmlscs.ifeatures.IMethodFeatures import IMethodFeatures
from jbcmlscs.ifeatures.IClassDictionary import IClassDictionary


class IClassFeatures:

    def __init__(self,xnode):
        self.xnode = xnode
        self.dictionary = IClassDictionary(self,self.xnode.find('dictionary'))
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
            self.methods.append(IMethodFeatures(self,x))


if __name__ == '__main__':

    # ffile = '/Users/henny/MUSE/etestdir/etestfeatures/e/7/e/d/e7ed915e429341161356da3bf19932f6.xml'
    ffile = '/Users/henny/MUSE/etestdir/etestfeatures/f/5/6/1/f561d9d64cd68990cfdbc99760477d89.xml'
    xclass = UF.getxnode(ffile,'class')
    iclass = IClassFeatures(xclass)
    print(iclass.name)

    print(str(iclass.dictionary.constant_value_table))
    print(str(iclass.dictionary.opcode_table))

    print(str(iclass.dictionary.fxpr_table))
    print(str(iclass.dictionary.fxfeature_table))

    print('\n\n' + iclass.package + '.' + iclass.name)
    print('\n\nMethods')

    for m in iclass.methods:
        print('\n' + m.name + ' (' + str(m.instrs) + ' instrs)')
        print('max depth: ' + str(m.cfg.max_depth()))
        for pc in sorted(m.features):
            print('   ' + str(pc).rjust(3) + '  ' + str(m.features[pc]))
