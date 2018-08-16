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

class JJarMd5Xref():
    '''Related jar md5 indices to the class md5 indices in the jar.'''

    def __init__(self,indexpath):
        self.indexpath = indexpath
        self.xref = UF.loadjarmd5xref(self.indexpath)

    def addxref(self,jmd5ix,cmd5ix):
        if not jmd5ix in self.xref:
            self.xref[jmd5ix] = []
        if not (cmd5ix in self.xref[jmd5ix]):
            self.xref[jmd5ix].append(cmd5ix)

    def getjarclassindices(self,jmd5ix):
        if jmd5ix in self.xref: return self.xref[jmd5ix]

    def getjarixsforclassix(self,cmd5ix):
        result = []
        for jarix in self.xref:
            if cmd5ix in self.xref[jarix]: result.append(jarix)
        return result

    def save(self): UF.savejarmd5xref(self.indexpath,self.xref)
            
