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

import os
import json

import jbcmlscs.util.fileutil as UF

class JClassMd5Xref():

    def __init__(self,indexpath):
        self.indexpath = indexpath
        self.xref = UF.loadclassmd5xref(self.indexpath)

    def addxref(self,cmd5ix,packageix,classix):
        if cmd5ix in self.xref:
            (pckix,clix) = self.xref[cmd5ix]
            if pckix == packageix and clix == classix:
                return
            else:
                print('Encountered class md5 with different classname and package')
        else:
            self.xref[cmd5ix] = (packageix,classix)

    def getcmd5ix(self,pckix,cnix):
        print(str(pckix) + ',' + str(cnix))
        invindex = { (pckix,cnix): v for (v,[pckix,cnix] ) in  self.xref.items() }
        if (pckix,cnix) in invindex: return int(invindex[ (pckix,cnix) ])

    def save(self): UF.saveclassmd5xref(self.indexpath,self.xref)
