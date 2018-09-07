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
import jbcmlscs.index.JDocumentCounter as DC

'''
Document index for a given jmd5 intended for index construction.
'''

class JDocuments():


    def __init__(self,indexpath,pckmd5):
        self.indexpath = indexpath
        self.pckmd5 = pckmd5
        self.documents = UF.loaddocumentsfile(self.indexpath,pckmd5)  # doc-ix -> (cmd5-ix, method-ix, sig-ix)

    def size(self): return len(self.documents)
        
    def adddocument(self,cmd5ix,methodix,sigix):
        docix = DC.requestdocid()
        self.documents[docix] = (cmd5ix,methodix,sigix)
        return docix

    def save(self):
        UF.savedocumentsfile(self.indexpath,self.pckmd5,self.documents)

