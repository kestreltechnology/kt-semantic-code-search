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
import scs.jbc.index.DocumentCounter as DC

class Documents():
    """Maintains a relationship between docix and cmd5ix, methodix, sigix per package

    Form of index: docix -> (cmd5ix, methodix, sigix)

    Document indices are assigned globally (across all packages) by the document
    counter.
    """

    def __init__(self,indexpath,pckmd5):
        self.indexpath = indexpath
        self.pckmd5 = pckmd5
        self.documents = UF.load_documents_file(self.indexpath,pckmd5)  

    def size(self): return len(self.documents)
        
    def add_document(self,cmd5ix,methodix,sigix):
        docix = DC.documentcounter.request_doc_id()
        self.documents[docix] = (cmd5ix,methodix,sigix)
        return docix

    def save(self):
        UF.save_documents_file(self.indexpath,self.pckmd5,self.documents)

