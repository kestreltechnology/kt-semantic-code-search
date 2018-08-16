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


class JIndexedDocuments():

    def __init__(self,docs,rindex):
        self.docs = docs          # doc-ix -> (cmd5-ix,mn-ix,sig-ix)
        self.rindex = rindex      # JReverseIndex

    def getlength(self): return len(self.docs)

    def getdocids(self): return self.docs.keys()

    def getdocument(self,docix):
        if docix in self.docs:
            (cmd5ix,mnix,sigix) = self.docs[docix]
            jarnames = self.rindex.getjarnames(cmd5ix)
            (package,classname) = self.rindex.getpackageclass(cmd5ix)
            methodname = self.rindex.getmethodname(mnix)
            signature = self.rindex.getsignature(sigix)
            return (package,classname,methodname,signature,jarnames)

    def getdocumentname(self,docix,docformat='full'):
        doc = self.getdocument(docix)
        if docformat == 'full':
            return (doc[0] + '.' + doc[1] + '.' + doc[2] + doc[3])
        if docformat == 'columns':
            return (doc[0].ljust(40) + doc[1].ljust(40) +
                    doc[2].ljust(20) + doc[3].ljust(20))
        if docformat == 'methodname':
            return doc[2]
        if docformat == 'methodsig':
            return (doc[2] + doc[3])
        if docformat == 'classmethodsig':
            return (doc[1] + '.' + doc[2] + doc[3])

    def getmethodname(self,docix):
        return self.getdocument(docix)[2]

    def getjarnames(self,docix):
        return self.getdocument(docix)[4]
