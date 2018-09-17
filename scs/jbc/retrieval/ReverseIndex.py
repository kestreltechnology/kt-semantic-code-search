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

# def invmap(d): return { k: v for v, k in d.items() }

def invmap(d): return dict(zip(d.values(), d.keys()))

class ReverseIndex():

    def __init__(self,jindexjar):
        self.jindexjar = jindexjar
        self.packages = invmap(jindexjar.get_package_index())
        self.classmd5s = invmap(jindexjar.get_classmd5_index())
        self.classnames = invmap(jindexjar.get_classname_index())
        self.methodnames = invmap(jindexjar.get_methodname_index())
        self.signatures = invmap(jindexjar.get_signature_index())
        self.classmd5xref = jindexjar.get_classmd5_xref()
        self.jarnames = jindexjar.get_jarnames()

    def get_package(self,pckix):
        if pckix in self.packages: return self.packages[pckix]
        print('Package-ix ' + str(pckix) + ' not found in index jarfile')

    def get_classname(self,cnix):
        if cnix in self.classnames: return self.classnames[cnix]
        print('Classname-ix ' + str(cnix) + ' not found in index jarfile')

    def get_methodname(self,mnix):
        if mnix in self.methodnames: return self.methodnames[mnix]
        print('Methodname-ix ' + str(mnix) + ' not found in index jarfile')

    def get_signature(self,sigix):
        if sigix in self.signatures: return self.signatures[sigix]
        print('Signature-ix ' + str(sigix) + ' not found in index jarfile')

    def get_package_classix(self,cmd5ix):
        if str(cmd5ix) in self.classmd5xref: return self.classmd5xref[str(cmd5ix)]
        print('Class-md5-ix ' + str(cmd5ix) + ' not found in index jarfile')

    def get_package_class(self,cmd5ix):
        (pckix,cnix) = self.get_package_classix(cmd5ix)
        return (self.get_package(pckix), self.get_classname(cnix))

    def get_jarnames(self,cmd5ix): return self.jindexjar.get_jars_for_classix(cmd5ix)
