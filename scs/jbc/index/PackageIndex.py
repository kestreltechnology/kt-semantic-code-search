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

import hashlib

import scs.jbc.util.fileutil as UF

class PackageIndex():

    def __init__(self,indexpath):
        self.indexpath = indexpath
        self.index = UF.load_package_index(self.indexpath)
        self.startlength = len(self.index)

    def add_package(self,package):
        return self.index.setdefault(package,len(self.index))

    def get_pckix(self,package):
        if package in self.index: return self.index[package]

    def get_length(self): return len(self.index)

    def get_md5s(self):
        return [ hashlib.md5(x).hexdigest() for x in self.index ]

    def get_md5ixs(self):
        return [ (hashlib.md5(x).hexdigest(),self.index[x]) for x in self.index ]

    def save(self): UF.save_package_index(self.indexpath, self.index)
