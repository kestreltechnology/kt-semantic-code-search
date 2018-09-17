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

import scs.jbc.util.fileutil as UF

class ClassMd5Index():
    '''Maps class md5 to its local index.'''

    def __init__(self,indexpath):
        self.indexpath = indexpath
        self.index = UF.load_classmd5_index(self.indexpath)
        self.startlength = len(self.index)
        self.invindex = None

    def has_cmd5(self,cmd5): return cmd5 in self.index

    def add_cmd5(self,cmd5):
        ind = self.index.setdefault(cmd5,len(self.index))        
        return ind

    def get_length(self):
        return len(self.index)

    def get_cmd5(self,cmd5ix):
        self._revertindex()
        if cmd5ix in self.invindex:
            return self.invindex[cmd5ix]

    def save(self):
        UF.save_classmd5_index(self.indexpath, self.index)

    def _revertindex(self):
        if self.invindex is None:
            self.invindex = { v: k for (k,v) in self.index.items() }
