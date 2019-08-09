# ------------------------------------------------------------------------------
# Python API to access CodeHawk Binary Analyzer analysis results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2019 Kestrel Technology LLC
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

import json
import os

class SearchIndex(object):

    def __init__(self,path):
        self.path = path
        self.docindexdir = os.path.join(self.path,'docindex')
        self.vocabularydir = os.path.join(self.path,'vocabulary')
        self.postingsdir = os.path.join(self.path,'postings')
        self.indexfiles = {}

    def get_docindex_file(self,index):
        if index in self.indexfiles:
            return self.indexfiles[index]
        filename = os.path.join(self.docindexdir,index + '.json')
        if os.path.isfile(filename):
            with open(filename,'r') as fp:
                self.indexfiles[index] = json.load(fp)
                return self.indexfiles[index]
        else:
            print('Docindex file ' + filename + ' not found')

    def get_doc_count(self): return len(self.get_xmd5_index())

    def get_xmd5_index(self):
        return self.get_docindex_file('xmd5s')

    def get_doc_ids(self): return self.get_xmd5_index().values()

    def get_xmd5_xref(self):
        return self.get_docindex_file('xmd5xref')

    def get_document(self,docix):
        return self.get_xmd5_xref()[str(docix)]

    def get_featureset_vocabulary(self,fs):
        vdir = self.vocabularydir
        filename = os.path.join(vdir,fs + '.json')
        if os.path.isfile(filename):
            with open(filename,'r') as fp:
                return json.load(fp)
        else:
            print('Vocabulary file ' + filename + ' not found')

    def get_all_featureset_postings(self,fs):
        pdir = self.postingsdir
        filename = os.path.join(pdir,fs + '.json')
        if os.path.isfile(filename):
            with open(filename,'r') as fp:
                return json.load(fp)
        else:
            print('Postings file ' + filename + ' not found')
    
