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

import math
import os
import json
import zipfile

import scs.jbc.util.fileutil as UF

from scs.jbc.retrieval.IndexedPostings import IndexedPostings
from scs.jbc.retrieval.IndexedVocabulary import IndexedVocabulary
from scs.jbc.retrieval.IndexedDocuments import IndexedDocuments
from scs.jbc.retrieval.ReverseIndex import ReverseIndex

class FeatureStats():

    def __init__(self,indexjar,pckmd5s):
        self.indexjar = indexjar
        rindex = ReverseIndex(self.indexjar)
        docs = self.indexjar.get_documents(pckmd5s)
        self.docs = IndexedDocuments(docs,rindex)
        self.pckmd5s = pckmd5s
        self.postings = None

    def get_counts(self,fs):
        postings = self.indexjar.get_all_featureset_postings(self.pckmd5s,fs)
        self.postings = IndexedPostings(postings)
        fsvoc = self.indexjar.get_featureset_vocabulary(fs)
        if not fsvoc is None:
            self.vocabulary = IndexedVocabulary(fsvoc)
        else:
            print('**Warning**: Featureset ' + fs + ' not present in index jar')

        counts = self.postings.get_term_frequency()
        doccount = self.docs.get_length()
        result = {}
        for fsix in counts:
            fsterm = self.vocabulary.get_term(int(fsix))
            ivf = math.log10(doccount)
            if counts[fsix] > 0:
                ivf = math.log10(float(doccount)/float(counts[fsix]))
            result[fsterm] = (counts[fsix],ivf)
        return result

            


        
