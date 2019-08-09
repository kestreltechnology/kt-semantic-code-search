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

class IndexedPostings(object):

    def __init__(self,postings):
        self.postings = postings   # docix -> termix -> count
        self.used = {}

    def has_term(self,docix,termix):
        docix = str(docix)
        termix = str(termix)
        return (docix in self.postings and 
                termix in self.postings[docix] and self.postings[docix][termix] > 0)

    def use_term(self,docix,termix):
        docix = str(docix)
        termix = str(termix)
        self.postings[docix][termix] -= 1
        self.used.setdefault(docix,{})
        self.used[docix].setdefault(termix,0)
        self.used[docix][termix] += 1

    def get_doc_term_frequency(self,docix):
        docix = str(docix)
        result = {}
        if docix in self.used:
            for termix in self.used[docix]:
                result[termix] = self.used[docix][termix]
        if docix in self.postings:
            for termix in self.postings[docix]:
                result.setdefault(termix,0)
                result[termix] += self.postings[docix][termix]
        return result

    def get_term_frequency(self):
        result = {}
        for docix in self.postings:
            for termix in self.postings[docix]:
                if not termix in result: result[termix] = 0
                result[termix] += self.postings[docix][termix]
        return result

    def __str__(self):
        return ','.join(self.postings.keys())
        
