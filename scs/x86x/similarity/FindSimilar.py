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

from scipy.sparse import dok_matrix
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.metrics.pairwise import cosine_similarity
from scipy import mat

from scs.x86x.retrieval.IndexedPostings import IndexedPostings
from scs.x86x.retrieval.IndexedVocabulary import IndexedVocabulary

class FindSimilar(object):

    def __init__(self,searchindex,searchterms):
        self.searchindex = searchindex
        self.searchterms = searchterms
        self.featuresets = self.searchterms.get_featuresets()
        self.postings = {}
        self.vocabulary = {}
        self.weightings = {}
        self.similarity = {}
        self._initialize(self.featuresets)

    def search(self):
        doccount = self.searchindex.get_doc_count()
        termcount = self.searchterms.get_term_count()
        print('Creating a ' + str(doccount) + ' by ' + str(termcount) + ' matrix')
        xpattern = self.searchterms.get_expanded_pattern(self.vocabulary)
        print('Expanded pattern: ' + str(xpattern))
        self.dokmatrix = dok_matrix((doccount,termcount),dtype=int)
        self.docids = list(self.searchindex.get_doc_ids())
        for dx in range(doccount):
            tx = 0
            for fs in sorted(xpattern):
                for termix in xpattern[fs]:
                    if self.postings[fs].has_term(self.docids[dx],termix):
                        self.dokmatrix[dx,tx] = 1
                        self.postings[fs].use_term(self.docids[dx],termix)
                    tx += 1
        tfidf = TfidfTransformer(norm='l2',smooth_idf=True)
        tfidf.fit(self.dokmatrix)
        self.set_weightings(xpattern,tfidf.idf_)
        self.similarity = cosine_similarity(mat([tfidf.idf_]),self.dokmatrix)

    def set_weightings(self,xpattern,idfvector):
        index = 0
        for fs in sorted(xpattern):
            for termix in xpattern[fs]:
                t = self.vocabulary[fs].get_term(termix)
                self.weightings[index] = (idfvector[index],t,fs)
                index += 1

    def get_similarity_results_properties(self,propertyformats,mincutoff=0.0,maxcutoff=1.0):
        qresults = []
        featuresets = propertyformats.get_featuresets()
        self._initialize(featuresets)
        for i in range(self.searchindex.get_doc_count()):
            if self.similarity[0,i] >= mincutoff and self.similarity[0,i] <= maxcutoff:
                qresults.append((i,self.similarity[0,i]))
        results = {}        # fs -> docix - > termix -> count
        for i in range(len(qresults)):
            docix = self.docids[qresults[i][0]]
            for fs in featuresets:
                if fs in self.vocabulary and fs in self.postings:
                    results.setdefault(fs,{})
                    results[fs][docix] = self.postings[fs].get_doc_term_frequency(docix)
        properties = {}   # fs -> termix -> count
        for fs in results:
            properties[fs] = {}
            for docix in results[fs]:
                for termix in results[fs][docix]:
                    properties[fs].setdefault(termix,0)
                    properties[fs][termix] += results[fs][docix][termix]
        xproperties = {}
        for fs in properties:
            xproperties[fs] = {}
            for termix in properties[fs]:
                term = self.vocabulary[fs].get_term(int(termix))
                xproperties[fs][term] = properties[fs][termix]
        return xproperties
        
    def get_similarity_results_structured(self,mincutoff=0.0,maxcutoff=1.0):
        qresults = []
        for i in range(self.searchindex.get_doc_count()):
            if self.similarity[0,i] >= mincutoff and self.similarity[0,i] <= maxcutoff:
                qresults.append((i,self.similarity[0,i]))
        qresults = sorted(qresults,key=lambda x:x[1],reverse=True)
        results = []
        for i in range(len(qresults)):
            docix = self.docids[qresults[i][0]]
            document = self.searchindex.get_document(docix)
            results.append((qresults[i][1],document))
        return results

    def _initialize(self,featuresets):
        for fs in featuresets:
            fsvoc = self.searchindex.get_featureset_vocabulary(fs)
            if not fsvoc is None:
                self.vocabulary[fs] = IndexedVocabulary(fsvoc)
            fspostings = self.searchindex.get_all_featureset_postings(fs)
            self.postings[fs] = IndexedPostings(fspostings)

