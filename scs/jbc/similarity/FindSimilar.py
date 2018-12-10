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

import json
import os
import zipfile

from scipy.sparse import dok_matrix
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.metrics.pairwise import cosine_similarity
from scipy import mat

import scs.jbc.util.fileutil as UF

from scs.jbc.similarity.Pattern import Pattern
from scs.jbc.retrieval.IndexedPostings import IndexedPostings
from scs.jbc.retrieval.IndexedDocuments import IndexedDocuments
from scs.jbc.retrieval.IndexedVocabulary import IndexedVocabulary
from scs.jbc.retrieval.ReverseIndex import ReverseIndex

class FindSimilar():

    def __init__(self,indexjar,pattern,pckmd5s):
        self.indexjar = indexjar
        self.pattern = pattern
        self.pckmd5s = pckmd5s                  # (pckix,pckmd5) list
        self.featuresets = self.pattern.get_featuresets()
        reverseindex = ReverseIndex(self.indexjar)
        self.docs = IndexedDocuments(indexjar.get_documents(pckmd5s),reverseindex)
        self.postings = {}              # fs -> doc-ix -> term-ix -> freq
        self.vocabulary = {}            # fs -> term -> term-ix
        self.loaded = 0                 # number of data files loaded
        self.notloaded = 0              # number of data files not loaded
        for fs in self.featuresets:
            fsvoc = self.indexjar.get_featureset_vocabulary(fs)
            if not fsvoc is None:
                self.vocabulary[fs] = IndexedVocabulary(fsvoc)
            else:
                print('**Warning**: Featureset ' + fs + ' not present in index jar')
            featureterms = self.pattern.get_feature_terms(fs,self.vocabulary[fs])
            (fsloaded,fsnotloaded,fspostings) = self.indexjar.get_featureset_postings(pckmd5s,fs,featureterms)
            self.loaded += fsloaded
            self.notloaded += fsnotloaded
            self.postings[fs] = IndexedPostings(fspostings)
        self.weightings = {}
        self.similarity = {}
        print('Postings files loaded/not loaded: ' + str(self.loaded) + '/' + str(self.notloaded)
                  + ' (' + '%5.1f' % ((float(self.loaded)*100.0/float(self.loaded + self.notloaded)))
                  + '% loaded)')

    def search(self):
        doccount = self.docs.get_length()
        termcount = self.pattern.get_term_count()
        print('Creating a ' + str(doccount) + ' by ' + str(termcount) + ' matrix')
        xpattern = self.pattern.get_expanded_pattern(self.vocabulary)
        self.dokmatrix = dok_matrix((doccount,termcount),dtype=int)
        self.docids = list(self.docs.get_doc_ids())
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

    def get_weightings(self): return self.weightings

    def get_similarity_results(self,count=50,cutoff=0.1,docformat='full'):
        qresults = []
        for i in range(self.docs.get_length()):
            if self.similarity[0,i] > cutoff:
                qresults.append((i,self.similarity[0,i]))
        qresults = sorted(qresults,key=lambda x:x[1],reverse=True)
        results = []
        for i in range(min(len(qresults),count)):
            docix = self.docids[qresults[i][0]]
            prdoc = self.docs.get_document_name(docix,docformat)
            jjdoc = ' (' + ','.join(self.docs.get_jarnames(docix)) + ')'
            results.append((qresults[i][1],prdoc + jjdoc))
        return results

    def get_similarity_results_structured(self,count=50,cutoff=0.1):
        qresults = []
        for i in range(self.docs.get_length()):
            if self.similarity[0,i] > cutoff:
                qresults.append((i,self.similarity[0,i]))
        qresults = sorted(qresults,key=lambda x:x[1],reverse=True)
        results = []
        for i in range(min(len(qresults),count)):
            docix = self.docids[qresults[i][0]]
            (package,classname,methodname,signature,jarnames) = self.docs.get_document(docix)
            results.append((qresults[i][1],package,classname,methodname,signature,jarnames))
        return results

            
