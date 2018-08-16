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

import json
import os
import zipfile

from scipy.sparse import dok_matrix
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.metrics.pairwise import cosine_similarity
from scipy import mat

import jbcmlscs.util.fileutil as UF

from jbcmlscs.similarity.JPattern import JPattern
from jbcmlscs.retrieval.JIndexedData import JIndexedData
from jbcmlscs.retrieval.JIndexedDocuments import JIndexedDocuments
from jbcmlscs.retrieval.JIndexedVocabulary import JIndexedVocabulary
from jbcmlscs.retrieval.JReverseIndex import JReverseIndex

class JFindSimilar():

    def __init__(self,jindexjar,jpattern,pckmd5s):
        self.jindexjar = jindexjar
        self.jpattern = jpattern
        self.pckmd5s = pckmd5s                  # (pckix,pckmd5) list
        self.featuresets = self.jpattern.getfeaturesets()
        reverseindex = JReverseIndex(self.jindexjar)
        self.docs = JIndexedDocuments(jindexjar.getdocuments(pckmd5s),reverseindex)
        self.data = {}              # fs -> doc-ix -> term-ix -> freq
        self.vocabulary = {}        # fs -> term -> term-ix
        self.loaded = 0             # number of data files loaded
        self.notloaded = 0          # number of data files not loaded
        for fs in self.featuresets:
            fsvoc = self.jindexjar.getfeaturesetvocabulary(fs)
            if not fsvoc is None:
                self.vocabulary[fs] = JIndexedVocabulary(fsvoc)
            else:
                print('**Warning**: Featureset ' + fs + ' not present in index jar')
            featureterms = self.jpattern.get_feature_terms(fs,self.vocabulary[fs])
            (fsloaded,fsnotloaded,fsdata) = self.jindexjar.getfeaturesetdata(pckmd5s,fs,featureterms)
            self.loaded += fsloaded
            self.notloaded += fsnotloaded
            self.data[fs] = JIndexedData(fsdata)
        self.weightings = {}
        self.similarity = {}
        print('Data files loaded/not loaded: ' + str(self.loaded) + '/' + str(self.notloaded)
                  + ' (' + '%5.1f' % ((float(self.loaded)*100.0/float(self.loaded + self.notloaded)))
                  + '% loaded)')

    def search(self):
        doccount = self.docs.getlength()
        termcount = self.jpattern.gettermcount()
        print('Creating a ' + str(doccount) + ' by ' + str(termcount) + ' matrix')
        xpattern = self.jpattern.getexpandedpattern(self.vocabulary)
        self.dokmatrix = dok_matrix((doccount,termcount),dtype=int)
        self.docids = list(self.docs.getdocids())
        for dx in range(doccount):
            tx = 0
            for fs in sorted(xpattern):
                for termix in xpattern[fs]:
                    if self.data[fs].hasterm(self.docids[dx],termix):
                        self.dokmatrix[dx,tx] = 1
                        self.data[fs].useterm(self.docids[dx],termix)
                    tx += 1
        tfidf = TfidfTransformer(norm='l2')
        tfidf.fit(self.dokmatrix)
        self.setweightings(xpattern,tfidf.idf_)
        self.similarity = cosine_similarity(mat([tfidf.idf_]),self.dokmatrix)

    def setweightings(self,xpattern,idfvector):
        index = 0
        for fs in sorted(xpattern):
            for termix in xpattern[fs]:
                t = self.vocabulary[fs].getterm(termix)
                self.weightings[index] = (idfvector[index],t,fs)
                index += 1

    def getweightings(self): return self.weightings

    def getsimilarityresults(self,count=50,cutoff=0.1,docformat='full'):
        qresults = []
        for i in range(self.docs.getlength()):
            if self.similarity[0,i] > cutoff:
                qresults.append((i,self.similarity[0,i]))
        qresults = sorted(qresults,key=lambda x:x[1],reverse=True)
        results = []
        for i in range(min(len(qresults),count)):
            docix = self.docids[qresults[i][0]]
            prdoc = self.docs.getdocumentname(docix,docformat)
            jjdoc = ' (' + ','.join(self.docs.getjarnames(docix)) + ')'
            results.append((qresults[i][1],prdoc + jjdoc))
        return results
            
            
            
