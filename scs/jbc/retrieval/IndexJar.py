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
import hashlib

import scs.jbc.util.fileutil as UF

from scs.jbc.index.PackageDigest import PackageDigest

'''
Provides access to the featureset data in the index jar file.

Directory structure of the jar file:

- documentcounter.json : contains the number of documents  (document offset)

- docindex
    - jarnames.json     : jarmd5-ix -> jarname list
    - classmd5.json     : classmd5 -> classmd5-ix
    - classmd5xref.json : classmd5-ix -> (packagename-ix, classname-ix)
    - classnames.json   : classname -> classname-ix
    - jarmd5s.json      : jarmd5 -> jarmd5-ix
    - jarmd5xref.json   : jarmd5-ix -> classmd5-ix list (classes found in jar)
    - jarnames.json     : jarmd5-ix -> jarname
    - methodnames.json  : methodname -> methodname-ix
    - packages.json     : packagename -> packagename-ix
    - signatures.json   : signature -> signature-ix

- postings
    - pckhash[0:2]/pckhash[2:4]/pckhash[4:32]/pckhash_<fs>.json: doc-ix -> term-x -> freq
    - pckhash[0:2]/pckhash[2:4]/pckhash[4:32]/pckhash_documents.json
                              doc-ix -> (classmd5-ix,methodname-ix,signature-ix)

- vocabulary
    - <fs>.json : term -> term-ix
'''

class IndexJar():

    def __init__(self,jarfilename):
        self.jarfilename = jarfilename         # name of indexedfeatures jarfile
        self.indexname = os.path.basename(self.jarfilename)[:-4]   
        self.jarfile = zipfile.ZipFile(self.jarfilename,'r')
        self.jfiles = [ x.filename for x in self.jarfile.infolist() ]
        self.indexfiles = {}
        self.pckdigest = self.get_package_digest()
        self.pckdigest = PackageDigest(None,digest=self.pckdigest)

    def get_docindex_dir(self):
        return os.path.join(self.indexname,'docindex')

    def get_vocabulary_dir(self):
        return os.path.join(self.indexname,'vocabulary')

    def get_postings_dir(self):
        return os.path.join(self.indexname,'postings')

    def get_postings_pck_dir(self,pckmd5):
        ddir = self.get_postings_dir()
        return UF.get_postings_dir(ddir,pckmd5,create=False)

    def get_docindex_file(self,index):
        if index in self.indexfiles:
            return self.indexfiles[index]
        ddir = self.get_docindex_dir()
        filename = os.path.join(ddir,index + '.json')
        if filename in self.jfiles:
            s = self.jarfile.read(filename)
            self.indexfiles[index] = json.loads(str(s.decode('ascii')))
            return self.indexfiles[index]
        else:
            print('Docindex file ' + filename + ' not found in jar file')

    def get_package_index(self):
        return self.get_docindex_file('packages')

    def get_classmd5_index(self):
        return self.get_docindex_file('classmd5s')

    def get_classname_index(self):
        return self.get_docindex_file('classnames')

    def get_methodname_index(self):
        return self.get_docindex_file('methodnames')

    def get_signature_index(self):
        return self.get_docindex_file('signatures')

    def get_classmd5_xref(self):
        return self.get_docindex_file('classmd5xref')

    def get_jarmd5_xref(self):
        return self.get_docindex_file('jarmd5xref')

    def get_jarnames(self):
        return self.get_docindex_file('jarnames')

    def get_package_digest(self):
        return self.get_docindex_file('pckdigest')

    def get_featureset_vocabulary(self,fs):
        vdir = self.get_vocabulary_dir()
        filename = os.path.join(vdir,fs + '.json')
        if filename in self.jfiles:
            s = self.jarfile.read(filename)
            return json.loads(str(s.decode('ascii')))
        else:
            print('Vocabulary file for ' + fs + ' not found in jar file')

    # returns (pckix,pckmd5) for all packages or those in restrict, if nonempty
    def get_all_pckmd5s(self,restrict=None):
        packageindex = self.get_package_index()
        packages = list(packageindex.keys()) if restrict is None else restrict
        return [ (packageindex[x],hashlib.md5(x.encode('utf-8')).hexdigest()) for x in packages ]

    def get_jars_for_classix(self,cmd5ix):
        result = []
        jarmd5xref = self.get_jarmd5_xref()
        for jarix in jarmd5xref:
            if cmd5ix in jarmd5xref[jarix]: result.append(jarix)
        return sum([ self.get_jarnames()[jarix] for jarix in result ],[])

    def get_documents(self,pckmd5s):
        ddict = {}
        for (pckix,pckmd5) in pckmd5s:
            ddir = self.get_postings_pck_dir(pckmd5)
            filename = os.path.join(ddir, pckmd5 + '_documents.json')
            if filename in self.jfiles:
                s = self.jarfile.read(filename)
                ddict.update(json.loads(str(s.decode('ascii'))))
        return ddict

    def get_featureset_postings(self,pckmd5s,fs,featureterms):
        ddict = {}
        loaded = 0
        notloaded = 0
        for (pckix,pckmd5) in pckmd5s:
            if self.pckdigest.intersects(pckix,fs,featureterms):
                ddir = self.get_postings_pck_dir(pckmd5)
                filename = os.path.join(ddir, pckmd5 + '_' + fs + '.json')
                if filename in self.jfiles:
                    loaded += 1
                    s = self.jarfile.read(filename)
                    ddict.update(json.loads(str(s.decode('ascii'))))
            else:
                notloaded += 1
        return (loaded,notloaded,ddict)

    def get_all_featureset_postings(self,pckmd5s,fs):
        ddict = {}
        for (pckix,pckmd5) in pckmd5s:
            ddir = self.get_postings_pck_dir(pckmd5)
            filename = os.path.join(ddir,pckmd5 + '_' + fs + '.json')
            if filename in self.jfiles:
                s = self.jarfile.read(filename)
                ddict.update(json.loads(str(s.decode('ascii'))))
        return  ddict

            
            
        
        
