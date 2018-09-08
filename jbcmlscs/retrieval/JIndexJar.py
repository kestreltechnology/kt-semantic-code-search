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
import hashlib

import jbcmlscs.util.fileutil as UF

from jbcmlscs.index.JPackageDigest import JPackageDigest

'''
Provides access to the featureset data in the index jar file.

Directory structure of the jar file:

- admin.json : contains the number of documents  (document offset)

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

- data
    - pckhash[0:2]/pckhash[2:4]/pckhash[4:32]/pckhash_<fs>.json: doc-ix -> term-x -> freq
    - pckhash[0:2]/pckhash[2:4]/pckhash[4:32]/pckhash_documents.json
                              doc-ix -> (classmd5-ix,methodname-ix,signature-ix)

- vocabulary
    - <fs>.json : term -> term-ix
'''

class JIndexJar():

    def __init__(self,jarfilename):
        self.jarfilename = jarfilename         # name of indexedfeatures jarfile
        self.indexname = os.path.basename(self.jarfilename)[:-4]   
        self.jarfile = zipfile.ZipFile(self.jarfilename,'r')
        self.jfiles = [ x.filename for x in self.jarfile.infolist() ]
        self.indexfiles = {}
        self.pckdigest = self.getpckdigest()
        self.pckdigest = JPackageDigest(None,digest=self.pckdigest)

    def getdocindexdir(self):
        return os.path.join(self.indexname,'docindex')

    def getvocabularydir(self):
        return os.path.join(self.indexname,'vocabulary')

    def getdatadir(self):
        return os.path.join(self.indexname,'data')

    def getdatapckdir(self,pckmd5):
        ddir = self.getdatadir()
        return UF.getdatadir(ddir,pckmd5,create=False)

    def getdocindexfile(self,index):
        if index in self.indexfiles:
            return self.indexfiles[index]
        ddir = self.getdocindexdir()
        filename = os.path.join(ddir,index + '.json')
        if filename in self.jfiles:
            s = self.jarfile.read(filename)
            self.indexfiles[index] = json.loads(str(s.decode('ascii')))
            return self.indexfiles[index]
        else:
            print('Docindex file ' + filename + ' not found in jar file')

    def getpackageindex(self):
        return self.getdocindexfile('packages')

    def getmd5classindex(self):
        return self.getdocindexfile('classmd5s')

    def getclassnameindex(self):
        return self.getdocindexfile('classnames')

    def getmethodnameindex(self):
        return self.getdocindexfile('methodnames')

    def getsignatureindex(self):
        return self.getdocindexfile('signatures')

    def getclassmd5xref(self):
        return self.getdocindexfile('classmd5xref')

    def getjarmd5xref(self):
        return self.getdocindexfile('jarmd5xref')

    def getjarnames(self):
        return self.getdocindexfile('jarnames')

    def getpckdigest(self):
        return self.getdocindexfile('pckdigest')

    def getfeaturesetvocabulary(self,fs):
        vdir = self.getvocabularydir()
        filename = os.path.join(vdir,fs + '.json')
        if filename in self.jfiles:
            s = self.jarfile.read(filename)
            return json.loads(str(s.decode('ascii')))
        else:
            print('Vocabulary file for ' + fs + ' not found in jar file')

    # returns (pckix,pckmd5) for all packages or those in restrict, if nonempty
    def getallpckmd5s(self,restrict=None):
        packageindex = self.getpackageindex()
        packages = list(packageindex.keys()) if restrict is None else restrict
        return [ (packageindex[x],hashlib.md5(x.encode('utf-8')).hexdigest()) for x in packages ]

    def getjarsforclassix(self,cmd5ix):
        result = []
        jarmd5xref = self.getjarmd5xref()
        for jarix in jarmd5xref:
            if cmd5ix in jarmd5xref[jarix]: result.append(jarix)
        return sum([ self.getjarnames()[jarix] for jarix in result ],[])

    def getdocuments(self,pckmd5s):
        ddict = {}
        for (pckix,pckmd5) in pckmd5s:
            ddir = self.getdatapckdir(pckmd5)
            filename = os.path.join(ddir, pckmd5 + '_documents.json')
            if filename in self.jfiles:
                s = self.jarfile.read(filename)
                ddict.update(json.loads(str(s.decode('ascii'))))
        return ddict

    def getfeaturesetdata(self,pckmd5s,fs,featureterms):
        ddict = {}
        loaded = 0
        notloaded = 0
        for (pckix,pckmd5) in pckmd5s:
            if self.pckdigest.intersects(pckix,fs,featureterms):
                ddir = self.getdatapckdir(pckmd5)
                filename = os.path.join(ddir, pckmd5 + '_' + fs + '.json')
                if filename in self.jfiles:
                    loaded += 1
                    s = self.jarfile.read(filename)
                    ddict.update(json.loads(str(s.decode('ascii'))))
            else:
                notloaded += 1
        return (loaded,notloaded,ddict)

            
            
        
        
