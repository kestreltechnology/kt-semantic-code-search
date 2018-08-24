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

'''
Controls the incorporation of the features of a new jar into an existing index
or starts a new index if none exists.

It extracts the features from the class-level xml files produced by CodeHawk
for a single jar, creates indices for new package names, class names, method
names, and signatures, and creates document indices for all methods. It then
saves the feature data for this jar in newly created subdirectories per package
or, if the package already exists, adds the data to the existing data for the
package.

- featurespath: directory that holds the xml features
- indexedfeaturespath: directory that contains the index

It maintains the following mappings in the documents directory:
- classmd5s.json         : class md5 -> class md5 index
- classnames.json        : classname -> class name index
- classmd5xref           : class md5 index -> (package index, class name index)
- jarmd5s.json           : jar md5 -> jar md5 index
- jarnames.json          : jar md5 index -> jarname
- jarmd5xref.json        : jar md5 index -> class md5 index list
- methodnames.json       : method name -> method name index
- packages.json          : package name -> package name index
- signatures.json        : method signature -> method signature index

For every featureset the vocabulary directory contains a file
- <featuresetname>.json  : term (feature) -> term index

For every package (directory name derived from the package name md5):
- x_documents.json       : document index -> (class md5 index, method name index, signature index)
- x_<featurename>.json   : document index -> term index -> data (frequency)

'''
import locale
import os
import subprocess
import time, hashlib, zipfile
from contextlib import contextmanager

import jbcmlscs.util.fileutil as UF
import jbcmlscs.index.JDocumentCounter as DC

from jbcmlscs.features.JClassFeatures import JClassFeatures
from jbcmlscs.index.JClassMd5Index import JClassMd5Index
from jbcmlscs.index.JJarMd5Index import JJarMd5Index
from jbcmlscs.index.JJarMd5Xref import JJarMd5Xref
from jbcmlscs.index.JJarNames import JJarNames
from jbcmlscs.index.JClassNameIndex import JClassNameIndex
from jbcmlscs.index.JMethodNameIndex import JMethodNameIndex
from jbcmlscs.index.JPackageIndex import JPackageIndex
from jbcmlscs.index.JSignatureIndex import JSignatureIndex
from jbcmlscs.index.JPackageDigest import JPackageDigest

from jbcmlscs.index.JData import JData
from jbcmlscs.index.JDocuments import JDocuments
from jbcmlscs.index.JVocabulary import JVocabulary

from jbcmlscs.index.JClassMd5Xref import JClassMd5Xref

@contextmanager
def timing():
    t0 = time.time()
    yield
    print('Completed in ' + str(time.time() - t0))

class JAdministrator():

    def __init__(self,featurespath,indexedfeaturespath):
        self.featurespath = featurespath
        self.indexpath = indexedfeaturespath
 
        self.classmd5index = JClassMd5Index(self.indexpath)
        self.jarmd5index = JJarMd5Index(self.indexpath)
        self.packageindex = JPackageIndex(self.indexpath)
        self.classnameindex = JClassNameIndex(self.indexpath)
        self.methodnameindex = JMethodNameIndex(self.indexpath)
        self.signatureindex = JSignatureIndex(self.indexpath)
        self.vocabulary = JVocabulary(self.indexpath)
        self.classmd5xref = JClassMd5Xref(self.indexpath)
        self.jmd5xref = JJarMd5Xref(self.indexpath)
        self.jarnames = JJarNames(self.indexpath)
        self.pckdigest = JPackageDigest(self.indexpath)

        self.documents = {}       #   pckmd5 -> JDocuments
        self.data = {}            #   pckmd5 -> JData

    def hasjar(self,jmd5): return self.jarmd5index.hasjmd5(jmd5)

    def registerjarfile(self,jarfile,jmd5):
        jmd5ix = self.jarmd5index.addjmd5(jmd5)
        self.jarnames.addjar(jmd5ix,os.path.basename(jarfile))
        
        filenames = []
        print('Registering ' + jarfile + ' ...')
        try:
            jarfile = zipfile.ZipFile(jarfile,'r')
            for info in jarfile.infolist():
                filenames.append(info.filename)
            for f in filenames:
                if f.endswith('.class'):
                    zfile = jarfile.read(f)
                    cmd5 = hashlib.md5(zfile).hexdigest()
                    cmd5ix = self.classmd5index.addcmd5(cmd5)
                    self.jmd5xref.addxref(jmd5ix,cmd5ix)
        except zipfile.BadZipfile:
            print(jarfile + ' appears to be corrupted! Skipping.\n')
            
    def prep_dirs(self, jmd5):
        (jdm5ix, cmd5s) = self.get_cmd5s(jmd5)

        if cmd5s != None:
            for cmd5 in cmd5s:
                filename = UF.getmd5_1111_dir(self.featurespath, cmd5)

    def get_cmd5s(self, jmd5):
        jmd5ix = self.jarmd5index.addjmd5(jmd5)
        # print('jmd5ix = ' + str(jmd5ix))
        cmd5ixs = self.jmd5xref.getjarclassindices(jmd5ix)
        if cmd5ixs is None: return (jmd5ix, None)
        cmd5s = [ self.classmd5index.getcmd5(x) for x in cmd5ixs
                      if not self.classmd5index.getcmd5(x) is None ]
        return (jmd5ix, cmd5s)

    def loadfeatures(self,jmd5):
        (jmd5ix, cmd5s) = self.get_cmd5s(jmd5)

        count = 0
        # print('Loading features from ' + self.featurespath + ' ...')
        with timing():
            if cmd5s != None:
                for cmd5 in cmd5s:
                    filename = UF.getcmd5_filename(self.featurespath,cmd5)
                    if os.path.isfile(filename):
                        # print('read ' + filename)
                        xclass = UF.getxnode(filename,'class')
                        fclass = JClassFeatures(xclass)
                        self.addclasskeyvaluepairs(fclass,jmd5ix)
                        count += 1
                        if count % 10000 == 0: print('==> ' + str(count) + ' classes')
                    else:
                        print("Warning : " + filename + " not found\n")

    def addpckdata(self,pckmd5):
        if not pckmd5 in self.documents:
            self.documents[pckmd5] = JDocuments(self.indexpath,pckmd5)
            self.data[pckmd5] = JData(self.indexpath,pckmd5)

    def addclasskeyvaluepairs(self,fclass,jmd5ix):
        package = fclass.getpackage()
        pckmd5 = hashlib.md5(package.encode(encoding=locale.getpreferredencoding(False))).hexdigest()
        self.addpckdata(pckmd5)
        pckdocts = self.documents[pckmd5]
        pckdata = self.data[pckmd5]
        packageix = self.packageindex.addpackage(package)
        classnameix = self.classnameindex.addclassname(fclass.getclassname())
        classmd5ix = self.classmd5index.addcmd5(fclass.getmd5())
        self.classmd5xref.addxref(classmd5ix,packageix,classnameix)
        def f(m):
            methodix = self.methodnameindex.addmethodname(m.getname())
            sigix = self.signatureindex.addsignature(m.getsignature())
            docix = pckdocts.adddocument(classmd5ix,methodix,sigix)
            sigtermix = self.vocabulary.addterm('signatures',m.getsignature())
            self.pckdigest.add_term(packageix,'signatures',sigtermix)
            pckdata.addfeature('signatures',docix,sigtermix,1)
            self.pckdigest.add_doc(packageix)
            def g(fs):
                if fs.istfidf():
                    for (k,v) in fs.getkeyvaluepairs():
                        termix = self.vocabulary.addterm(fs.getname(),k)
                        pckdata.addfeature(fs.getname(),docix,termix,v)
                        self.pckdigest.add_term(packageix,fs.getname(),termix)
            m.iter(g)
        fclass.iter(f)

    def savefeatures(self):
        # print('Saving features ... ')
        UF.createindexdirectories(self.indexpath)
        DC.readdocumentcounter(self.indexpath)

        self._reportchanges()
        with timing():
            for p in self.documents: self.documents[p].save()
            self.jarmd5index.save()
            self.packageindex.save()
            self.classmd5index.save()
            self.classnameindex.save()
            self.methodnameindex.save()
            self.signatureindex.save()
            self.pckdigest.save()
            self.vocabulary.save()
            for p in self.data: self.data[p].save()
            self.classmd5xref.save()
            self.jmd5xref.save()
            self.jarnames.save()
            DC.savedocumentcounter(self.indexpath)

    def _reportchanges(self):
        result = {}
        result['packages'] = (self.packageindex.startlength,
                              self.packageindex.getlength())
        result['classes'] = (self.classmd5index.startlength,
                             self.classmd5index.getlength())
        result['classnames'] = (self.classnameindex.startlength,
                                self.classnameindex.getlength())
        result['methodnames'] = (self.methodnameindex.startlength,
                                 self.methodnameindex.getlength())
        result['signatures'] = (self.signatureindex.startlength,
                                self.signatureindex.getlength())
        print('documents: ' + str(DC.documentcounter))
        print('index'.ljust(14) + 'old'.rjust(8) + 'new'.rjust(8))
        print('-' * 60)
        for name in sorted(result):
            print(name.ljust(14) + str(result[name][0]).rjust(8) + 
                  str(result[name][1]).rjust(8))
        print('')
        print('vocabulary'.ljust(30) + 'old'.rjust(10) + 'new'.rjust(10))
        print('-' * 60)
        featuresets = self.vocabulary.getfeaturesets()
        for fs in sorted(featuresets):
            print(fs.ljust(30) + str(self.vocabulary.getstartlength(fs)).rjust(10) +
                  str(self.vocabulary.getlength(fs)).rjust(10))
        oldtotal = sum([ self.vocabulary.getstartlength(fs) for fs in featuresets])
        newtotal = sum([ self.vocabulary.getlength(fs) for fs in featuresets])
        print('-' * 60)
        print('total'.ljust(30) + str(oldtotal).rjust(10) + str(newtotal).rjust(10))
        print('-' * 60)
        # print('')
        # print('Package digest:')
        # print(str(self.pckdigest))
        
        
