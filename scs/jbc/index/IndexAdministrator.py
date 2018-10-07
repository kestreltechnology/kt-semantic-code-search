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

"""
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

It maintains the following mappings in the docindex directory of the index:
- classmd5s.json         : class md5 -> class md5 index
- classnames.json        : classname -> class name index
- classmd5xref           : class md5 index -> (package index, class name index)
- jarmd5s.json           : jar md5 -> jar md5 index
- jarnames.json          : jar md5 index -> jarname list
- jarmd5xref.json        : jar md5 index -> class md5 index list
- methodnames.json       : method name -> method name index
- packages.json          : package name -> package name index
- signatures.json        : method signature -> method signature index

For every featureset the vocabulary directory contains a file
- <featuresetname>.json  : term (feature) -> term index

For every package (directory name derived from the package name md5):
- x_documents.json       : document index -> (class md5 index, method name index, signature index)
- x_<featurename>.json   : document index -> term index -> data (frequency)
"""

import locale
import os
import subprocess
import time, hashlib, zipfile
from contextlib import contextmanager

import scs.jbc.util.fileutil as UF
import scs.jbc.index.DocumentCounter as DC

from scs.jbc.index.ClassMd5Index import ClassMd5Index
from scs.jbc.index.JarMd5Index import JarMd5Index
from scs.jbc.index.JarMd5Xref import JarMd5Xref
from scs.jbc.index.JarNames import JarNames
from scs.jbc.index.ClassNameIndex import ClassNameIndex
from scs.jbc.index.ClassMd5Xref import ClassMd5Xref
from scs.jbc.index.MethodNameIndex import MethodNameIndex
from scs.jbc.index.PackageIndex import PackageIndex
from scs.jbc.index.SignatureIndex import SignatureIndex
from scs.jbc.index.PackageDigest import PackageDigest

from scs.jbc.index.Postings import Postings
from scs.jbc.index.Documents import Documents
from scs.jbc.index.Vocabulary import Vocabulary

@contextmanager
def timing():
    t0 = time.time()
    yield
    print('Completed in ' + str(time.time() - t0))

class IndexAdministrator():

    def __init__(self,featurespath,indexpath):
        self.featurespath = featurespath
        self.indexpath = indexpath
        DC.documentcounter.initialize(self.indexpath)
 
        self.classmd5index = ClassMd5Index(self.indexpath)
        self.jarmd5index = JarMd5Index(self.indexpath)
        self.packageindex = PackageIndex(self.indexpath)
        self.classnameindex = ClassNameIndex(self.indexpath)
        self.methodnameindex = MethodNameIndex(self.indexpath)
        self.signatureindex = SignatureIndex(self.indexpath)
        self.vocabulary = Vocabulary(self.indexpath)
        self.classmd5xref = ClassMd5Xref(self.indexpath)
        self.jmd5xref = JarMd5Xref(self.indexpath)
        self.jarnames = JarNames(self.indexpath)
        self.pckdigest = PackageDigest(self.indexpath)

        self.documents = {}       #   pckmd5 -> Documents
        self.data = {}            #   pckmd5 -> Postings

    def has_jar(self,jmd5): return self.jarmd5index.has_jmd5(jmd5)

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

    def add_pck_postings(self,pckmd5):
        if not pckmd5 in self.documents:
            self.documents[pckmd5] = Documents(self.indexpath,pckmd5)
            self.data[pckmd5] = Postings(self.indexpath,pckmd5)

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

    def has_cmd5(self,cmd5): return self.classmd5index.has_cmd5(cmd5)

    def get_cmd5ix(self,cmd5): return self.classmd5index.get_cmd5ix(cmd5)

    def add_class_features(self,classfeatures,jmd5ix,recorder):
        package = classfeatures.package
        pckmd5 = hashlib.md5(package.encode(encoding=locale.getpreferredencoding(False))).hexdigest()
        self.add_pck_postings(pckmd5)
        pckdocts = self.documents[pckmd5]
        pckdata = self.data[pckmd5]
        packageix = self.packageindex.add_package(package)
        classnameix = self.classnameindex.add_classname(classfeatures.name)
        classmd5ix = self.classmd5index.add_cmd5(classfeatures.md5)
        self.classmd5xref.add_xref(classmd5ix,packageix,classnameix)
        def f(m):
            methodix = self.methodnameindex.add_methodname(m.name)
            sigix = self.signatureindex.add_signature(m.get_signature())
            docix = pckdocts.add_document(classmd5ix,methodix,sigix)
            sigtermix = self.vocabulary.add_term('signatures',m.get_signature())
            self.pckdigest.add_term(packageix,'signatures',sigtermix)
            pckdata.add_posting('signatures',docix,sigtermix,1)
            self.pckdigest.add_doc(packageix)
            m.get_feature_terms(recorder)
            featureterms = recorder.results
            for fs in featureterms:
                for t in featureterms[fs]:
                    termix = self.vocabulary.add_term(fs,t)
                    pckdata.add_posting(fs,docix,termix,featureterms[fs][t])
                    self.pckdigest.add_term(packageix,fs,termix)
        classfeatures.iter(f)

    def add_class_dbfeatures(self,iclass,jmd5ix):
        package = iclass.package
        pckmd5 = hashlib.md5(package.encode(encoding=locale.getpreferredencoding(False))).hexdigest()
        self.addpckdata(pckmd5)
        pckdocts = self.documents[pckmd5]
        pckdata = self.data[pckmd5]
        packageix = self.packageindex.addpackage(package)
        classnameix = self.classnameindex.addclassname(iclass.name)
        classmd5ix = self.classmd5index.addcmd5(iclass.md5)
        self.classmd5xref.addxref(classmd5ix,packageix,classnameix)
        def f(m):
            methodix = self.methodnameindex.addmethodname(m.name)
            sigix = self.signatureindex.addsignature(m.get_signature())
            docix = pckdocts.adddocument(classmd5ix,methodix,sigix)
            sigtermix = self.vocabulary.addterm('signatures',m.get_signature())
            self.pckdigest.add_term(packageix,'signatures',sigtermix)
            pckdata.addfeature('signatures',docix,sigtermix,1)
            self.pckdigest.add_doc(packageix)
            featureterms = m.get_db_feature_terms()   #  fs -> term -> fs
            for fs in featureterms:
                for t in featureterms[fs]:
                    termix = self.vocabulary.addterm(fs,t)
                    pckdata.addfeature(fs,docix,termix,featureterms[fs][t])
                    self.pckdigest.add_term(packageix,fs,termix)
        iclass.iter(f)
        

    def save_features(self):
        print('Saving features ... ')
        UF.create_index_directories(self.indexpath)
        # DC.readdocumentcounter(self.indexpath)

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
            DC.documentcounter.save()

    def jar_features(self):
        (parentdir,indexbasename,jarfilename) = UF.get_indexjar_filename(self.indexpath)
        os.chdir(parentdir)
        postings = os.path.join(indexbasename,'postings')
        docindex = os.path.join(indexbasename,'docindex')
        vocabulary = os.path.join(indexbasename,'vocabulary')
        documentcounter = os.path.join(indexbasename,'documentcounter.json')
        jarcmd = [ 'jar', 'cf', jarfilename, documentcounter, postings, docindex,vocabulary ]
        print(jarcmd)
        subprocess.call(jarcmd)

    def _reportchanges(self):
        result = {}
        result['packages'] = (self.packageindex.startlength,
                              self.packageindex.get_length())
        result['classes'] = (self.classmd5index.startlength,
                             self.classmd5index.get_length())
        result['classnames'] = (self.classnameindex.startlength,
                                self.classnameindex.get_length())
        result['methodnames'] = (self.methodnameindex.startlength,
                                 self.methodnameindex.get_length())
        result['signatures'] = (self.signatureindex.startlength,
                                self.signatureindex.get_length())
        print('documents: ' + str(DC.documentcounter) + ' (was '
                  + str(DC.documentcounter.previouscounter) + ')')
        print('index'.ljust(14) + 'old'.rjust(8) + 'new'.rjust(8))
        print('-' * 60)
        for name in sorted(result):
            print(name.ljust(14) + str(result[name][0]).rjust(8) + 
                  str(result[name][1]).rjust(8))
        print('')
        print('vocabulary'.ljust(30) + 'old'.rjust(10) + 'new'.rjust(10))
        print('-' * 60)
        featuresets = self.vocabulary.featuresets
        for fs in sorted(featuresets):
            print(fs.ljust(30) + str(self.vocabulary.get_start_length(fs)).rjust(10) +
                  str(self.vocabulary.get_length(fs)).rjust(10))
        oldtotal = sum([ self.vocabulary.get_start_length(fs) for fs in featuresets])
        newtotal = sum([ self.vocabulary.get_length(fs) for fs in featuresets])
        print('-' * 60)
        print('total'.ljust(30) + str(oldtotal).rjust(10) + str(newtotal).rjust(10))
        print('-' * 60)
        # print('')
        # print('Package digest:')
        # print(str(self.pckdigest))
        
        
