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

import argparse
import os
import subprocess

import jbcmlscs.util.fileutil as UF

from jbcmlscs.index.JAdministrator import JAdministrator

from jbcmlscs.index.JClassMd5Index import JClassMd5Index
from jbcmlscs.index.JJarMd5Index import JJarMd5Index
from jbcmlscs.index.JJarManifest import JJarManifest
from jbcmlscs.index.JJarNames import JJarNames
from jbcmlscs.index.JClassNameIndex import JClassNameIndex
from jbcmlscs.index.JPackageIndex import JPackageIndex
from jbcmlscs.index.JClassMd5Xref import JClassMd5Xref

from jbcmlscs.ifeatures.IClassFeatures import IClassFeatures

def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('featurespath',help='features base directory')
    parser.add_argument('indexedfeaturespath',help='directory to save the indexed features')
    args = parser.parse_args()
    return args

def qualifies(xclass):
    icfeatures = IClassFeatures(xclass)
    return ((icfeatures.dictionary.opcode_table.size() > 0)
                or icfeatures.dictionary.string_table.has_string('BigDecimal')
                or icfeatures.dictionary.string_table.has_string('BigInteger'))

if __name__ == '__main__':

    args = parse()

    fpath = args.featurespath
    
    classmd5index = JClassMd5Index(fpath)             # cmd5 -> cmd5 index
    jarmd5index = JJarMd5Index(fpath)                 # jmd5 -> jmd5 index
    packageindex = JPackageIndex(fpath)               # package name ->  pck index
    classnameindex = JClassNameIndex(fpath)           # class name -> class name index
    classmd5xref = JClassMd5Xref(fpath)               # cmd5 -> (pck index, cnix)
    jarmanifest = JJarManifest(fpath)                   # jmd5 -> pckix -> cmd5ix

    jadmin = JAdministrator(args.featurespath,args.indexedfeaturespath)

    classesexcluded = []

    for fjmd5ix in jarmanifest.xref:
        jmd5 = jarmd5index.getjmd5(fjmd5ix)
        if jadmin.hasjar(jmd5):
            continue
        jmd5ix = jadmin.jarmd5index.addjmd5(jmd5)
        jadmin.jarnames.addjar(jmd5ix,jarmanifest.getfiles(fjmd5ix))
        for fpckix in jarmanifest.getpckixs(fjmd5ix):
            for fcmd5ix in jarmanifest.getcmd5ixs(fjmd5ix,fpckix):
                cmd5 = classmd5index.getcmd5(fcmd5ix)
                xclass = UF.load_features_file(args.featurespath,cmd5)
                if qualifies(xclass):
                    cmd5ix = jadmin.classmd5index.addcmd5(cmd5)
                    jadmin.jmd5xref.addxref(jmd5ix,cmd5ix)
                    jadmin.add_class_ifeatures(IClassFeatures(xclass),jmd5ix)
                else:
                    classesexcluded.append(xclass.get('name') + ' (' + cmd5 + ')')

    print('\nExcluded:' + str(len(classesexcluded)) + ' classes\n')

    jadmin.savefeatures()

    (parentdir,indexbasename,jarfilename) = UF.getindexjarfilename(args.indexedfeaturespath)
    os.chdir(parentdir)
    data = os.path.join(indexbasename, 'data')
    docindex = os.path.join(indexbasename, 'docindex')
    vocabulary = os.path.join(indexbasename, 'vocabulary')
    jarcmd = ['jar', 'cf', jarfilename, data, docindex, vocabulary ]
    print(jarcmd)
    subprocess.call(jarcmd)
    
                

    

    
