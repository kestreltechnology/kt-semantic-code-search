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

"""
Script that takes as input a directory that contains jar files and a directory
in which feature files are to be saved. 

Features are saved per class file, in a file in a subdirectory of featurespath:
d1/d2/d3/d4/<md5 of classfile>.xml, where d1,d2,d3,d4 are the first four digits
of the md5 of the class file.

Each jar processed is registered (with its jar-md5) in a file called 
features-jarmanifest.json, which is kept in the featurespath directory. If a jar 
is already listed in that file (recognized by the jar-md5), the file is not
processed, but the name of the jar is added to the list of files kept for that jar
(if not already present). 

Each jar in features-jarmanifest.json has a record that lists the indices of
the class files present in the jar, organized by package. The class indices
themselves are kept in the file <featurespath>/features-classmd5s.json.
"""

import argparse
import hashlib
import os
import subprocess
import time
import zipfile

from contextlib import contextmanager

import jbcmlscs.util.fileutil as UF

from jbcmlscs.util.Config import Config

from jbcmlscs.features.JClassFeatures import JClassFeatures
from jbcmlscs.index.JClassMd5Index import JClassMd5Index
from jbcmlscs.index.JJarMd5Index import JJarMd5Index
from jbcmlscs.index.JJarManifest import JJarManifest
from jbcmlscs.index.JJarNames import JJarNames
from jbcmlscs.index.JClassNameIndex import JClassNameIndex
from jbcmlscs.index.JPackageIndex import JPackageIndex
from jbcmlscs.index.JClassMd5Xref import JClassMd5Xref


@contextmanager
def timing():
    t0 = time.time()
    yield
    print('Completed all jarfiles in ' + str(time.time() - t0))

def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('jarpath',help='directory that contains the jar files')
    parser.add_argument('featurespath',help='directory to store the features')
    args = parser.parse_args()
    return args

def generate_ifeatures(chjcommand,jarname,featurespath):
    cmd = [ chjcommand , '-o', featurespath, jarname ]
    result = subprocess.call(cmd, stderr=subprocess.STDOUT)
    return result

def get_jarmd5(jarfile):
    md5 = hashlib.md5(open(jarfile,'rb').read()).hexdigest()
    return md5

def get_jar_packages(jarfile,featurespath):
    packages = {}      # pckname -> (cmd5, classname) list
    filenames = []
    try:
        jarfile = zipfile.ZipFile(jarfile,'r')
        for info in jarfile.infolist():
            filenames.append(info.filename)
        for f in filenames:
            if f.endswith('.class'):
                zfile = jarfile.read(f)
                cmd5  = hashlib.md5(zfile).hexdigest()
                filename = UF.getcmd5_filename(featurespath,cmd5)
                if os.path.isfile(filename):
                    xclass = UF.getxnode(filename,'class')
                    packagename = xclass.get('package')
                    if not packagename in packages:
                        packages[packagename] = []
                    packages[packagename].append((cmd5,xclass.get('name')))
    except zipfile.BadZipfile:
        print(jarfile + ' appears to be corrupted! Skipping.\n')
    return packages

        
if  __name__ == '__main__':

    args = parse()
    fpath = args.featurespath
    UF.createfeaturesdocdirectory(fpath)
    
    classmd5index = JClassMd5Index(fpath)             # cmd5 -> cmd5 index
    jarmd5index = JJarMd5Index(fpath)                 # jmd5 -> jmd5 index
    packageindex = JPackageIndex(fpath)               # package name ->  pck index
    classnameindex = JClassNameIndex(fpath)           # class name -> class name index
    classmd5xref = JClassMd5Xref(fpath)               # cmd5 -> (pck index, cnix)
    jarmanifest = JJarManifest(fpath)                   # jmd5 -> pckix -> cmd5ix
    
    config = Config()

    for root, dirs, files in os.walk(args.jarpath):
        for name in  files:
            if name.endswith('.jar'):
                fname = os.path.join(root,name)
                jmd5 = get_jarmd5(fname)
                jmd5ix = jarmd5index.addjmd5(jmd5)
                if jarmanifest.hasjar(jmd5ix):
                    jarmanifest.addfile(jmd5ix,name)
                    continue
                jarmanifest.addfile(jmd5ix,name)                
                generate_ifeatures(config.chjecommand,fname,args.featurespath)
                jarpackages = get_jar_packages(fname,fpath)
                for package in jarpackages:
                    pckix = packageindex.addpackage(package)
                    for (cmd5,cn) in jarpackages[package]:
                        cmd5ix = classmd5index.addcmd5(cmd5)
                        cnix = classnameindex.addclassname(cn)
                        classmd5xref.addxref(cmd5ix,pckix,cnix)
                        jarmanifest.addxref(jmd5ix,pckix,cmd5ix)

    classmd5index.save()
    jarmd5index.save()
    packageindex.save()
    classnameindex.save()
    classmd5xref.save()
    jarmanifest.save()
