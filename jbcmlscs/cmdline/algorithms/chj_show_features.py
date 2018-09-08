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

import argparse
import os
import time

from contextlib import contextmanager

import jbcmlscs.util.fileutil as UF

from jbcmlscs.features.JClassFeatures import JClassFeatures
from jbcmlscs.index.JClassMd5Index import JClassMd5Index
from jbcmlscs.index.JJarMd5Index import JJarMd5Index
from jbcmlscs.index.JJarManifest import JJarManifest
from jbcmlscs.index.JJarNames import JJarNames
from jbcmlscs.index.JClassNameIndex import JClassNameIndex
from jbcmlscs.index.JPackageIndex import JPackageIndex
from jbcmlscs.index.JClassMd5Xref import JClassMd5Xref


from jbcmlscs.ifeatures.IClassFeatures import IClassFeatures

@contextmanager
def timing():
    t0 = time.time()
    yield
    print('Completed all jarfiles in ' + str(time.time() - t0))

def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('featurespath',help='directory that holds the features')
    parser.add_argument('classname',help='fully qualified classnname')
    parser.add_argument('methodname',help='name of the method')
    args = parser.parse_args()
    return args

if __name__ == '__main__':

    args = parse()
    fpath = args.featurespath

    classmd5index = JClassMd5Index(fpath)             # cmd5 -> cmd5 index
    jarmd5index = JJarMd5Index(fpath)                 # jmd5 -> jmd5 index
    packageindex = JPackageIndex(fpath)               # package name ->  pck index
    classnameindex = JClassNameIndex(fpath)           # class name -> class name index
    classmd5xref = JClassMd5Xref(fpath)               # cmd5 -> (pck index, cnix)
    jarmanifest = JJarManifest(fpath)                   # jmd5 -> pckix -> cmd5ix

    names = args.classname.split('.')
    package = '.'.join(names[:-1])
    cn = names[-1]
    pckix = packageindex.getpckix(package)
    if pckix is None:
        print('package ' + package + ' not found')
        exit(-1)
    cnix = classnameindex.getcnix(cn)
    if cnix is None:
        print('classname ' + cn + ' not found')
        exit(-1)

    cmd5ix = classmd5xref.getcmd5ix(pckix,cnix)
    if cmd5ix is None:
        print('Error: no class found for ' + args.classname)
        exit(-1)

    cmd5 = classmd5index.getcmd5(cmd5ix)
    if cmd5 is None:
        print('Error: no cmd5 found for ' + args.classname + ' (cmd5ix = ' + str(cmd5ix))
        exit(-1)

    xclass = UF.load_features_file(args.featurespath,cmd5)
    iclass = IClassFeatures(xclass)
    print(iclass.package + '.' + iclass.name)
    for m in iclass.methods:
        if m.name == args.methodname or args.methodname == 'all':
            maxdepth = m.cfg.max_depth()
            print('\n  ' + m.name + ' (' + str(m.instrs) + ')')
            print('   max depth: ' + str(maxdepth))
            for pc in sorted(m.features):
                print('     ' + str(pc).rjust(3) + '  '
                        + str(m.levels(pc)).rjust(maxdepth) + '  ' + str(m.features[pc]))
