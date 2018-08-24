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
import multiprocessing

from jbcmlscs.index.JAdministrator import JAdministrator
from jbcmlscs.index.JJarMd5Index import JJarMd5Index

import jbcmlscs.cmdline.AnalysisManager as AM
import jbcmlscs.util.fileutil as UF



def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('jarpath',help='directory that contains the jar files of interest')
    parser.add_argument('featurespath',help='features base directory')
    parser.add_argument('indexedfeaturespath',help='indexed features base directory')
    parser.add_argument('--noexpand',help='don\'t descend into directories with suffix .jar.DC',action='store_true')
    parser.add_argument
    args = parser.parse_args()
    return args

def no_expand(dirnames):
    for dirname in dirnames:
        if dirname.endswith('.jar.DC'):
            dirnames.remove(dirname)
    return dirnames

def generate_indices(args, am, jadmin):
    for root, dirs, files in os.walk(args.jarpath):
        if args.noexpand:
            dirs = no_expand(dirs)
        for name in files:
            if name.endswith('.jar'):
                fname = os.path.join(root,name)
                jmd5 = am.getjarmd5(fname)
                if jadmin.hasjar(jmd5):
                    continue
                else:
                    jadmin.registerjarfile(fname,jmd5)
                jadmin.loadfeatures(jmd5)


if __name__ == '__main__':

    args = parse()
    am = AM.AnalysisManager(args.featurespath)
    jadmin = JAdministrator(args.featurespath, args.indexedfeaturespath)

    generate_indices(args, am, jadmin)

    jadmin.savefeatures()

    (parentdir,indexbasename,jarfilename) = UF.getindexjarfilename(args.indexedfeaturespath)
    os.chdir(parentdir)
    data = os.path.join(indexbasename, 'data')
    docindex = os.path.join(indexbasename, 'docindex')
    vocabulary = os.path.join(indexbasename, 'vocabulary')
    jarcmd = ['jar', 'cf', jarfilename, data, docindex, vocabulary ]
    print(jarcmd)
    subprocess.call(jarcmd)
