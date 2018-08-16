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

from jbcmlscs.index.JDocuments import JDocuments
from jbcmlscs.index.JPackageIndex import JPackageIndex
from jbcmlscs.index.JPackageDigest import JPackageDigest
from jbcmlscs.index.JData import JData

def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('indexpath',help='indexed features base directory')
    parser.add_argument
    args = parser.parse_args()
    return args


if __name__ == '__main__':

    args = parse()

    packageindex = JPackageIndex(args.indexpath)
    pckdigest = JPackageDigest(args.indexpath)

    for (pckmd5,pckix) in packageindex.getmd5ixs():
        docs = JDocuments(args.indexpath,pckmd5)
        data = JData(args.indexpath,pckmd5)
        pckdigest.setdigest(pckix,data.digest(docs.size()))

    pckdigest.save()
                                
        
    
