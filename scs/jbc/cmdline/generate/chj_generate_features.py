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
import time

from contextlib import contextmanager

import scs.jbc.util.fileutil as UF
from scs.jbc.util.Config import Config

from scs.jbc.index.FeaturesAdministrator import FeaturesAdministrator

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
        
if  __name__ == '__main__':

    args = parse()
    UF.create_features_docindex_directory(args.featurespath)
    admin = FeaturesAdministrator(args.featurespath)
    admin.generate_features(args.jarpath,Config().codehawk)
