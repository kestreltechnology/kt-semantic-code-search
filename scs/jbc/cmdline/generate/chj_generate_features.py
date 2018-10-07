# ------------------------------------------------------------------------------
# Java byte code semantic code search
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
themselves are kept in the file <featurespath>/docindex/classmd5s.json.
"""

import argparse
import time

from contextlib import contextmanager

import scs.jbc.util.fileutil as UF
from scs.jbc.util.Config import Config

from scs.jbc.index.FeaturesAdministrator import FeaturesAdministrator

initial_counts = {
    "files": 0 ,
    "packages": 0,
    "classes": 0
    }

final_counts = {
    "files": 0,
    "packages": 0,
    "classes": 0
    }

def set_counts(admin,counts):
    mf = admin.jarmanifest
    counts['files'] = mf.file_count()
    counts['packages'] = mf.package_count()
    counts['classes'] = mf.class_count()

def get_counts(counts):
    return (str(counts['files']).rjust(10)
                + str(counts['packages']).rjust(10)
                + str(counts['classes']).rjust(10))

def get_count_increments(c1,c2):
    return (str(c2['files'] - c1['files']).rjust(10)
                + str(c2['packages'] - c1['packages']).rjust(10)
                + str(c2['classes'] - c1['classes']).rjust(10))

def report():
    lines = []
    lines.append('             files  packages  classes')
    lines.append('-' * 50)
    lines.append('initial' + get_counts(initial_counts))
    lines.append('final  ' + get_counts(final_counts))
    lines.append('-' * 50)
    lines.append('new    ' + get_count_increments(initial_counts,final_counts))
    return '\n'.join(lines)

@contextmanager
def timing():
    t0 = time.time()
    yield
    print('Completed all jarfiles in ' + str(time.time() - t0) + '\n')
    print(report())

def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('jarpath',help='directory that contains the jar files')
    parser.add_argument('featurespath',help='directory to store the features')
    args = parser.parse_args()
    return args
        
if  __name__ == '__main__':

    with timing():
        args = parse()
        UF.create_features_docindex_directory(args.featurespath)
        admin = FeaturesAdministrator(args.featurespath)
        set_counts(admin,initial_counts)
        admin.generate_features(args.jarpath,Config().codehawk)
        set_counts(admin,final_counts)
