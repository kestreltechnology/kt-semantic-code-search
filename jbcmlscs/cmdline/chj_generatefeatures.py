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
import time
from contextlib import contextmanager

from jbcmlscs.index.JAdministrator import JAdministrator
from jbcmlscs.index.JJarMd5Index import JJarMd5Index

import jbcmlscs.cmdline.AnalysisManager as AM
import jbcmlscs.util.fileutil as UF

@contextmanager
def timing():
    t0 = time.time()
    yield
    print('Completed all jarfiles in ' + str(time.time() - t0))

def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('jarpath',help='directory that contains the jar files of interest')
    parser.add_argument('featurespath',help='features base directory')
    parser.add_argument('--maxprocesses',help='number of jars to process in parallel', type=int, default=1)
    parser.add_argument('--noexpand',help='Don\'t descend into directories wtih suffix .jar.DC',action='store_true')
    args = parser.parse_args()
    return args

def execute_cmd(CMD):
    try:
        result = subprocess.check_output(CMD, shell=True)
        print(result)
    except subprocess.CalledProcessError as args:
        print(args.output)
        print(args)
        exit(1)
        

def generate_features_parallel(args, am, jadmin):
    with timing():
        count = 0
        for root, dirs, files in os.walk(args.jarpath, topdown=True):
            if args.noexpand:
                for dirname in dirs:
                    if dirname.endswith('.jar.DC'):
                        dirs.remove(dirname)
            for name in files:
                if name.endswith('.jar'):
                    fname = os.path.join(root, name)
                    jmd5 = am.getjarmd5(fname)
                    if jadmin.hasjar(jmd5):
                        continue
                    else:
                        jadmin.registerjarfile(fname, jmd5)
                   
                    jadmin.prep_dirs(jmd5)	
 
                    print('Generating features for jar ' + str(count) + ' ... ')
                    count += 1                

                    cmd = am.get_generatefeatures_cmd(fname)
                    while(len(multiprocessing.active_children()) >= args.maxprocesses):
                        pass

                    multiprocessing.Process(target=execute_cmd, args=(cmd,)).start()

        #Wait for feature generation to complete for all jar files
        while(len(multiprocessing.active_children()) > 0):
            pass

def generate_features(args, am, jadmin):
    with timing():
        for root, dirs, files in os.walk(args.jarpath, topdown=True):
            for name in files:
                if name.endswith('.jar'):
                    fname = os.path.join(root,name)
                    jmd5 = am.getjarmd5(fname)
                    if jadmin.hasjar(jmd5):
                        continue
                    else:
                        jadmin.registerjarfile(fname,jmd5)

                    jadmin.prep_dirs(jmd5)                    

                    try:
                        result = am.generatefeatures(fname)
                        print(result)
                    except subprocess.CalledProcessError as args:
                        print(args.output)
                        print(args)
                        exit(1)

if __name__ == '__main__':

    args = parse()
    am = AM.AnalysisManager(args.featurespath)
    jadmin = JAdministrator(args.featurespath, None)

    if args.maxprocesses > 1:
        generate_features_parallel(args, am, jadmin)
    else:
        generate_features(args, am, jadmin)
