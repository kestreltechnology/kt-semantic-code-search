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

import argparse, os
import xml.etree.ElementTree as ET
import json

featuresetnames = [
        'sizes', 'signatures', 'branch-conditions-v', 'branch-conditions-vmcfs',
        'branch-conditions-vmcfsi', 'method-assignments-v', 'method-assignments-vmcfs',
        'method-assignments-vmcfsi', 'attrs', 'libcalls' ]

def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('queryname',help='name of query to be saved')
    parser.add_argument('classfeaturesfile',help='filename of the file with features')
    parser.add_argument('methodname',help='name of the method')
    parser.add_argument('signature',help='signature of the method')
    parser.add_argument('--featuresets', help='featuresets to be included (default: all)',
                        choices=featuresetnames,nargs='*',default=featuresetnames)
    args = parser.parse_args()
    return args

def savequery(mnode,featuresets,queryname):
    result = {}
    result['signatures'] = {}
    result['signatures'][mnode.get('sig')] = 1
    for fnode in mnode.find('method-features').findall('feature-set'):
        fsetname = fnode.get('name')
        if fsetname in featuresets:
            result[fsetname] = {}
            for bnode in fnode.findall('block'):
                for knode in bnode.findall('kv'):
                    if knode.get('k') == 'instrs': continue
                    result[fsetname][knode.get('k')] = int(knode.get('v'))
    filename = queryname + '.json'
    with open(filename,'w') as fp:
        json.dump(result,fp,sort_keys=True, indent=3)
            


if __name__ == '__main__':

    args = parse()

    xroot = ET.parse(args.classfeaturesfile).find('class')
    for mnode in xroot.find('methods').findall('method'):
        if mnode.get('name') == args.methodname:
            if mnode.get('sig') == args.signature:
                savequery(mnode,args.featuresets,args.queryname)
                exit(0)

    print('Method ' + args.methodname + ' not found in class ' + args.classfeaturesfile)
    
