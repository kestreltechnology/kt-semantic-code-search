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
import hashlib
import json
import os
import subprocess
import time

from tkinter import * 
from tkinter.ttk import Progressbar 
from tkinter import ttk

from contextlib import contextmanager

from jbcmlscs.retrieval.JIndexJar import JIndexJar
from jbcmlscs.similarity.JPattern import JPattern
from jbcmlscs.similarity.JFindSimilar import JFindSimilar

featuresets = [ 'branch-conditions-v', 'branch-conditions-vmcfs',
                    'method-assignments-vmcfs', 'method-assignments-vmcfsi','signatures','sizes']

def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('indexedfeaturesjar',help='indexedcorpus jarfile')
    parser.add_argument('pattern',help='json file with feature patterns')
    parser.add_argument('--packages',nargs='*',
                        help='restrict query to the class files with these package names')
    args = parser.parse_args()
    return args

@contextmanager
def timing():
    t0 = time.time()
    yield
    print('Completed in ' + str(time.time() - t0) + ' secs')


if __name__ == '__main__':

    args = parse()
    with timing():
        print('\nLoading the corpus ...')
        jindexjar = JIndexJar(args.indexedfeaturesjar)
        pcks = jindexjar.getallpckmd5s(args.packages)
        jpattern = JPattern(args.pattern)
        jquery = JFindSimilar(jindexjar,jpattern,pcks)
    with timing():
        print('\n\nConstructing the query matrices ...')
        jquery.search()
    weightings = jquery.getweightings()
    similarityresults = jquery.getsimilarityresults_structured(count=30)

    results = {}
    results['methods'] = []
    results['weights'] = []
    
    for r in sorted(weightings):
        w = weightings[r]
        weighting = {}
        weighting['score'] = w[0]
        weighting['feature'] = w[1]
        weighting['featureset'] = w[2]
        results['weights'].append(weighting)

    for (r,package,classname,methodname,signature,jarnames) in similarityresults:
        shortsignature = signature if len(signature) < 10 else '(...)'
        m = {}
        m['score'] = r
        m['package'] = package
        m['classname'] = classname
        m['methodname'] = methodname
        m['signature'] = signature
        m['jarnames'] = ','.join(jarnames)
        m['fqmethodname'] = (package + '.' + classname + '.' + methodname
                                 + shortsignature)
        results['methods'].append(m)

    window = Tk()
    window.title('Similarity results for ' + args.pattern)
    window.geometry('1400x800')
    style = ttk.Style()
    style.theme_use('default')
    style.configure('black.Horizontal.TProgressBar',background='blue')

    notebook = ttk.Notebook(window) 
    tab1 = ttk.Frame(notebook) 
    tab2 = ttk.Frame(notebook) 
    notebook.add(tab1, text='term weights') 
    notebook.add(tab2, text='results')

    row = 1
    maxweight = sorted([ f['score'] for f in results['weights'] ],reverse=True)[0]
    maxwidth = sorted([ len(f['feature']) for f in results['weights'] ], reverse=True)[0]
    for s in sorted(featuresets):
        if any([ f['featureset'] == s for f in results['weights'] ]):
            lbl = Label(tab1, text=s,font=('Monaco',16),anchor=W,width=25,justify=LEFT)
            lbl.grid(columnspan=2,row=row)
            row += 1
        for f in sorted(results['weights'],key=lambda f:f['score'],reverse=True):
            if f['featureset'] == s:
                bar = Progressbar(tab1,length=200,style='black.Horizontal.TProgressbar')
                bar['value'] = f['score'] * (100.0 / maxweight)
                bar.grid(column=0,row=row)
                lbl = Label(tab1, text=f['feature'],
                                font=("Monaco", 12),anchor=W,width=maxwidth,justify=LEFT)
                lbl.grid(column=1,row=row)
                row += 1

    row = 1
    maxfqmethodname = sorted([len(m['fqmethodname']) for m in results['methods'] ],reverse=True)[0]
    maxjars = sorted([len(m['jarnames']) for m in results['methods'] ],reverse=True)[0]
    for m in sorted(results['methods'],key=lambda m:m['score'],reverse=True):
        seqlabel = Label(tab2,text=str(row),font=('Monaco',12),
                             anchor=W,width=2,justify=RIGHT,padx=5)
        seqlabel.grid(column=0,row=row)
        bar = Progressbar(tab2,length=200,style='black.Horizontal.TProgressbar')
        bar['value'] = m['score'] * 100.0
        bar.grid(column=1,row=row)
        methodlabel = Label(tab2,text=m['fqmethodname'],
                                font=('Monaco',12),
                                anchor=W,width=maxfqmethodname,
                                justify=LEFT,padx=5)
        jarlabel = Label(tab2,text=m['jarnames'],
                             font=('Monaco',12),
                             anchor=W,
                             width=maxjars,justify=LEFT)
        methodlabel.grid(column=2,row=row)
        jarlabel.grid(column=3,row=row)
        row += 1
                
    notebook.pack(expand=1, fill='both')

    window.mainloop()

    # print(json.dumps(results,indent=4,sort_keys=True))
              