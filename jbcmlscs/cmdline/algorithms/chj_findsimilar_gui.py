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
from tkinter import filedialog
 
from contextlib import contextmanager

from jbcmlscs.retrieval.JIndexJar import JIndexJar
from jbcmlscs.similarity.JPattern import JPattern
from jbcmlscs.similarity.JFindSimilar import JFindSimilar

from jbcmlscs.gui.SimilarMethodsTab import SimilarMethodsTab
from jbcmlscs.gui.TermWeightsTab import TermWeightsTab
from jbcmlscs.gui.MethodInfoTab import MethodInfoTab

#featuresets = [ 'branch-conditions-v', 'branch-conditions-vmcfs',
#                    'method-assignments-vmcfs', 'method-assignments-vmcfsi','signatures','sizes']

featuresets = [ 'assigns', 'exprs', 'conditions', 'literals', 'inloop-assigns', 'inloop-conditions', 'inloop-exprs', 'signatures', 'return' ]

def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('indexedfeaturesjar',help='indexedcorpus jarfile')
    parser.add_argument('pattern',help='json file with feature patterns')
    parser.add_argument('--featurespath',default=None,help='directory that holds the features')
    parser.add_argument('--packages',nargs='*',
                        help='restrict query to the class files with these package names')
    args = parser.parse_args()
    return args

@contextmanager
def timing():
    t0 = time.time()
    yield
    print('Completed in ' + str(time.time() - t0) + ' secs')

class findSimilar():
    def __init__(self, parent, jindexjar, fpath, packages, pattern):
        self.featuresets = featuresets

        self.myParent = parent
        self.notebook = ttk.Notebook(self.myParent)
        self.add_menu() 

        self.packages = packages
        self.pattern = pattern
        self.jindexjar = jindexjar
        self.jquery = get_query(jindexjar, packages, pattern)
        self.fpath = fpath

        self.tab1 = None
        self.tab2 = None

        self.build_tabs(self.jquery)

    def build_tabs(self, jquery):
        results = get_results(jquery) 

        self.tab1 = TermWeightsTab(self.notebook) 
        self.tab2 = SimilarMethodsTab(self.notebook, self.fpath)

        self.configure_root()
        self.tab2.configure()
        self.tab1.build(results, featuresets)
        self.tab2.build(results)

        self.tab2.label_frame.update_idletasks()
        self.tab2.calculate_sizes()

        self.notebook.add(self.tab1.tab, text='term weights') 
        self.notebook.add(self.tab2.tab, text='results')

        self.notebook.pack(expand=1, fill='both')

    def configure_root(self):
        self.myParent.grid_rowconfigure(0, weight=1)
        self.myParent.columnconfigure(0, weight=1)
        self.myParent.title('Similarity results for ' + self.pattern)
        self.myParent.geometry('1400x800')

        style = ttk.Style()
        style.theme_use('default')
        style.configure('black.Horizontal.TProgressBar',background='blue')
        style.configure('.', font=('Monaco', 16))

    def add_menu(self):
        menubar = Menu(self.myParent)
        filemenu = Menu(menubar, font=('MS Sans Serif', 14), tearoff=0)
        filemenu.add_command(label="Open", command=self.load_query)
        filemenu.add_command(label="Close", command=self.close_tab)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self.myParent.quit)
        menubar.add_cascade(label="File", font=('MS Sans Serif', 14), menu=filemenu)
        self.myParent.config(menu=menubar)

    def load_query(self):
        pattern = str(filedialog.askopenfile(parent=self.myParent,mode='rb',title='Choose a file').name)
        self.pattern = pattern
        jquery = get_query(self.jindexjar, self.packages, pattern) 
        self.build_tabs(jquery)

    def close_tab(self):
        current_tab = self.notebook.select()
        self.notebook.forget(current_tab) 

def load_index(args):
    with timing():
        print('\nLoading the corpus ...')
        jindexjar = JIndexJar(args.indexedfeaturesjar)
    return jindexjar

def get_query(jindexjar, packages, pattern):
    with timing():
        print('\nLoading the corpus ...')
        pcks = jindexjar.getallpckmd5s(packages)
        jpattern = JPattern(pattern)
        jquery = JFindSimilar(jindexjar,jpattern,pcks)
    return jquery

def get_results(jquery):
    with timing():
        print('\n\nConstructing the query matrices ...')
        jquery.search()
    weightings = jquery.getweightings()
    similarityresults = jquery.getsimilarityresults_structured(count=100)

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

    return results


if __name__ == '__main__':
    args = parse()
    
    jindexjar = load_index(args)

    window = Tk()
    myapp = findSimilar(window, jindexjar, args.featurespath, args.packages, args.pattern)
    window.mainloop()

    # print(json.dumps(results,indent=4,sort_keys=True))          
