# ------------------------------------------------------------------------------
# Python API to access CodeHawk Java Analyzer analysis results
# Author: Henny Sipma, Andrew McGraw
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

from tkinter import *
from tkinter.ttk import Progressbar
from tkinter import ttk

from contextlib import contextmanager

class TermWeightsTab():

    def __init__(self, parent):
        self.myParent = parent
        self.tab = ttk.Frame(parent)

        self.tab.grid(sticky='news')

    def build(self, results, featuresets):
        row = 1
        maxweight = sorted([ f['score'] for f in results['weights'] ],reverse=True)[0]
        maxwidth = sorted([ len(f['feature']) for f in results['weights'] ], reverse=True)[0]
        for s in sorted(featuresets):
            if any([ f['featureset'] == s for f in results['weights'] ]):
                lbl = Label(self.tab, text=s,font=('Monaco',16),anchor=W,width=25,justify=LEFT)
                lbl.grid(columnspan=2,row=row, sticky='w')
                row += 1
            for f in sorted(results['weights'],key=lambda f:f['score'],reverse=True):
                if f['featureset'] == s:
                    bar = Progressbar(self.tab,length=200,style='black.Horizontal.TProgressbar')
                    bar['value'] = f['score'] * (100.0 / maxweight)
                    bar.grid(column=0,row=row)
                    lbl = Label(self.tab, text=f['feature'],
                                    font=("Monaco", 12),anchor=W,width=maxwidth,justify=LEFT)
                    lbl.grid(column=1,row=row)
                    row += 1
