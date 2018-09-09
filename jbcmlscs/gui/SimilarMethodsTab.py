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

from tkinter import ttk
from tkinter.ttk import Progressbar
from tkinter import Canvas
from tkinter import Label
from tkinter import LEFT, RIGHT, W

from contextlib import contextmanager

from jbcmlscs.features.JClassFeatures import JClassFeatures
from jbcmlscs.index.JClassMd5Index import JClassMd5Index
from jbcmlscs.index.JJarMd5Index import JJarMd5Index
from jbcmlscs.index.JJarNames import JJarNames
from jbcmlscs.index.JClassNameIndex import JClassNameIndex
from jbcmlscs.index.JPackageIndex import JPackageIndex
from jbcmlscs.index.JClassMd5Xref import JClassMd5Xref

from jbcmlscs.gui.MethodInfoTab import MethodInfoTab
from jbcmlscs.gui.ExtendedLabel import ExtendedLabel

class SimilarMethodsTab():

    def __init__(self, parent, fpath):
        self.myParent = parent
        self.tab = ttk.Frame(parent)

        self.tab.grid(sticky='news')
        self.canvas_frame = ttk.Frame(self.tab)
        self.canvas = Canvas(self.canvas_frame, bg="yellow")
        self.scrollbar = ttk.Scrollbar(self.canvas_frame, orient="vertical", command=self.canvas.yview)
        self.label_frame = ttk.Frame(self.canvas)

        self.seqlabels = []
        self.progressbars = []
        self.methodlabels = []
        self.jarlabels = []

        self.fpath = fpath
        if fpath != None:
            self.classmd5index = JClassMd5Index(fpath)             # cmd5 -> cmd5 index
            self.jarmd5index = JJarMd5Index(fpath)                 # jmd5 -> jmd5 index
            self.packageindex = JPackageIndex(fpath)               # package name ->  pck index
            self.classnameindex = JClassNameIndex(fpath)           # class name -> class name index
            self.classmd5xref = JClassMd5Xref(fpath)               # cmd5 -> (pck index, cnix)

    def configure(self):
        self.canvas_frame.grid(row=0, column=0, pady=(5, 0), sticky='nw')
        self.canvas_frame.grid_rowconfigure(0, weight=1)
        self.canvas_frame.grid_columnconfigure(0, weight=1)
        self.canvas_frame.grid_propagate(False)

        self.canvas.grid(row=0, column=0, sticky="news")

        self.scrollbar.grid(row=0, column=1, sticky='ns')
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.create_window((0, 0), window=self.label_frame, anchor='nw')

    def build(self, results):
        row = 1
        maxfqmethodname = sorted([len(m['fqmethodname']) for m in results['methods'] ],reverse=True)[0]
        maxjars = sorted([len(m['jarnames']) for m in results['methods'] ],reverse=True)[0]
        for m in sorted(results['methods'],key=lambda m:m['score'],reverse=True):
            seqlabel = Label(self.label_frame,text=str(row),font=('Monaco',12),
                                 anchor=W,width=2,justify=RIGHT,padx=5)
            self.seqlabels.append(seqlabel)
            seqlabel.grid(column=0,row=row)
            bar = Progressbar(self.label_frame,length=200,style='black.Horizontal.TProgressbar')
            bar['value'] = m['score'] * 100.0
            self.progressbars.append(bar)
            bar.grid(column=1,row=row)
            methodlabel = ExtendedLabel(m['package'] + '.' + m['classname'], m['methodname'],
                                self.label_frame, text=m['fqmethodname'],
                                font=('Monaco',12),
                                anchor=W,width=maxfqmethodname,
                                justify=LEFT,padx=5)
            #methodlabel = Label(self.label_frame,text=m['fqmethodname'],
            #                    font=('Monaco',12),
            #                    anchor=W,width=maxfqmethodname,
            #                    justify=LEFT,padx=5)
            jarlabel = Label(self.label_frame,text=m['jarnames'],
                                 font=('Monaco',12),
                                 anchor=W,
                                 width=maxjars,justify=LEFT)
            self.methodlabels.append(methodlabel)
            self.jarlabels.append(jarlabel)
            methodlabel.grid(column=2,row=row)
            methodlabel.bind("<Button-1>", self.methodlabelclick)
            jarlabel.grid(column=3,row=row)
            row += 1

    def calculate_sizes(self):
        rowcount = min(30, len(self.seqlabels))
        labels_width = self.seqlabels[0].winfo_width() + \
            self.progressbars[0].winfo_width() + \
            self.methodlabels[0].winfo_width() + \
            self.jarlabels[0].winfo_width()
        labels_height = sum([self.seqlabels[i].winfo_height() for i in range(rowcount)])

        #self.canvas_frame.config(width=labels_width + self.scrollbar.winfo_width())
        self.canvas_frame.config(width=labels_width + self.scrollbar.winfo_width(), height=labels_height)
        self.canvas.config(scrollregion=self.canvas.bbox("all"))

    def methodlabelclick(self, event):
        if self.fpath != None:
            classname = event.widget.get_classname()
            methodname = event.widget.get_methodname()
            new_tab = MethodInfoTab(self.myParent, self, classname, methodname)
