# ------------------------------------------------------------------------------
# Python API to access CodeHawk Java Analyzer analysis results
# Author: Andrew McGraw
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

class MethodInfoTab():

    def __init__(self, parent, info):
        self.myParent = parent

        self.tab = ttk.Frame(parent)
        self.tab.grid(sticky='news')

        self.lbl = Label(self.tab, text=info, font=('Monaco', 12), anchor=W, width=len(info), justify=LEFT)
        self.lbl.grid(column=0, row=0)

        self.button1 = Button(self.tab)
        self.button1.configure(text="Close", background="green")
        self.button1.grid(column=0, row=1, sticky='nw')
        self.button1.bind("<Button-1>", self.closeTab)

        self.myParent.add(self.tab, text='temp')

    def closeTab(self, event):
        current_tab = self.myParent.select()
        self.myParent.forget(current_tab)
