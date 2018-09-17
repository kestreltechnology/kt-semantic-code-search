# ------------------------------------------------------------------------------
# Python API to access CodeHawk Java Analyzer analysis results
# Author: Andrew McGraw, Henny Sipma
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
from tkinter import Text
from tkinter import Button
from tkinter import END

from scs.jbc.features.ClassFeatures import ClassFeatures

import scs.jbc.util.fileutil as UF

class MethodInfoTab():

    def __init__(self, parent, origin, classname, methodname):
        self.myParent = parent

        self.tab = ttk.Frame(parent)
        self.tab.grid(sticky='news')

        info = self.process_info(classname, origin)
        if type(info) is str:
            full_text = info
        else:
            (pckix, cnix, cmd5ix, cmd5) = info

            lines = []

            xclass = UF.load_features_file(origin.fpath,cmd5)
            iclass = ClassFeatures(xclass)
            lines.append(iclass.package + '.' + iclass.name)
            for m in iclass.methods:
                if m.name == methodname or methodname == 'all':
                    maxdepth = m.cfg.max_depth()
                    lines.append('\n  ' + m.name + ' (' + str(m.instrs) + ')')
                    lines.append('   max depth: ' + str(maxdepth))
                    for pc in sorted(m.features):
                        lines.append('     ' + str(pc).rjust(3) + '  '
                            + str(m.levels(pc)).rjust(maxdepth) + '  ' + str(m.features[pc]))

            full_text = '\n'.join(lines)
            #max_width = max([len(line) for line in lines])

        text_widget = Text(self.tab, width=120, height=40)
        text_widget.insert(END, full_text)
        text_widget.grid(row=0, column=0, sticky='nw')

        yscrollbar = ttk.Scrollbar(self.tab, orient="vertical", command=text_widget.yview)
        yscrollbar.grid(row=0, column=1, sticky='ns')
        text_widget.configure(yscrollcommand=yscrollbar.set)

        #if max_width > 40:
        #    xscrollbar = ttk.Scrollbar(self.tab, orient="horizontal", command=text_widget.xview)
        #    xscrollbar.grid(row=1, column=0, sticky='we')
        #    text_widget.configure(xscrollcommand=xscrollbar.set)

        self.button1 = Button(self.tab)
        self.button1.configure(text="Close", background="green")
        self.button1.grid(column=0, row=2, sticky='nw')
        self.button1.bind("<Button-1>", self.closeTab)

        self.myParent.add(self.tab, text=self.make_abbrev_name(classname, methodname))

    def closeTab(self, event):
        current_tab = self.myParent.select()
        self.myParent.forget(current_tab)

    def make_abbrev_name(self, classname, methodname):
        abbrev_name = ''
        classname_segments = classname.split('.')
        for segment in classname_segments:
            abbrev_name += segment[0]
        abbrev_name = abbrev_name + '.' + methodname
        return abbrev_name

    def process_info(self, classname, origin):
        names = classname.split('.')
        package = '.'.join(names[:-1])
        cn = names[-1]
        pckix = origin.packageindex.get_pckix(package)
        if pckix is None:
            errorinfo = 'package ' + package + ' not found'
            print(errorinfo)
            return errorinfo
 
        cnix = origin.classnameindex.get_cnix(cn)
        if cnix is None:
            errorinfo = 'classname ' + cn + ' not found'
            print(errorinfo)
            return errorinfo

        cmd5ix = origin.classmd5xref.get_cmd5ix(pckix,cnix)
        if cmd5ix is None:
            errorinfo = 'Error: no class found for ' + classname
            print(errorinfo)
            return errorinfo

        cmd5 = origin.classmd5index.get_cmd5(cmd5ix)
        if cmd5 is None:
            errorinfo = 'Error: no cmd5 found for ' + classname + ' (cmd5ix = ' + str(cmd5ix)
            print(errorinfo)
            return errorinfo

        return (pckix, cnix, cmd5ix, cmd5)
