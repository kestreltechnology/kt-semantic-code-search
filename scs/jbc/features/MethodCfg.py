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

from scs.jbc.features.CfgBlock import CfgBlock

class MethodCfg():

    def __init__(self,imethod,xnode):
        self.imethod = imethod
        self.xnode = xnode
        self.blocks = {}
        self.edges = {}
        self._initialize()

    def get_loop_nesting_level(self,pc):
        if self.has_loops():
            b = self.get_block(pc)
            if not b is None: return len(b.looplevels)
        return 0

    def get_cyclomatic_complexity(self):
        if self.xnode is None: return 1
        if self.imethod.obsolete: return (-1)
        nhandlers = len(self.imethod.handlers)
        nreturns = self.imethod.get_return_instructions()
        nthrows = self.imethod.get_throw_instructions()
        return (len(self.edges) - len(self.blocks)
                    + (2 * (nhandlers + nreturns + nthrows)))

    def levels(self,pc):
        if self.has_loops():
            b = self.get_block(pc)
            if not b is None:
                return ('L' * len(b.looplevels))
            else:
                print('No block found for pc = ' + str(pc) + ' in method '
                          + self.imethod.iclass.package + '.'
                          + self.imethod.iclass.name + '.'
                          + self.imethod.name)
        return ''

    def get_block(self,pc):
        for b in sorted(self.blocks):
            if pc >= b and pc <= self.blocks[b].lastpc: return self.blocks[b]
        else: return None

    def has_loops(self):
        if len(self.blocks) == 0: return False
        return (any([ len(b.looplevels) > 0 for b in self.blocks.values() ]))

    def max_depth(self):
        if len(self.blocks) == 0:  return 0
        return max( [ len(b.looplevels) for b in self.blocks.values() ])

    def _initialize(self):
        if self.xnode is None: return
        for b in self.xnode.find('blocks').findall('bb'):
            pcs = [ int(x) for x in b.get('p').split(',') ]
            self.blocks[pcs[0]] = CfgBlock(self,b,pcs[0],pcs[1])
        for e in  self.xnode.find('edges').findall('e'):
            pcs = [ int(x) for x in e.get('p').split(',') ]
            self.edges[pcs[0]] = pcs[1]
