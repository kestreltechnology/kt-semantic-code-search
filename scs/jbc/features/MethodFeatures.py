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

from scs.jbc.features.ExceptionHandler import ExceptionHandler
from scs.jbc.features.FeatureContext import FeatureContext
from scs.jbc.features.MethodCfg import MethodCfg

class MethodFeatures():

    def __init__(self,iclass,xnode):
        self.iclass = iclass
        self.xnode = xnode
        self.name = self.xnode.get('name')
        self.instrs = 0
        self.native = 'native' in self.xnode.attrib and self.xnode.get('native') == 'yes'
        # no features generated if the method uses jsr instructions (obsolete)
        self.obsolete = 'obsolete' in self.xnode.attrib and self.xnode.get('obsolete') == 'yes'
        if 'instrs' in self.xnode.attrib:
            self.instrs = int(self.xnode.get('instrs'))
        self.features = {}
        self.cfg = MethodCfg(self,self.xnode.find('cfg'))
        self.handlers = []
        self._initialize()

    def levels(self,pc): return self.cfg.levels(pc)

    def get_return_instructions(self):
        result = 0
        for pc in  self.features:
            if self.features[pc].is_return_stmt(): result += 1
        return result

    def get_throw_instructions(self):
        result = 0;
        for pc in self.features:
            if self.features[pc].is_throw_stmt(): result += 1
        return result

    def get_conditions(self):
        result = 0
        for pc in self.features:
            if self.features[pc].is_condition(): result += 1
        return result

    def get_loop_nesting_level(self,pc): return self.cfg.get_loop_nesting_level(pc)

    def get_signature(self):
        return str(self.iclass.dictionary.get_ms(int(self.xnode.get('ims'))).get_signature_string())

    def get_feature_terms(self,recorder):
        recorder.reset()
        recorder.record_methodname(self.name)
        recorder.record_max_loop_depth(self.cfg.max_depth())
        recorder.record_cyclomatic_complexity(self.cfg.get_cyclomatic_complexity())
        recorder.record_condition_count(self.get_conditions())
        size = 'xxsmall'
        if self.native: size = 'native'
        if self.instrs >= 5 and self.instrs < 20: size = 'xsmall'
        if self.instrs >= 20 and self.instrs < 100: size = 'small'
        if self.instrs >= 100 and self.instrs < 1000: size = 'medium'
        if self.instrs >= 1000 and self.instrs < 5000: size = 'large'
        if self.instrs >= 5000 and self.instrs < 10000: size = 'xlarge'
        if self.instrs >= 10000: size = 'xxlarge'
        recorder.record_size(size)
        for (pc,f) in self.features.items():
            context = FeatureContext(self,pc)
            f.record_features(recorder,context)

    def get_db_feature_terms(self):
        result = {}
        result['callees'] = {}
        result['classnames'] = {}
        result['packages'] = {}
        result['methodnames'] = {}
        result['stringargs'] = {}
        for (pc,f) in self.features.items():
            f.record_db_features(result,len(self.levels(pc)))
        return result


    def _initialize(self):
        for n in self.xnode.find('features').findall('fx'):
            pc = int(n.get('pc'))
            fx = self.iclass.dictionary.get_fxfeature(int(n.get('f')))
            self.features[pc] = fx
        xhandlers = self.xnode.find('handlers')
        if not xhandlers is None:
            for xh in xhandlers.findall('h'):
                self.handlers.append(ExceptionHandler(self,xh))
