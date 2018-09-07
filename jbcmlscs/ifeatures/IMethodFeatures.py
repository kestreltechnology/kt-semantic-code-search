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

from jbcmlscs.ifeatures.IMethodCfg import IMethodCfg

class IMethodFeatures:

    def __init__(self,iclass,xnode):
        self.iclass = iclass
        self.xnode = xnode
        self.name = self.xnode.get('name')
        self.instrs = 0
        self.native = 'native' in self.xnode.attrib and self.xnode.get('native') == 'yes'
        if 'instrs' in self.xnode.attrib:
            self.instrs = int(self.xnode.get('instrs'))
        self.features = {}
        self.cfg = IMethodCfg(self,self.xnode.find('cfg'))
        self._initialize()

    def levels(self,pc): return self.cfg.levels(pc)

    def get_signature(self):
        return str(self.iclass.dictionary.get_ms(int(self.xnode.get('ims'))).get_signature_string())

    def get_feature_terms(self):
        result = {}
        result['exprs'] = {}
        result['assigns'] = {}
        result['conditions'] = {}
        result['literals'] = {}
        result['return'] = {}
        result['callees'] = {}
        result['inloop-assigns'] = {}
        result['inloop-conditions'] = {}
        result['inloop-returns'] = {}
        result['inloop-exprs'] = {}
        for (pc,f) in self.features.items():
            #try:
                f.record_algorithmic_features(result,len(self.levels(pc)))
            #except:
            #    print('method: ' + self.name + str(self.get_signature()) + ' ' + self.iclass.md5
            #              + ' ' + self.iclass.package + '.' + self.iclass.name
            #              + ':  ' + str(f) + ' at pc = ' + str(pc))
            #    raise Exception('error')                                
        return result

    def get_db_feature_terms(self):
        result = {}
        result['callees'] = {}
        for (pc,f) in self.features.items():
            f.record_db_features(result,len(self.levels(pc)))
        return result


    def _initialize(self):
        for n in self.xnode.find('features').findall('fx'):
            pc = int(n.get('pc'))
            fx = self.iclass.dictionary.get_fxfeature(int(n.get('f')))
            self.features[pc] = fx
