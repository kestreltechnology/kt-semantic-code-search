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

from scs.jbc.features.FeaturesRecorder import FeaturesRecorder

featuresets = {
    'callees': 'names of callees',
    'conditions': 'branch conditions',
    'exprs': 'expressions',
    'fieldnames': 'names of fields',
    'iliterals': 'integer literal constants',
    'methodnames': 'names of methods in the index',
    'shortstrings': 'short string literals (up to 12 characters',
    'xliterals': 'floating-point literal constants'
    }

class ConceptFeaturesRecorder(FeaturesRecorder):

    def __init__(self):
        FeaturesRecorder.__init__(self,'concepts',featuresets)

    def termstr(self,feature):
        return feature.feature_string()

    def record_function_call_expr(self,feature,context):
        fname = feature.get_cms().get_method_name()
        self.add_term('callees',fname)

    def record_int_constant(self,feature,context):
        self.add_term('iliterals',str(feature.get_value()))

    def record_long_constant(self,feature,context):
        self.add_term('iliterals',str(feature.get_value()))

    def record_float_constant(self,feature,context):
        self.add_term('xliterals',str(feature.get_value()))

    def record_double_constant(self,feature,context):
        self.add_term('xliterals',str(feature.get_value()))

    def record_string_constant(self,feature,context):
        s = str(feature.get_value())
        if len(s) <= 12:
            self.add_term('shortstrings',s)

    def record_field_expr(self,feature,context):
        self.add_term('fieldnames',str(feature.get_name()))

    def record_opcode_expr(self,feature,context):
        if not feature.get_op().is_comparison_opcode():
            self.add_term('exprs',self.termstr(feature))

    def record_function_call_expr(self,feature,context):
        self.add_term('callees',feature.get_cms().get_method_name())
        self.add_term('exprs',feature.feature_call_string())

    def record_condition(self,feature,context):
        self.add_term('conditions',self.termstr(feature.get_fxpr()))

    def record_methodname(self,name): self.add_term('methodnames',name)

    def record_procedure_call_stmt(self,feature,context):
        fname = feature.get_cms().get_method_name()
        self.add_term('callees',fname)
