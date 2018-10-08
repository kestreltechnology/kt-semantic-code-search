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

class FeaturesRecorder():

    def __init__(self,name,featuresets):
        self.name = name
        self.results = {}
        self.featuresets = featuresets
        self.featuresetnames = sorted(self.featuresets.keys())
        for s in self.featuresetnames:
            self.results[s] = {}

    def reset(self):
        for s in self.featuresetnames:
            self.results[s] = {}

    def add_term(self,featureset,term):
        if not featureset in self.results:
            print('Invalid featureset: ' + featureset)
            exit(-1)
        if not term in self.results[featureset]:
            self.results[featureset][term] = 0
        self.results[featureset][term] += 1

    def termstr(self,feature): return str(feature)

    def record_opcode_expr(self,feature,context): pass

    def record_constant(self,feature,context): pass

    def record_string_constant(self,feature,context): pass

    def record_int_constant(self,feature,context): pass

    def record_float_constant(self,feature,context): pass

    def record_long_constant(self,feature,context): pass

    def record_double_constant(self,feature,context): pass

    def record_class_constant(self,feature,context): pass

    def record_opcode(self,feature,context): pass

    def record_arithmetic_opcode(self,feature,context): pass

    def record_converter_opcode(self,feature,context): pass

    def record_comparison_opcode(self,feature,context): pass

    def record_test_opcode(self,feature,context): pass

    def record_new_object_opcode(self,feature,context): pass

    def record_new_array_opcode(self,feature,context): pass

    def record_new_multi_array_opcode(self,feature,context): pass

    def record_arraylength_opcode(self,feature,context): pass

    def record_instanceof_opcode(self,feature,context): pass

    def record_expr(self,feature,context): pass

    def record_var_expr(self,feature,context): pass

    def record_field_expr(self,feature,context): pass

    def record_array_elem_expr(self,feature,context): pass

    def record_const_expr(self,feature,context): pass

    def record_opcde_expr(self,feature,context): pass

    def record_function_call_expr(self,feature,context): pass

    def record_multiple_sources_expr(self,feature,context): pass
            
    def record_exception_expr(self,feature,context): pass
        
    def record_null_expr(self,feature,context): pass

    def record_code_component(self,feature,context): pass

    def record_condition(self,feature,context): pass

    def record_assignment(self,feature,context): pass

    def record_procedure_call_stmt(self,feature,context): pass

    def record_return_stmt(self,feature,context): pass

    def record_throw_stmt(self,feature,context): pass

    def record_methodname(self,name): pass

    def record_size(self,desc): pass

    def record_max_loop_depth(self,depth): pass

    def record_cyclomatic_complexity(self,complexity): pass

    def record_condition_count(self,conditioncount): pass
