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

featuresets = [
    'exprs', 'inloop-exprs',
    'assigns', 'inloop-assigns',
    'conditions', 'inloop-conditions',
    'return-exprs', 'inloop-return-exprs',
    'literals', 'callees','methodnames','size',
    'max-loop-depth','cyclomatic-complexity', 'condition-count']

functionnames_tracked = [
    'mod','div','exp','pow','modpow','moddiv','sin','cos','tan',
    'size','sqrt','hashCode','index','nextIndex','currentIndex',
    'length','ceil','indexOf','gcd','byteValue','floatValue',
    'floor','getLength','getIndex','getOffset','getNanos',
    'shortValue','max','median','intValue','maxSize','log','log2C',
    'lastIndexOf','mean','parseByte','parseInt','parseFloat',
    'nextInt','round','totalSize','variance','mul','atan','sinh',
    'cosh'
    ]

fieldnames_tracked = [
    'index','length','size'
    ]


class AlgorithmicFeaturesRecorder(FeaturesRecorder):

    def __init__(self):
        FeaturesRecorder.__init__(self,'algorithmic',featuresets)

    def termstr(self,feature):
        return feature.feature_string()

    def lhs_termstr(self,feature):
        if feature.is_field_expr():
            if feature.get_name() in fieldnames_tracked:
                return 'f_' + feature.get_name()
            else:
                return feature.feature_string()
        else:
            return self.termstr(feature)

    def call_termstr(self,feature):
        if feature.is_function_call_expr():
            name = feature.get_name()
            if name in functionnames_tracked:
                return feature.feature_call_string()

    def record_constant(self,feature,context):
        if not (feature.is_string_constant() or feature.is_class_constant()):
            self.add_term('literals',str(feature))        

    def record_opcode_expr(self,feature,context):
        if feature.is_algorithmic() and not feature.get_op().is_comparison_opcode():
            term = self.termstr(feature)
            self.add_term('exprs',term)
            if context.is_inloop(): self.add_term('inloop-exprs',term)

    def record_function_call_expr(self,feature,context):
        rvtype = feature.get_cms().get_return_type()
        if rvtype.is_floating_type() or rvtype.is_non_boolean_integral_type():
            fname = feature.get_cms().get_method_name()
            self.add_term('callees',fname)
            if fname in functionnames_tracked:
                term = self.call_termstr(feature)
                if not term is None:
                    self.add_term('exprs',term)
                    if context.is_inloop(): self.add_term('inloop-exprs',term)

    def record_assignment(self,feature,context):
        if feature.is_algorithmic_feature():
            rhsf = self.termstr(feature.get_rhs())
            lhsf = self.lhs_termstr(feature.get_lhs())
            term = lhsf + ' := ' + rhsf
            self.add_term('assigns',term)
            if context.is_inloop(): self.add_term('inloop-assigns',term)

    def record_condition(self,feature,context):
        if feature.is_algorithmic_feature():
            term = self.termstr(feature.get_fxpr())
            self.add_term('conditions',term)
            if context.is_inloop(): self.add_term('inloop-conditions',term)

    def record_return_stmt(self,feature,context):
        if feature.is_algorithmic_feature():
            term = self.termstr(feature.get_fxpr())
            self.add_term('return-exprs',term)
            if context.is_inloop(): self.add_term('inloop-return-exprs',term)

    def record_methodname(self,name): self.add_term('methodnames',name)

    def record_size(self,size): self.add_term('size',size)

    def record_max_loop_depth(self,d): self.add_term('max-loop-depth',str(d))

    def record_cyclomatic_complexity(self,c): self.add_term('cyclomatic-complexity',str(c))

    def record_condition_count(self,c): self.add_term('condition-count',str(c))

