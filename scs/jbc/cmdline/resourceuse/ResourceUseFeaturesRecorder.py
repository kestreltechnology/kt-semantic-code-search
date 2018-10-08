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
    'collection_callees': 'names of calls to collection classes',
    'condition_count': 'number of conditions in a method',
    'conditions': 'branch conditions',
    'cyclomatic_complexity': 'cyclomatic_complexity levels of methods',
    'inloop_callees': 'calls made from within a loop',
    'inloop_conditions': 'conditions that appear within a loop',
    'inloop_new_array': 'creation of new array in a loop',
    'inloop_new_multi_array': 'creation of new multi-dimensional array in a loop',
    'inloop_new_object': 'creation of new object in a loop',
    'max_loop_depth': 'maximum loop level nestings of a method',
    'methodnames': 'names of methods in the index',
    'new_array': 'creation of new array',
    'new_multi_array': 'creation of new multi-dimensional array',
    'new_object': 'creation of new object',
    'regex_callees': 'calls to methods belonging to the java.util.regex classes',
    'sizes': 'method sizes (number of instructions)'
    }

collection_classnames = [
    'Hashtable', 'HashMap', 'ArrayList', 'List', 'Map', 'LinkedList', 'TreeMap',
    'TreeSet', 'HashSet', 'Set', 'SortedSet', 'SortedMap' ]

regex_classnames = [ 'Pattern', 'Matcher', 'MatchResult' ]

regex_methodnames = [
    'end', 'group', 'groupCount', 'start',
    'find', 'matches', 'region', 'regionEnd', 'regionStart', 'replaceAll',
    'replaceFirst', 'requireEnd', 'reset', 'toMatchResult', 'usePattern',
    'asPredicate', 'compile', 'matcher', 'pattern', 'quote', 'split'
    ]

class ResourceUseFeaturesRecorder(FeaturesRecorder):

    def __init__(self):
        FeaturesRecorder.__init__(self,'resourceuse',featuresets)

    def termstr(self,feature):
        return feature.feature_string()

    def call_termstr(self,feature):
        if feature.is_function_call_expr():
            return feature.feature_call_string()

    def record_opcode_expr(self,feature,context):
        if feature.is_op():
            if feature.get_op().is_new_object():
                name = str(feature.get_op().get_class_name())
                self.add_term('new_object',name)
                if context.is_inloop():
                    self.add_term('inloop_new_object',name)
            elif feature.get_op().is_new_array():
                elementtype = str(feature.get_op().get_element_type())
                self.add_term('new_array',elementtype)
                if context.is_inloop():
                    self.add_term('inloop_new_array',elementtype)

    def record_function_call_expr(self,feature,context):
        fname = feature.get_cms().get_method_name()
        term = self.call_termstr(feature)
        self.add_term('callees',term)
        if context.is_inloop(): self.add_term('inloop_callees',term)
        if fname in regex_methodnames:
            self.add_term('regex_callees', term)

    def record_condition(self,feature,context):
        term = self.termstr(feature.get_fxpr())
        self.add_term('conditions',term)
        if context.is_inloop(): self.add_term('inloop_conditions',term)

    def record_methodname(self,name): self.add_term('methodnames',name)

    def record_size(self,size): self.add_term('sizes',size)

    def record_max_loop_depth(self,d): self.add_term('max_loop_depth',str(d))

    def record_cyclomatic_complexity(self,c): self.add_term('cyclomatic_complexity',str(c))

    def record_condition_count(self,c): self.add_term('condition_count',str(c))

    def record_procedure_call_stmt(self,feature,context):
        fname = feature.get_cms().get_method_name()
        term = feature.feature_call_string()
        self.add_term('callees',term)
        if context.is_inloop(): self.add_term('inloop_callees',term)
        cn = feature.get_cms().get_class_name()
        classname = str(cn.get_name())
        methodname = feature.get_cms().get_method_name()
        if classname in collection_classnames:
            self.add_term('collection_callees', classname + '::' + methodname)
        if methodname in regex_methodnames:
            self.add_term('regex_callees', classname + '::' + methodname)
            
