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

import scs.jbc.features.DictionaryRecord as D

arithmetic_opcodes = {
    '60': ('add','i','+'),
    '61': ('add','l','+'),
    '62': ('add','f','+'),
    '63': ('add','d','+'),
    '64': ('sub','i','-'),
    '65': ('sub','l','-'),
    '66': ('sub','f','-'),
    '67': ('sub','d','-'),
    '68': ('mul','i','*'),
    '69': ('mul','l','*'),
    '6a': ('mul','f','*'),
    '6b': ('mul','d','*'),
    '6c': ('div','i','/'),
    '6d': ('div','l','/'),
    '6e': ('div','f','/'),
    '6f': ('div','d','/'),
    '70': ('rem','i','%'),
    '71': ('rem','l','%'),
    '72': ('rem','f','%'),
    '73': ('rem','d','%'),
    '74': ('neg','i','-'),
    '75': ('neg','l','-'),
    '76': ('neg','f','-'),
    '77': ('neg','d','-'),
    '78': ('shl','i','<<'),
    '79': ('shl','l','<<'),
    '7a': ('shr','i','>>'),
    '7b': ('shr','l','>>'),
    '7c': ('shr','iu','u>>'),
    '7d': ('shr','lu','u>>'),
    '7e': ('and','i','&'),
    '7f': ('and','l','&'),
    '80': ('or','i','|'),
    '81': ('or','l','|'),
    '82': ('xor','i','^'),
    '83': ('xor','l','^')
    }

converter_opcodes = {
    '85': ('i','l'),
    '86': ('i','f'),
    '87': ('i','d'),
    '88': ('l','i'),
    '89': ('l','f'),
    '8a': ('l','d'),
    '8b': ('f','i'),
    '8c': ('f','l'),
    '8d': ('f','d'),
    '8e': ('d','i'),
    '8f': ('d','l'),
    '90': ('d','f'),
    '91': ('i','b'),
    '92': ('i','c'),
    '93': ('i','s')
    }

comparison_opcodes = {
    '94': ('l','l'),
    '95': ('f','l'),
    '96': ('f','g'),
    '97': ('d','l'),
    '98': ('d','g')
    }

test_opcodes = {
    '99': ('eq-0',' == 0'),
    '9a': ('ne-0',' != 0'),
    '9b': ('lt-0',' < 0'),
    '9c': ('ge-0',' >= 0'),
    '9d': ('gt-0',' > 0'),
    '9e': ('le-0',' <= 0'),
    '9f': ('eq',' == '),
    'a0': ('ne',' != '),
    'a1': ('lt',' < '),
    'a2': ('ge',' >= '),
    'a3': ('gt',' > '),
    'a4': ('le',' <= '),
    'a5': ('a-eq',' == '),
    'a6': ('a-ne',' != '),
    'c6': ('null',' isNull'),
    'c7': ('nonnull', '!isNull')
    }

test_comparison_symbols = {
    '99': ' == ',
    '9a': ' != ',
    '9b': ' < ',
    '9c': ' >= ',
    '9d': ' > ',
    '9e': ' <= '
    }

class FTClassName(D.DictionaryRecord):

    def __init__(self,ifd,index,tags,args):
        D.DictionaryRecord.__init__(self,ifd,index,tags,args)

    def get_name(self): return self.ifd.get_string(int(self.args[0]))

    def get_package_strings(self):
        return  [ self.ifd.get_string(int(x)) for x in self.args[1:] ]

    def get_package(self):
        return '.'.join( [ self.ifd.get_string(int(x)) for x in self.args[1:] ] )
        
    def __str__(self): return (self.get_name())


class FTClassObjectType(D.DictionaryRecord):

    def __init__(self,ifd,index,tags,args):
        D.DictionaryRecord.__init__(self,ifd,index,tags,args)

    def get_class(self): return self.ifd.get_class_name(int(self.args[0]))

    def is_array_type(self): return False

    def __str__(self): return str(self.get_class())

class FTArrayObjectType(D.DictionaryRecord):

    def __init__(self,ifd,index,tags,args):
        D.DictionaryRecord.__init__(self,ifd,index,tags,args)

    def get_type(self): return  self.ifd.get_value_type(int(self.args[0]))

    def is_array_type(self): return True

    def __str__(self): return '[' + str(self.get_type())

class FTObjectValueType(D.DictionaryRecord):

    def __init__(self,ifd,index,tags,args):
        D.DictionaryRecord.__init__(self,ifd,index,tags,args)

    def get_type(self): return self.ifd.get_object_type(int(self.args[0]))

    def is_floating_type(self): return False

    def is_integral_type(self): return False

    def is_non_boolean_integral_type(self): return False

    def is_array_type(self): return self.get_type().is_array_type()

    def __str__(self): return str(self.get_type())

class FTBasicValueType(D.DictionaryRecord):

    def __init__(self,ifd,index,tags,args):
        D.DictionaryRecord.__init__(self,ifd,index,tags,args)

    def get_type(self): return self.tags[1]

    def is_array_type(self): return False

    def is_floating_type(self):
        ty = str(self.get_type())
        return ty == 'F'  or  ty == 'D'

    def is_integral_type(self):
        ty = str(self.get_type())
        return ty in [ 'L', 'I', 'C', 'S', 'B', 'Z', 'XIZX', 'XBZX' ]

    def is_non_boolean_integral_type(self):
        return self.is_integral_type() and not self.get_type() == 'Z'

    def __str__(self): return self.get_type()

class FTFieldSignature(D.DictionaryRecord):

    def __init__(self,ifd,index,tags,args):
        D.DictionaryRecord.__init__(self,ifd,index,tags,args)

    def get_name(self): return self.ifd.get_string(int(self.args[0]))

    def get_type(self): return self.ifd.get_value_type(int(self.args[1]))

    def __str__(self):
        return  (str(self.get_name()) + ':' + str(self.get_type()))

class FTClassFieldSignature(D.DictionaryRecord):

    def __init__(self,ifd,index,tags,args):
        D.DictionaryRecord.__init__(self,ifd,index,tags,args)

    def get_class_name(self): return self.ifd.get_class_name(int(self.args[0]))

    def get_signature(self): return self.ifd.get_fs(int(self.args[1]))

    def __str__(self):
        return str(self.get_class_name()) + '.' + str(self.get_signature())

class FTMethodSignature(D.DictionaryRecord):

    def __init__(self,ifd,index,tags,args):
        D.DictionaryRecord.__init__(self,ifd,index,tags,args)

    def get_name(self): return self.ifd.get_string(int(self.args[0]))

    def get_return_type(self): return self.ifd.get_value_type(int(self.args[1]))

    def get_signature(self):
        return [ self.ifd.get_value_type(int(x)) for x in self.args[1:] ]

    def get_signature_string(self):
        return ('(' + ','.join( [ str(x) for x in self.get_signature()[1:] ])
                    + ')' + str(self.get_signature()[0]))

    def __str__(self):
        return (self.get_name() + '('
                    + ','.join( [ str(x) for x in self.get_signature()[1:] ])
                    + ')'  + str(self.get_signature()[0]))

class FTClassMethodSignature(D.DictionaryRecord):

    def __init__(self,ifd,index,tags,args):
        D.DictionaryRecord.__init__(self,ifd,index,tags,args)

    def get_class_name(self): return self.ifd.get_class_name(int(self.args[0]))

    def get_method_signature(self):
        return self.ifd.get_ms(int(self.args[1]))

    def get_method_name(self):
        return self.get_method_signature().get_name()

    def get_return_type(self):
        return self.get_method_signature().get_return_type()

    def __str__(self):
        return str(self.get_class_name()) + '.' + str(self.get_method_signature())


class FTConstValue(D.DictionaryRecord):

    def __init__(self,ifd,index,tags,args):
        D.DictionaryRecord.__init__(self,ifd,index,tags,args)

    def get_value(self): return 'none'

    def is_string_constant(self): return False
    def is_class_constant(self): return False

    def record_db_features(self,d,looplevels): return

    def record_features(self,recorder,context):
        recorder.record_constant(self,context)

    def __str__(self): return str(self.get_value())

class FTConstString(FTConstValue):

    def __init__(self,ifd,index,tags,args):
        FTConstValue.__init__(self,ifd,index,tags,args)

    def is_string_constant(self): return True

    def record_db_features(self,d,looplevels):
        fs = self.ifd.get_string(int(self.args[0]))
        if not fs in d['stringargs']: d['stringargs'][fs] = 0
        d['stringargs'][fs] += 1

    def record_features(self,recorder,context):
        FTConstValue.record_features(self,recorder,context)
        recorder.record_string_constant(self,context)

    def get_value(self): return self.ifd.get_string(int(self.args[0]))


class FTConstInt(FTConstValue):

    def __init__(self,ifd,index,tags,args):
        FTConstValue.__init__(self,ifd,index,tags,args)

    def record_features(self,recorder,context):
        FTConstValue.record_features(self,recorder,context)        
        recorder.record_int_constant(self,context)

    def get_value(self): return int(self.args[0])

class FTConstFloat(FTConstValue):

    def __init__(self,ifd,index,tags,args):
        FTConstValue.__init__(self,ifd,index,tags,args)

    def record_features(self,recorder,context):
        FTConstValue.record_features(self,recorder,context)        
        recorder.record_float_constant(self,context)

    def get_value(self): return float(self.tags[1])

class FTConstLong(FTConstValue):

    def __init__(self,ifd,index,tags,args):
        FTConstValue.__init__(self,ifd,index,tags,args)

    def record_features(self,recorder,context):
        FTConstValue.record_features(self,recorder,context)        
        recorder.record_long_constant(self,context)

    def get_value(self): return int(self.tags[1])

class FTConstDouble(FTConstValue):

    def __init__(self,ifd,index,tags,args):
        FTConstValue.__init__(self,ifd,index,tags,args)

    def record_features(self,recorder,context):
        FTConstValue.record_features(self,recorder,context)                
        recorder.record_double_constant(self,context)

    def get_value(self): return float(self.tags[1])

class FTConstClass(FTConstValue):

    def __init__(self,ifd,index,tags,args):
        FTConstValue.__init__(self,ifd,index,tags,args)

    def is_class_constant(self): return True

    def record_features(self,recorder,context):
        FTConstValue.record_features(self,recorder,context)                
        recorder.record_class_constant(self,context)

    def get_value(self): return self.ifd.get_object_type(int(self.args[0]))
        
class FTOpcode(D.DictionaryRecord):

    def  __init__(self,ifd,index,tags,args):
        D.DictionaryRecord.__init__(self,ifd,index,tags,args)

    def is_binary_arithmetic_opcode(self): return False
    def is_unary_arithmetic_opcode(self): return False
    def is_binary_test_opcode(self): return False
    def is_unary_test_opcode(self): return False
    def is_comparison_opcode(self): return False
    def is_converter_opcode(self): return False
    def is_instanceof(self): return False
    def is_arraylength(self): return False
    def is_new_object(self): return False
    def is_new_array(self): return False
    def is_new_multi_array(self): return False

    def feature_string(self): return self.__str__()

    def record_features(self,recorder,context):
        recorder.record_opcode(self,context)

    def __str__(self): return (self.tags[0])


class FTArithmeticInstr(FTOpcode):

    def __init__(self,ifd,index,tags,args):
        FTOpcode.__init__(self,ifd,index,tags,args)

    def get_op(self): return arithmetic_opcodes[self.tags[0]][2]

    def get_type(self): return arithmetic_opcodes[self.tags[0]][1]

    def is_binary_arithmetic_opcode(self):
        return (not self.is_unary_arithmetic_opcode())

    def is_unary_arithmetic_opcode(self):
        return (arithmetic_opcodes[self.tags[0]][0] == 'neg')

    def feature_string(self): return (' ' + self.get_op() + ' ')

    def record_features(self,recorder,context):
        recorder.record_arithmetic_opcode(self,context)

    def __str__(self): return self.get_op()

class FTConverterInstr(FTOpcode):

    def __init__(self,ifd,index,tags,args):
        FTOpcode.__init__(self,ifd,index,tags,args)

    def is_converter_opcode(self): return True

    def get_src_type(self): return converter_opcodes[self.tags[0]][0]

    def get_tgt_type(self): return converter_opcodes[self.tags[0]][1]

    def record_features(self,recorder,context):
        recorder.record_converter_opcode(self,context)

    def __str__(self): return self.get_src_type() + '->' + self.get_tgt_type()

class FTComparisonInstr(FTOpcode):

    def __init__(self,ifd,index,tags,args):
        FTOpcode.__init__(self,ifd,index,tags,args)

    def get_type(self): return comparison_opcodes[self.tags[0]][0]

    def get_nan_behavior(self): return comparison_opcodes[self.tags[0]][1]

    def is_comparison_opcode(self): return True

    def record_features(self,recorder,context):
        recorder.record_comparison_opcode(self,context)

    def __str__(self):
        if self.get_type() == 'l': return 'cmpl'
        return 'cmp' + self.get_type() + '_' + self.get_nan_behavior()

class FTTestInstr(FTOpcode):

    def __init__(self,ifd,index,tags,args):
        FTOpcode.__init__(self,ifd,index,tags,args)

    def get_comparison(self): return test_opcodes[self.tags[0]][1]

    def get_offset(self): return int(self.args[0])

    def is_binary_test_opcode(self):
        return (self.tags[0] >= '9f' and self.tags[0] <= 'a6')

    def is_unary_test_opcode(self):
        return ((self.tags[0]  >= '99' and self.tags[0] <= '9e')
                    or (self.tags[0]  == 'c6') or (self.tags[0] == 'c7'))

    def get_comparison_symbol(self):
        return  test_comparison_symbols[self.tags[0]]

    def record_features(self,recorder,context):
        recorder.record_test_opcode(self,context)

    def __str__(self): return self.get_comparison()
            
class FTNewObject(FTOpcode):

    def __init__(self,ifd,index,tags,args):
        FTOpcode.__init__(self,ifd,index,tags,args)

    def get_class_name(self): return self.ifd.get_class_name(int(self.args[0]))

    def is_new_object(self): return True

    def record_features(self,recorder,context):
        recorder.record_new_object_opcode(self,context)

    def __str__(self): return  'new ' + str(self.get_class_name())

class FTNewArray(FTOpcode):

    def __init__(self,ifd,index,tags,args):
        FTOpcode.__init__(self,ifd,index,tags,args)

    def get_element_type(self): return self.ifd.get_value_type(int(self.args[0]))

    def is_new_array(self): return True

    def record_features(self,recorder,context):
        recorder.record_new_array_opcode(self,context)

    def __str__(self):
        return 'new-array(' + str(self.get_element_type()) + ')'

class FTNewMultiArray(FTOpcode):

    def __init__(self,ifd,index,tags,args):
        FTOpcode.__init__(self,ifd,index,tags,args)

    def get_element_type(self): return self.ifd.get_object_type(int(self.args[0]))

    def get_dimensions(self): return int(self.args[1])

    def is_new_multi_array(self): return True

    def record_features(self,recorder,context):
        recorder.record_new_multi_array_opcode(self,context)

    def __str__(self):
        return ('new-multi-array(' + str(self.get_element_type()) + ',' + str(self.get_dimensions()))

class FTArrayLength(FTOpcode):

    def __init__(self,ifd,index,tags,args):
        FTOpcode.__init__(self,ifd,index,tags,args)

    def is_arraylength(self): return True

    def record_features(self,recorder,context):
        recorder.record_arraylength_opcode(self,context)

    def __str__(self): return 'arraylength'

class FTInstanceOf(FTOpcode):

    def __init__(self,ifd,index,tags,args):
        FTOpcode.__init__(self,ifd,index,tags,args)

    def is_instanceof(self): return True

    def get_type(self): return self.ifd.get_object_type(int(self.args[0]))

    def record_features(self,recorder,context):
        recorder.record_instanceof_opcode(self,context)

    def __str__(self): return 'instanceof(' + str(self.get_type()) + ')'


class FTXpr(D.DictionaryRecord):

    def __init__(self,ifd,index,tags,args):
        D.DictionaryRecord.__init__(self,ifd,index,tags,args)

    def is_algorithmic(self): return False

    def get_algorithmic_features(self): return []

    def is_op(self): return False
    def is_comparison_expr(self): return False
    def is_instanceof_expr(self): return False
    def is_field_expr(self): return False
    def is_function_call_expr(self): return False

    def get_type(self): return None

    def feature_string(self): return self.__str__()

    def record_algorithmic_features(self,d,looplevels): return

    def record_db_features(self,d,looplevels): return

    def includes_multiple_sources(self): return False

    def type_feature_string(self):
        ty = self.get_type()
        if ty is None: return '?'
        if ty.is_floating_type(): return 'x'
        if ty.is_integral_type(): return 'i'
        return  'b'

    def record_features(self,recorder,context):
        recorder.record_expr(self,context)

    def __str__(self): return 'fxpr:' + self.tags[0]

class FTXVar(FTXpr):

    def __init__(self,ifd,index,tags,args):
        FTXpr.__init__(self,ifd,index,tags,args)

    def get_type(self): return self.ifd.get_value_type(int(self.args[0]))

    def is_algorithmic(self):
        ty = self.get_type()
        return ty.is_floating_type() or ty.is_integral_type()

    def get_element_type(self):
        if self.get_type().is_array_type():
            return self.get_type().get_type()
        return None

    def record_features(self,recorder,context):
        recorder.record_var_expr(self,context)

    def get_algorithmic_features(self): return [ str(self) ]

    def __str__(self):
        ty = self.get_type()
        if ty.is_floating_type(): return 'x'
        if ty.is_integral_type(): return 'i'
        return 'b'

class FTXField(FTXpr):

    def __init__(self,ifd,index,tags,args):
        FTXpr.__init__(self,ifd,index,tags,args)

    def get_cfs(self): return self.ifd.get_cfs(int(self.args[0]))

    def get_type(self): return self.get_cfs().get_signature().get_type()

    def is_field_expr(self): return True

    def get_name(self): return self.get_cfs().get_signature().get_name()

    def is_algorithmic(self):
        ty = self.get_type()
        return ty.is_integral_type() or ty.is_floating_type()

    def record_features(self,recorder,context):
        recorder.record_field_expr(self,context)

    def feature_string(self):
        ty = self.get_type()
        if ty.is_floating_type(): return 'f_x'
        if ty.is_integral_type(): return 'f_i'
        return 'f_b'

    def __str__(self): return str(self.get_cfs())

class FTXArrayElem(FTXpr):

    def __init__(self,ifd,index,tags,args):
        FTXpr.__init__(self,ifd,index,tags,args)

    def get_array(self): return self.ifd.get_fxpr(int(self.args[0]))

    def get_index(self): return self.ifd.get_fxpr(int(self.args[1]))

    def get_type(self): return self.tags[1]

    def is_floating_element_type(self):
        ty = self.get_type()
        return ty == 'F' or ty =='D'

    def is_integral_element_type(self):
        ty = self.get_type()
        return ty in [ 'L', 'I', 'C', 'S', 'B', 'Z', 'XIZX', 'XBZX' ]

    def is_algorithmic(self):
        return self.is_floating_element_type() or self.is_integral_element_type()

    def record_features(self,recorder,context):
        recorder.record_array_elem_expr(self,context)

    def feature_string(self): return self.type_feature_string()

    def type_feature_string(self):
        if self.is_floating_element_type(): return 'e_x'
        if self.is_integral_element_type(): return 'e_i'
        return  'b'

    def __str__(self):
        return str(self.get_array()) + '[' + str(self.get_index()) + ']'

class FTXConst(FTXpr):

    def __init__(self,ifd,index,tags,args):
        FTXpr.__init__(self,ifd,index,tags,args)

    def get_constant(self): return self.ifd.get_constant_value(int(self.args[0]))

    def is_algorithmic(self): return (not self.get_constant().is_string_constant())

    def record_features(self,recorder,context):
        self.get_constant().record_features(recorder,context)
        recorder.record_const_expr(self,context)

    def __str__(self): return str(self.get_constant())
   
class FTXOp(FTXpr):

    def __init__(self,ifd,index,tags,args):
        FTXpr.__init__(self,ifd,index,tags,args)

    def is_algorithmic(self):
        return not (self.includes_multiple_sources()
                        or self.get_op().is_instanceof()
                        or self.get_op().is_new_object()
                        or self.get_op().is_new_array()
                        or self.get_op().is_new_multi_array()
                        or (self.get_op().is_unary_test_opcode()
                                and self.get_args()[0].is_instanceof_expr())
                        or any( [ (not x.is_algorithmic()) for x in self.get_args() ]))

    def is_op(self): return True

    def get_op(self): return self.ifd.get_opcode(int(self.args[0]))

    def get_args(self): return [ self.ifd.get_fxpr(int(x)) for x in self.args[1:]]

    def is_comparison_expr(self): return self.get_op().is_comparison_opcode()

    def is_instanceof_expr(self): return self.get_op().is_instanceof()

    def includes_multiple_sources(self):
        return any([ x.includes_multiple_sources() for x in self.get_args() ])

    def record_features(self,recorder,context):
        recorder.record_opcode_expr(self,context)
        for a in self.get_args():
            a.record_features(recorder,context)

    def record_algorithmic_features(self,d,looplevels):
        if self.get_op().is_converter_opcode():
            self.get_args()[0].record_algorithmic_features(d,looplevels)
            return
        if self.get_op().is_instanceof():
            return
        if self.get_op().is_comparison_opcode():
            for a in self.get_args():
                a.record_algorithmic_features(d,looplevels)
            return
        if (self.get_op().is_unary_test_opcode()
                and self.get_args()[0].is_instanceof_expr()):
            return
        for a in self.get_args():
            a.record_algorithmic_features(d,looplevels)
        fs = self.feature_string()
        if not fs in d['exprs']: d['exprs'][fs] = 0
        d['exprs'][fs] += 1
        if looplevels > 0:
            if not fs in d['inloop-exprs']: d['inloop-exprs'][fs] = 0
            d['inloop-exprs'][fs] += 1

    def feature_string(self):
        if self.get_op().is_converter_opcode():
            return self.get_args()[0].feature_string()
        if self.get_op().is_binary_arithmetic_opcode() or self.get_op().is_binary_test_opcode():
            return ('(' + self.get_args()[0].feature_string()
                        + self.get_op().feature_string()
                        + self.get_args()[1].feature_string() + ')')
        if self.get_op().is_unary_test_opcode():
            if self.get_args()[0].is_comparison_expr():
                return ('(' + self.get_args()[0].get_args()[0].feature_string()
                            + self.get_op().get_comparison_symbol()
                            + self.get_args()[0].get_args()[1].feature_string() + ')')
            return ('(' + self.get_args()[0].feature_string() + str(self.get_op()) + ')')
        if self.get_op().is_arraylength():
            return 'arraylength(' + self.get_args()[0].feature_string() + ')'
        return ('(' + self.get_op().feature_string() + ','
                    + ','.join( [ x.feature_string() for x in self.get_args() ]) + ')')

    def __str__(self):
        if self.get_op().is_binary_arithmetic_opcode():
            return ('(' + str(self.get_args()[0]) + str(self.get_op()) +  str(self.get_args()[1]) + ')')
        if self.get_op().is_binary_test_opcode():
            return (str(self.get_args()[0]) + str(self.get_op()) + str(self.get_args()[1]))
        if self.get_op().is_unary_test_opcode():
                if self.get_args()[0].is_comparison_expr():
                    return (str(self.get_args()[0].get_args()[0])
                            + self.get_op().get_comparison_symbol()
                            + str(self.get_args()[0].get_args()[1]))
                return (str(self.get_args()[0]) + str(self.get_op()))
        return (str(self.get_op()) + '('
                    + ','.join( [str(x) for x in self.get_args()]) + ')')

class FTXFunctionCall(FTXpr):

    def __init__(self,ifd,index,tags,args):
        FTXpr.__init__(self,ifd,index,tags,args)

    def get_cms(self): return self.ifd.get_cms(int(self.args[0]))

    def get_name(self): return self.get_cms().get_method_name()

    def get_args(self): return [ self.ifd.get_fxpr(int(x)) for x in self.args[1:]]

    def get_type(self): return self.get_cms().get_method_signature().get_return_type()

    def is_algorithmic(self):
        ty = self.get_type()
        return ty.is_floating_type() or ty.is_integral_type()

    def includes_multiple_sources(self):
        return any([ x.includes_multiple_sources() for x in self.get_args() ])

    def is_function_call_expr(self): return True

    def feature_string(self): return self.type_feature_string()

    def record_features(self,recorder,context):
        recorder.record_function_call_expr(self,context)
        context.set_function_call_return_value(self.get_cms())
        for a in self.get_args():
            a.record_features(recorder,context)
        context.unset_function_call_return_value()

    def record_db_features(self,d,looplevels):
        cn = self.get_cms().get_class_name()
        classname = str(cn.get_name())
        package = str(cn.get_package())
        pckstrings = cn.get_package_strings()
        if not cn in d['classnames']: d['classnames'][classname] = 0
        d['classnames'][classname] += 1
        for s in cn.get_package_strings():
            if not s in d['packages']: d['packages'][s] = 0
            d['packages'][s] += 1
        if not package in d['packages']: d['packages'][package] = 0
        d['packages'][package] += 1
        mn = str(self.get_cms().get_method_signature().get_name())
        if not mn in d['methodnames']: d['methodnames'][mn] = 0
        d['methodnames'][mn] += 1
        fs = self.__str__()
        for a in self.get_args():
            a.record_db_features(d,looplevels)

    def feature_call_string(self):
        return (self.get_name() + '('
                    + ','.join( [ x.feature_string() for x in self.get_args() ])
                    + ')')

    def feature_string(self):
        rvty = self.get_type()
        if rvty.is_integral_type(): return 'fc_i'
        if rvty.is_floating_type(): return 'fc_x'
        return self.feature_call_string()

    def __str__(self):
        return  (str(self.get_cms())  + '('
                     + ','.join( [ str(x) for x  in self.get_args()]) + ')')

class FTXAttr(FTXpr):

    def __init__(self,ifd,index,tags,args):
        FTXpr.__init__(self,ifd,index,tags,args)

    def get_string(self): return self.tags[1]

    def get_fxpr(self): return self.ifd.get_fxpr(int(self.args[0]))

    def __str__(self): return str(self.get_fxpr()) + '__' + self.get_string()

class FTXMultiple(FTXpr):

    def __init__(self,ifd,index,tags,args):
        FTXpr.__init__(self,ifd,index,tags,args)

    def get_exprs(self): return [ self.ifd.get_fxpr(int(x)) for x in self.args ]

    def get_algorithmic_features(self): return []

    def includes_multiple_sources(self): return True

    def record_features(self,recorder,context):
        recorder.record_multiple_sources_expr(self,context)

    def __str__(self):
        return ('[[' + ' | '.join( [ str(x) for x in self.get_exprs() ]) + ']]')

class FTXException(FTXpr):

    def __init__(self,ifd,index,tags,args):
        FTXpr.__init__(self,ifd,index,tags,args)

    def record_features(self,recorder,context):
        recorder.record_exception_expr(self,context)

    def __str__(self): return 'exception'

class FTXNull(FTXpr):

    def __init__(self,ifd,index,tags,args):
        FTXpr.__init__(self,ifd,index,tags,args)

    def record_features(self,recorder,context):
        recorder.record_null_expr(self,context)

    def __str__(self): return 'null'

class FTXUnknown(FTXpr):

    def __init__(self,ifd,index,tags,args):
        FTXpr.__init__(self,ifd,index,tags,args)

    def __str__(self): return 'unknown'

class FTXFeature(D.DictionaryRecord):

    def __init__(self,ifd,index,tags,args):
        D.DictionaryRecord.__init__(self,ifd,index,tags,args)

    def is_algorithmic_feature(self): return False

    def is_return_stmt(self): return False
    def is_throw_stmt(self): return False
    def is_condition(self): return False

    def get_algorithmic_features(self): return []

    def record_algorithmic_features(self,d,looplevels): return

    def record_db_features(self,d,looplevels): return

    def feature_string(self): return str(self)

    def record_features(self,recorder,context):
        recorder.record_code_component(self,context)

    def __str__(self): return 'fxpr:' + self.tags[0]
              
class FTCondition(FTXFeature):

    def __init__(self,ifd,index,tags,args):
        FTXFeature.__init__(self,ifd,index,tags,args)

    def is_algorithmic_feature(self): return  self.get_fxpr().is_algorithmic()

    def is_condition(self): return True

    def get_algorithmic_features(self):
        return self.get_fxpr().get_algorithmic_features()

    def get_fxpr(self): return self.ifd.get_fxpr(int(self.args[0]))

    def record_features(self,recorder,context):
        recorder.record_condition(self,context);
        context.set_condition()
        self.get_fxpr().record_features(recorder,context)

    def feature_string(self): return 'C:' + self.get_fxpr().feature_string()

    def __str__(self): return 'C:' + str(self.get_fxpr())

class FTAssignment(FTXFeature):

    def __init__(self,ifd,index,tags,args):
        FTXFeature.__init__(self,ifd,index,tags,args)

    def is_algorithmic_feature(self): return self.get_rhs().is_algorithmic()

    def get_algorithmic_features(self):
        return self.get_rhs().get_algorithmic_features()

    def get_lhs(self): return self.ifd.get_fxpr(int(self.args[0]))

    def get_rhs(self): return self.ifd.get_fxpr(int(self.args[1]))

    def record_features(self,recorder,context):
        recorder.record_assignment(self,context)
        context.set_assignment(self.get_lhs())        
        self.get_rhs().record_features(recorder,context)

    def record_db_features(self,d,looplevels):
        self.get_rhs().record_db_features(d,looplevels)

    def feature_string(self):
        return ('A:' + self.get_lhs().feature_string() + ' := ' + self.get_rhs().feature_string())

    def __str__(self):
        return ('A:' + str(self.get_lhs())  + ' := ' +  str(self.get_rhs()))

class FTProcedurecall(FTXFeature):

    def __init__(self,ifd,index,tags,args):
        FTXFeature.__init__(self,ifd,index,tags,args)

    def get_cms(self): return self.ifd.get_cms(int(self.args[0]))

    def get_args(self): return  [ self.ifd.get_fxpr(int(x)) for x in self.args[1:]]

    def record_features(self,recorder,context):
        recorder.record_procedure_call_stmt(self,context)
        context.set_procedure_call_stmt(self.get_cms())        
        for a in self.get_args():
            a.record_features(recorder,context)

    def record_db_features(self,d,looplevels):
        cn = self.get_cms().get_class_name()
        classname = str(cn.get_name())
        package = str(cn.get_package())
        pckstrings = cn.get_package_strings()
        if not cn in d['classnames']: d['classnames'][classname] = 0
        d['classnames'][classname] += 1
        for s in cn.get_package_strings():
            if not s in d['packages']: d['packages'][s] = 0
            d['packages'][s] += 1
        if not package in d['packages']: d['packages'][package] = 0
        d['packages'][package] += 1
        mn = str(self.get_cms().get_method_signature().get_name())
        if not mn in d['methodnames']: d['methodnames'][mn] = 0
        d['methodnames'][mn] += 1
        for a in self.get_args():
            a.record_db_features(d,looplevels)

    def record_resource_features(self,d,looplevels):
        cn = self.get_cms().get_class_name()
        classname = str(cn.get_name())
        if classname  == 'HashMap' or classname == "Hashtable":
            if not classname in d['classnames']: d['classnames'][classname] = 0
            d['classnames'][classname] += 1
        mn = str(self.get_cms().get_method_signature().get_name())
        if not mn in d['methodnames']: d['methodnames'][mn] = 0
        d['methodnames'][mn] += 1
        for a in self.get_args():
            a.record_resource_features(d,looplevels)

    def feature_call_string(self):
        return (str(self.get_cms().get_method_name()) + '('
                    + ','.join( [ str(x) for x in self.get_args() ] ) + ')')

    def __str__(self):
        return ('P:' + str(self.get_cms()) + '('
                    + ','.join( [ str(x) for x in self.get_args() ] ) + ')')

class FTReturn(FTXFeature):

    def __init__(self,ifd,index,tags,args):
        FTXFeature.__init__(self,ifd,index,tags,args)

    def is_algorithmic_feature(self):
        return  self.has_fxpr() and self.get_fxpr().is_algorithmic()

    def is_return_stmt(self): return True

    def has_fxpr(self): return (int(self.args[0]) > 0)

    def record_features(self,recorder,context):
        recorder.record_return_stmt(self,context)
        context.set_return_stmt()
        if self.has_fxpr():
            self.get_fxpr().record_features(recorder,context)

    def get_fxpr(self):
        if self.has_fxpr():
            return self.ifd.get_fxpr(int(self.args[0]))

    def feature_string(self):
        if self.has_fxpr():
            return 'R:' + self.get_fxpr().feature_string()
        else:
            return 'R'

    def __str__(self):
        if self.has_fxpr():
            return 'R:' + str(self.get_fxpr())
        else:
            return 'R'
        

class FTThrow(FTXFeature):

    def __init__(self,ifd,index,tags,args):
        FTXFeature.__init__(self,ifd,index,tags,args)

    def get_fxpr(self): return self.ifd.get_fxpr(int(self.args[0]))

    def is_throw_stmt(self): return True

    def record_features(self,recorder,context):
        recorder.record_throw_stmt(self,context)

    def __str__(self): return 'T:' + str(self.get_fxpr())
