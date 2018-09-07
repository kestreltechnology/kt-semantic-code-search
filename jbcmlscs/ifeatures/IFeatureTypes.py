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

import jbcmlscs.ifeatures.IDictionaryRecord as ID

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
    '82': ('xor','i','xor'),
    '83': ('xor','l','xor')
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

class FTClassName(ID.IDictionaryRecord):

    def __init__(self,ifd,index,tags,args):
        ID.IDictionaryRecord.__init__(self,ifd,index,tags,args)

    def get_name(self): return self.ifd.get_string(int(self.args[0]))

    def get_package(self):
        return '.'.join( [ self.ifd.get_string(int(x)) for x in self.args[1:] ] )
        
    def __str__(self): return (self.get_name())


class FTClassObjectType(ID.IDictionaryRecord):

    def __init__(self,ifd,index,tags,args):
        ID.IDictionaryRecord.__init__(self,ifd,index,tags,args)

    def get_class(self): return self.ifd.get_class_name(int(self.args[0]))

    def is_array_type(self): return False

    def __str__(self): return str(self.get_class())

class FTArrayObjectType(ID.IDictionaryRecord):

    def __init__(self,ifd,index,tags,args):
        ID.IDictionaryRecord.__init__(self,ifd,index,tags,args)

    def get_type(self): return  self.ifd.get_value_type(int(self.args[0]))

    def is_array_type(self): return True

    def __str__(self): return '[' + str(self.get_type())

class FTObjectValueType(ID.IDictionaryRecord):

    def __init__(self,ifd,index,tags,args):
        ID.IDictionaryRecord.__init__(self,ifd,index,tags,args)

    def get_type(self): return self.ifd.get_object_type(int(self.args[0]))

    def is_floating_type(self): return False

    def is_integral_type(self): return False

    def is_array_type(self): return self.get_type().is_array_type()

    def __str__(self): return str(self.get_type())

class FTBasicValueType(ID.IDictionaryRecord):

    def __init__(self,ifd,index,tags,args):
        ID.IDictionaryRecord.__init__(self,ifd,index,tags,args)

    def get_type(self): return  self.tags[1]

    def is_array_type(self): return False

    def is_floating_type(self):
        ty = str(self.get_type())
        return ty == 'F'  or  ty == 'D'

    def is_integral_type(self):
        ty = str(self.get_type())
        return ty in [ 'L', 'I', 'C', 'S', 'B', 'Z', 'XIZX', 'XBZX' ]

    def __str__(self): return self.get_type()

class FTFieldSignature(ID.IDictionaryRecord):

    def __init__(self,ifd,index,tags,args):
        ID.IDictionaryRecord.__init__(self,ifd,index,tags,args)

    def get_name(self): return self.ifd.get_string(int(self.args[0]))

    def get_type(self): return self.ifd.get_value_type(int(self.args[1]))

    def __str__(self):
        return  (str(self.get_name()) + ':' + str(self.get_type()))

class FTClassFieldSignature(ID.IDictionaryRecord):

    def __init__(self,ifd,index,tags,args):
        ID.IDictionaryRecord.__init__(self,ifd,index,tags,args)

    def get_class_name(self): return self.ifd.get_class_name(int(self.args[0]))

    def get_signature(self): return self.ifd.get_fs(int(self.args[1]))

    def __str__(self):
        return str(self.get_class_name()) + '.' + str(self.get_signature())

class FTMethodSignature(ID.IDictionaryRecord):

    def __init__(self,ifd,index,tags,args):
        ID.IDictionaryRecord.__init__(self,ifd,index,tags,args)

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

class FTClassMethodSignature(ID.IDictionaryRecord):

    def __init__(self,ifd,index,tags,args):
        ID.IDictionaryRecord.__init__(self,ifd,index,tags,args)

    def get_class_name(self): return self.ifd.get_class_name(int(self.args[0]))

    def get_method_signature(self):
        return self.ifd.get_ms(int(self.args[1]))

    def __str__(self):
        return str(self.get_class_name()) + '.' + str(self.get_method_signature())


class FTConstValue(ID.IDictionaryRecord):

    def __init__(self,ifd,index,tags,args):
        ID.IDictionaryRecord.__init__(self,ifd,index,tags,args)

    def get_value(self): return 'none'

    def record_algorithmic_features(self,d,looplevels):
        fs = str(self)
        if not fs in d['literals']: d['literals'][fs] = 0
        d['literals'][fs] += 1

    def __str__(self): return str(self.get_value())

class FTConstString(FTConstValue):

    def __init__(self,ifd,index,tags,args):
        FTConstValue.__init__(self,ifd,index,tags,args)

    def record_algorithmic_features(self,d,looplevels): return

    def get_value(self): return self.ifd.get_string(int(self.args[0]))


class FTConstInt(FTConstValue):

    def __init__(self,ifd,index,tags,args):
        FTConstValue.__init__(self,ifd,index,tags,args)

    def get_value(self): return int(self.args[0])

class FTConstFloat(FTConstValue):

    def __init__(self,ifd,index,tags,args):
        FTConstValue.__init__(self,ifd,index,tags,args)

    def get_value(self): return float(self.tags[1])

class FTConstLong(FTConstValue):

    def __init__(self,ifd,index,tags,args):
        FTConstValue.__init__(self,ifd,index,tags,args)

    def get_value(self): return int(self.tags[1])

class FTConstDouble(FTConstValue):

    def __init__(self,ifd,index,tags,args):
        FTConstValue.__init__(self,ifd,index,tags,args)

    def get_value(self): return float(self.tags[1])

class FTConstClass(FTConstValue):

    def __init__(self,ifd,index,tags,args):
        FTConstValue.__init__(self,ifd,index,tags,args)

    def record_algorithmic_features(self,d,looplevels): return

    def get_value(self): return self.ifd.get_object_type(int(self.args[0]))
        
class FTOpcode(ID.IDictionaryRecord):

    def  __init__(self,ifd,index,tags,args):
        ID.IDictionaryRecord.__init__(self,ifd,index,tags,args)

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

    def __str__(self): return self.get_op()

class FTConverterInstr(FTOpcode):

    def __init__(self,ifd,index,tags,args):
        FTOpcode.__init__(self,ifd,index,tags,args)

    def is_converter_opcode(self): return True

    def get_src_type(self): return converter_opcodes[self.tags[0]][0]

    def get_tgt_type(self): return converter_opcodes[self.tags[0]][1]

    def __str__(self): return self.get_src_type() + '->' + self.get_tgt_type()

class FTComparisonInstr(FTOpcode):

    def __init__(self,ifd,index,tags,args):
        FTOpcode.__init__(self,ifd,index,tags,args)

    def get_type(self): return comparison_opcodes[self.tags[0]][0]

    def get_nan_behavior(self): return comparison_opcodes[self.tags[0]][1]

    def is_comparison_opcode(self): return True

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

    def __str__(self): return self.get_comparison()
            
class FTNewObject(FTOpcode):

    def __init__(self,ifd,index,tags,args):
        FTOpcode.__init__(self,ifd,index,tags,args)

    def get_class_name(self): return self.ifd.get_class_name(int(self.args[0]))

    def is_new_object(self): return True

    def __str__(self): return  'new ' + str(self.get_class_name())

class FTNewArray(FTOpcode):

    def __init__(self,ifd,index,tags,args):
        FTOpcode.__init__(self,ifd,index,tags,args)

    def get_element_type(self): return self.ifd.get_value_type(int(self.args[0]))

    def is_new_array(self): return True

    def __str__(self):
        return 'new-array(' + str(self.get_element_type()) + ')'

class FTNewMultiArray(FTOpcode):

    def __init__(self,ifd,index,tags,args):
        FTOpcode.__init__(self,ifd,index,tags,args)

    def get_element_type(self): return self.ifd.get_object_type(int(self.args[0]))

    def get_dimensions(self): return int(self.args[1])

    def is_new_multi_array(self): return True

    def __str__(self):
        return ('new-multi-array(' + str(self.get_element_type()) + ',' + str(self.get_dimensions()))

class FTArrayLength(FTOpcode):

    def __init__(self,ifd,index,tags,args):
        FTOpcode.__init__(self,ifd,index,tags,args)

    def is_arraylength(self): return True

    def __str__(self): return 'arraylength'

class FTInstanceOf(FTOpcode):

    def __init__(self,ifd,index,tags,args):
        FTOpcode.__init__(self,ifd,index,tags,args)

    def is_instanceof(self): return True

    def get_type(self): return self.ifd.get_object_type(int(self.args[0]))

    def __str__(self): return 'instanceof(' + str(self.get_type()) + ')'


class FTXpr(ID.IDictionaryRecord):

    def __init__(self,ifd,index,tags,args):
        ID.IDictionaryRecord.__init__(self,ifd,index,tags,args)

    def is_algorithmic(self): return False

    def get_algorithmic_features(self): return []

    def is_comparison_expr(self): return False
    def is_instanceof_expr(self): return False

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

    def __str__(self): return 'fxpr:' + self.tags[0]

class FTXVar(FTXpr):

    def __init__(self,ifd,index,tags,args):
        FTXpr.__init__(self,ifd,index,tags,args)

    def get_type(self): return self.ifd.get_value_type(int(self.args[0]))

    def get_element_type(self):
        if self.get_type().is_array_type():
            return self.get_type().get_type()
        return None

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

    def feature_string(self): return self.type_feature_string()

    def __str__(self): return str(self.get_cfs())

class FTXArrayElem(FTXpr):

    def __init__(self,ifd,index,tags,args):
        FTXpr.__init__(self,ifd,index,tags,args)

    def get_array(self): return self.ifd.get_fxpr(int(self.args[0]))

    def get_index(self): return self.ifd.get_fxpr(int(self.args[1]))

    def get_type(self): return self.tags[1]

    def feature_string(self): return self.type_feature_string()

    def type_feature_string(self):
        ty = self.get_type()
        if ty is None: return '?'
        if ty == 'F' or  ty == 'D': return 'x'
        if ty in [ 'L', 'I', 'C', 'S', 'B', 'Z', 'XIZX', 'XBZX' ]: return 'i'
        return  'b'

    def __str__(self):
        return str(self.get_array()) + '[' + str(self.get_index()) + ']'

class FTXConst(FTXpr):

    def __init__(self,ifd,index,tags,args):
        FTXpr.__init__(self,ifd,index,tags,args)

    def get_constant(self): return self.ifd.get_constant_value(int(self.args[0]))

    def is_algorithmic(self): return True

    def record_algorithmic_features(self,d,looplevels):
        self.get_constant().record_algorithmic_features(d,looplevels)

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
                                and self.get_args()[0].is_instanceof_expr()))

    def get_op(self): return self.ifd.get_opcode(int(self.args[0]))

    def get_args(self): return [ self.ifd.get_fxpr(int(x)) for x in self.args[1:]]

    def is_comparison_expr(self): return self.get_op().is_comparison_opcode()

    def is_instanceof_expr(self): return self.get_op().is_instanceof()

    def includes_multiple_sources(self):
        return any([ x.includes_multiple_sources() for x in self.get_args() ])

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

    def record_db_features(self,d,looplevels):
        for a in self.get_args():
            a.record_db_features(d,looplevels)

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

    def get_args(self): return [ self.ifd.get_fxpr(int(x)) for x in self.args[1:]]

    def get_type(self): return self.get_cms().get_method_signature().get_return_type()

    def includes_multiple_sources(self):
        return any([ x.includes_multiple_sources() for x in self.get_args() ])

    def feature_string(self): return self.type_feature_string()

    def record_db_features(self,d,looplevels):
        fs = self.__str__()
        if not fs in d['callees']: d['callees'][fs] = 0
        d['callees'][fs] += 1

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

    def __str__(self):
        return ('[[' + ' | '.join( [ str(x) for x in self.get_exprs() ]) + ']]')

class FTXException(FTXpr):

    def __init__(self,ifd,index,tags,args):
        FTXpr.__init__(self,ifd,index,tags,args)

    def __str__(self): return 'exception'

class FTXNull(FTXpr):

    def __init__(self,ifd,index,tags,args):
        FTXpr.__init__(self,ifd,index,tags,args)

    def __str__(self): return 'null'

class FTXUnknown(FTXpr):

    def __init__(self,ifd,index,tags,args):
        FTXpr.__init__(self,ifd,index,tags,args)

    def __str__(self): return 'unknown'

class FTXFeature(ID.IDictionaryRecord):

    def __init__(self,ifd,index,tags,args):
        ID.IDictionaryRecord.__init__(self,ifd,index,tags,args)

    def is_algorithmic_feature(self): return False

    def get_algorithmic_features(self): return []

    def record_algorithmic_features(self,d,looplevels): return

    def record_db_features(self,d,looplevels): return

    def feature_string(self): return str(self)

    def __str__(self): return 'fxpr:' + self.tags[0]
              
class FTCondition(FTXFeature):

    def __init__(self,ifd,index,tags,args):
        FTXFeature.__init__(self,ifd,index,tags,args)

    def is_algorithmic_feature(self): return  self.get_fxpr().is_algorithmic()

    def get_algorithmic_features(self):
        return self.get_fxpr().get_algorithmic_features()

    def get_fxpr(self): return self.ifd.get_fxpr(int(self.args[0]))

    def record_algorithmic_features(self,d,looplevels):
        if self.is_algorithmic_feature():
            self.get_fxpr().record_algorithmic_features(d,looplevels)
            fs = self.get_fxpr().feature_string()
            if not fs in d['conditions']: d['conditions'][fs] = 0
            d['conditions'][fs] += 1
            if looplevels > 0:
                if not fs in d['inloop-conditions']: d['inloop-conditions'][fs] = 0
                d['inloop-conditions'][fs] += 1

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

    def record_algorithmic_features(self,d,looplevels):
        if self.is_algorithmic_feature():
            self.get_rhs().record_algorithmic_features(d,looplevels)
            rhsf = self.get_rhs().feature_string()
            lhsf = self.get_lhs().feature_string()
            fs = lhsf + ' := ' + rhsf
            if not fs in d['assigns']: d['assigns'][fs] = 0
            d['assigns'][fs] += 1
            if looplevels > 0:
                if not fs in d['inloop-assigns']: d['inloop-assigns'][fs] = 0
                d['inloop-assigns'][fs] += 1
        return

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

    def record_algorithmic_features(self,d,looplevels):
        fs = self.get_cms().get_method_signature().get_name()
        if not fs in  d['callees']: d['callees'][fs] = 0
        d['callees'][fs] +=  1

    def record_db_features(self,d,looplevels):
        fs = self.__str__()
        if not fs in d ['callees']: d['callees'][fs] = 0
        d['callees'][fs] += 1

    def __str__(self):
        return ('P:' + str(self.get_cms()) + '('
                    + ','.join( [ str(x) for x in self.get_args() ] ) + ')')

class FTReturn(FTXFeature):

    def __init__(self,ifd,index,tags,args):
        FTXFeature.__init__(self,ifd,index,tags,args)

    def is_algorithmic_feature(self): return  self.get_fxpr().is_algorithmic()

    def get_algorithmic_features(self):
        return self.get_fxpr().get_algorithmic_features()

    def record_algorithmic_features(self,d,looplevels):
        if self.is_algorithmic_feature():
            self.get_fxpr().record_algorithmic_features(d,looplevels)
            fs = self.get_fxpr().feature_string()
            if not fs in d['return']: d['return'][fs] = 0
            d['return'][fs] += 1
            if looplevels > 0:
                if not fs in d['inloop-returns']: d['inloop-returns'][fs] = 0
                d['inloop-returns'][fs] += 1

    def record_db_features(self,d,looplevels):
        self.get_fxpr().record_db_features(d,looplevels)

    def get_fxpr(self): return self.ifd.get_fxpr(int(self.args[0]))

    def feature_string(self): return 'R:' + self.get_fxpr().feature_string()

    def __str__(self): return 'R:' + str(self.get_fxpr())
        

class FTThrow(FTXFeature):

    def __init__(self,ifd,index,tags,args):
        FTXFeature.__init__(self,ifd,index,tags,args)

    def get_fxpr(self): return self.ifd.get_fxpr(int(self.args[0]))

    def __str__(self): return 'T:' + str(self.get_fxpr())
