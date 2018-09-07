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

import jbcmlscs.util.IndexedTable as IT
import jbcmlscs.util.StringIndexedTable as ITS
import jbcmlscs.ifeatures.IFeatureTypes as FT

object_type_constructors = {
    'c': lambda x:FT.FTClassObjectType(*x),
    'a': lambda x:FT.FTArrayObjectType(*x)
    }

value_type_constructors = {
    'o': lambda x:FT.FTObjectValueType(*x),
    'b': lambda x:FT.FTBasicValueType(*x)
    }

constant_value_constructors = {
    's': lambda x:FT.FTConstString(*x),
    'i': lambda x:FT.FTConstInt(*x),
    'f': lambda x:FT.FTConstFloat(*x),
    'l': lambda x:FT.FTConstLong(*x),
    'd': lambda x:FT.FTConstDouble(*x),
    'c': lambda x:FT.FTConstClass(*x)
    }

opcode_constructors = {
    'bb': lambda x:FT.FTNewObject(*x),
    'bd': lambda x:FT.FTNewArray(*x),
    'be': lambda x:FT.FTArrayLength(*x),
    'c1': lambda x:FT.FTInstanceOf(*x),
    'c5': lambda x:FT.FTNewMultiArray(*x)
    }

fxpr_constructors = {
    'v': lambda x:FT.FTXVar(*x),
    'f': lambda x:FT.FTXField(*x),
    'a': lambda x:FT.FTXArrayElem(*x),
    'c': lambda x:FT.FTXConst(*x),
    'x': lambda x:FT.FTXOp(*x),
    'fc': lambda x:FT.FTXFunctionCall(*x),
    's': lambda x:FT.FTXAttr(*x),
    'm': lambda x:FT.FTXMultiple(*x),
    'e': lambda x:FT.FTXException(*x),
    'n': lambda x:FT.FTXNull(*x),
    'u': lambda x:FT.FTXUnknown(*x)
    }

fxfeature_constructors = {
    'c': lambda x:FT.FTCondition(*x),
    'a': lambda x:FT.FTAssignment(*x),
    'p': lambda x:FT.FTProcedurecall(*x),
    'r': lambda x:FT.FTReturn(*x),
    't': lambda x:FT.FTThrow(*x)
    }
    
def opcode_instruction(tag,args):
    if tag in FT.arithmetic_opcodes:
        return FT.FTArithmeticInstr(*args)
    if tag in FT.converter_opcodes:
        return FT.FTConverterInstr(*args)
    if tag in FT.comparison_opcodes:
        return FT.FTComparisonInstr(*args)
    if tag in FT.test_opcodes:
        return FT.FTTestInstr(*args)
    if tag in opcode_constructors:
        return opcode_constructors[tag](args)
    return FT.FTOpcode(*args)
    
class IClassDictionary:

    def __init__(self,iclass,xnode):
        self.iclass = iclass
        self.xnode = xnode
        self.class_name_table = IT.IndexedTable('class-name-table')
        self.object_type_table = IT.IndexedTable('object-type-table')
        self.value_type_table = IT.IndexedTable('value-type-table')
        self.fs_table = IT.IndexedTable('fs-table')
        self.ms_table = IT.IndexedTable('ms-table')
        self.cfs_table = IT.IndexedTable('cfs-table')
        self.cms_table = IT.IndexedTable('cms-table')
        self.opcode_table = IT.IndexedTable('opcode-table')
        self.constant_value_table = IT.IndexedTable('constant-value-table')
        self.fxfeature_table = IT.IndexedTable('fxfeature-table')
        self.fxpr_table = IT.IndexedTable('fxpr-table')
        self.string_table = ITS.StringIndexedTable('string-table')
        self.tables = [
            (self.string_table, self._read_xml_string_table),
            (self.class_name_table, self._read_xml_class_name_table),
            (self.object_type_table, self._read_xml_object_type_table),
            (self.value_type_table, self._read_xml_value_type_table),
            (self.fs_table, self._read_xml_fs_table),
            (self.ms_table, self._read_xml_ms_table),
            (self.cfs_table, self._read_xml_cfs_table),
            (self.cms_table, self._read_xml_cms_table),
            (self.opcode_table, self._read_xml_opcode_table),
            (self.constant_value_table, self._read_xml_constant_value_table),
            (self.fxpr_table, self._read_xml_fxpr_table),
            (self.fxfeature_table, self._read_xml_fxfeature_table)
            ]
        self.initialize(xnode)

    def get_string(self,ix): return self.string_table.retrieve(ix)

    def get_class_name(self,ix): return self.class_name_table.retrieve(ix)

    def get_object_type(self,ix): return self.object_type_table.retrieve(ix)

    def get_value_type(self,ix): return self.value_type_table.retrieve(ix)

    def get_fs(self,ix): return self.fs_table.retrieve(ix)

    def get_cfs(self,ix): return self.cfs_table.retrieve(ix)

    def get_ms(self,ix): return self.ms_table.retrieve(ix)

    def get_cms(self,ix): return self.cms_table.retrieve(ix)

    def get_opcode(self,ix): return self.opcode_table.retrieve(ix)

    def get_constant_value(self,ix): return self.constant_value_table.retrieve(ix)

    def get_fxpr(self,ix): return self.fxpr_table.retrieve(ix)

    def get_fxfeature(self,ix): return self.fxfeature_table.retrieve(ix)

    def initialize(self,xnode):
        if xnode is None: return
        for (t,f) in self.tables:
            f(xnode.find(t.name))

    def _read_xml_string_table(self,txnode):
        self.string_table.read_xml(txnode)

    def _read_xml_class_name_table(self,txnode):
        def get_value(node):
            rep = IT.get_rep(node)
            args = (self,) + rep
            return FT.FTClassName(*args)
        self.class_name_table.read_xml(txnode,'n',get_value)

    def _read_xml_object_type_table(self,txnode):
        def get_value(node):
            rep = IT.get_rep(node)
            tag = rep[1][0]
            args = (self,) + rep
            return object_type_constructors[tag](args)
        self.object_type_table.read_xml(txnode,'n',get_value)

    def _read_xml_value_type_table(self,txnode):
        def get_value(node):
            rep = IT.get_rep(node)
            tag = rep[1][0]
            args = (self,) + rep
            return value_type_constructors[tag](args)
        self.value_type_table.read_xml(txnode,'n',get_value)

    def _read_xml_fs_table(self,txnode):
        def get_value(node):
            rep = IT.get_rep(node)
            args =  (self,) + rep
            return FT.FTFieldSignature(*args)
        self.fs_table.read_xml(txnode,'n',get_value)

    def _read_xml_ms_table(self,txnode):
        def get_value(node):
            rep = IT.get_rep(node)
            args = (self,) + rep
            return FT.FTMethodSignature(*args)
        self.ms_table.read_xml(txnode,'n',get_value)

    def _read_xml_cfs_table(self,txnode):
        def get_value(node):
            rep = IT.get_rep(node)
            args = (self,) + rep
            return  FT.FTClassFieldSignature(*args)
        self.cfs_table.read_xml(txnode,'n',get_value)

    def _read_xml_cms_table(self,txnode):
        def get_value(node):
            rep = IT.get_rep(node)
            args = (self,) + rep
            return FT.FTClassMethodSignature(*args)
        self.cms_table.read_xml(txnode,'n',get_value)
        
    def _read_xml_opcode_table(self,txnode):
        def get_value(node):
            rep = IT.get_rep(node)
            tag = rep[1][0]
            args = (self,) + rep
            return opcode_instruction(tag,args)
        self.opcode_table.read_xml(txnode,'n',get_value)

    def _read_xml_constant_value_table(self,txnode):
        def get_value(node):
            rep = IT.get_rep(node)
            tag = rep[1][0]
            args = (self,) + rep
            return constant_value_constructors[tag](args)
        self.constant_value_table.read_xml(txnode,'n',get_value)

    def _read_xml_fxpr_table(self,txnode):
        def get_value(node):
            rep = IT.get_rep(node)
            tag = rep[1][0]
            args = (self,) + rep
            return fxpr_constructors[tag](args)
        self.fxpr_table.read_xml(txnode,'n',get_value)

    def _read_xml_fxfeature_table(self,txnode):
        def get_value(node):
            rep = IT.get_rep(node)
            tag = rep[1][0]
            args = (self,) + rep
            return fxfeature_constructors[tag](args)
        self.fxfeature_table.read_xml(txnode,'n',get_value)
