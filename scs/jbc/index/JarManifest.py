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

import scs.jbc.util.fileutil as UF

class JarManifest():
    """Relates jar md5 indices to the class md5 indices in the jar.

    Format: jmd5ix -> pckix -> cmd5ix list
    """

    def __init__(self,indexpath):
        self.indexpath = indexpath
        self.xref = UF.load_jar_manifest(self.indexpath)

    def add_xref(self,jmd5ix,pckix,cmd5ix):
        if not (pckix in self.xref[jmd5ix]['packages']):
            self.xref[jmd5ix]['packages'][pckix] = []
        if not (cmd5ix in self.xref[jmd5ix]['packages'][pckix]):
            self.xref[jmd5ix]['packages'][pckix].append(cmd5ix)

    def has_jar(self,jmd5ix): return jmd5ix in self.xref

    def get_files(self,jmd5ix):
        if jmd5ix in self.xref: return self.xref[jmd5ix]['files']

    def get_pckixs(self,jmd5ix):
        if jmd5ix in self.xref: return self.xref[jmd5ix]['packages']

    def get_cmd5ixs(self,jmd5ix,pckix):
        if jmd5ix in self.xref:
            if pckix in self.xref[jmd5ix]['packages']:
                return self.xref[jmd5ix]['packages'][pckix]

    def add_file(self,jmd5ix,name):
        if not jmd5ix in self.xref:
            self.xref[jmd5ix] = {}
            self.xref[jmd5ix]['files'] = []
            self.xref[jmd5ix]['packages'] = {}
        if not name in self.xref[jmd5ix]['files']:
            self.xref[jmd5ix]['files'].append(name)

    def get_cmd5ixs(self,jmd5ix):
        result = []
        if jmd5ix in self.xref:
            for pckix in self.xref[jmd5ix]['packages']:
                result += self.xref[jmd5ix]['packages'][pckix]
        return result

    def get_jarixs_for_cmd5ix(self,cmd5ix):
        result = []
        for jmd5ix in self.xref:
            for pckix in self.xref[jmd5ix]['packages']:
                if cmd5ix in self.xref[jmd5ix]['packages'][pckix]:
                    result.append(jmd5ix)
        return result

    def save(self): UF.save_jarmanifest(self.indexpath,self.xref)
            
