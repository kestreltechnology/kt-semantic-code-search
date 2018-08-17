# ------------------------------------------------------------------------------
# Python API to access CodeHawk Java Analyzer analysis results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2017 Kestrel Technology LLC
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

import locale
import hashlib
import os
import shutil
import subprocess

from jbcmlscs.util.Config import Config
from jbcmlscs.index.JJarMd5Index import JJarMd5Index

import jbcmlscs.util.fileutil as UF

class AnalysisManager():

    def __init__(self,featurespath):
        '''Initialize analyzer location and target jar locations

        Arguments:
        featurespath  -- path of the directory in which to save the analysis results
        '''

        self.config = Config()
        self.chjpath = self.config.chjpath
        self.featurespath = featurespath

    def _makedir(self,name):
        if os.path.isdir(name): return
        print('mkdir ' + name)
        os.mkdir(name)

    def getjarmd5_linux(self,jarfile):
        jarfile = jarfile.replace(' ','\ ')
        cmd = 'md5sum ' + jarfile
        result = subprocess.check_output(cmd, shell=True,universal_newlines=True)
        return result.strip()[:32]

    def getjarmd5_mac(self,jarfile):
        jarfile = jarfile.replace(' ','\ ')
        cmd = 'md5 ' + jarfile
        result = subprocess.check_output(cmd, shell=True,universal_newlines=True)
        return result.strip()[-32:]

    def getjarmd5(self,jarfile):
        md5 = hashlib.md5(open(jarfile,'rb').read()).hexdigest()
        return md5

    def get_generatefeatures_cmd(self, jarname):
        cmd = self.config.chjcommand
        f1 = ' -feature method_sizes '
        f2 = ' -feature method_assignments '
        f3 = ' -feature method_attrs '
        f4 = ' -feature method_branch_conditions '
        f5 = ' -feature method_libcalls '
        f6 = ' -feature method_literals '
        f7 = ' -feature method_api-types '
        f8 = ' -feature method_libcalls_sig '
        odir = ' -o ' + self.featurespath + ' '
        logdir = ' -log features.jchlog '
        cmd = cmd + f1 + f2 + f3 + f4 + f5 + f6 + f7 + f8 + odir + logdir + jarname
        return cmd


    def generatefeatures(self,jarname):
        cmd = self.get_generatefeatures_cmd(jarname)			
        result = subprocess.check_output(cmd, shell=True)
        return result
        



