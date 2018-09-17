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

import os

if os.path.isfile(os.path.join(os.path.dirname(os.path.abspath(__file__)),'ConfigLocal.py')):
    import scs.jbc.util.ConfigLocal as ConfigLocal

class Config():

    def __init__(self):
        '''Configuration settings for platform.'''

        '''default settings'''
        self.utildir = os.path.dirname(os.path.abspath(__file__))
        self.rootdir = os.path.dirname(self.utildir)
        self.bindir = os.path.join(self.rootdir,'binaries')
        self.chjpath = self.bindir

        # Update platform as required
        if os.uname()[0] == 'Linux':
            self.platform = 'linux'
        elif os.uname()[0] == 'Darwin':
            self.platform ='mac'

        self.codehawk = os.path.join(self.chjpath,'chj_features_' + self.platform)

        if os.path.isfile(os.path.join(self.utildir,'ConfigLocal.py')):
            ConfigLocal.getLocals(self)
