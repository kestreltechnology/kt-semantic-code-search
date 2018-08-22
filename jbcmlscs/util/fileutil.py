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

import json
import os
import xml.etree.ElementTree as ET


'''
Create (if necessary) and return the directory d/pckmd5[0:2]/pckmd5[2:4]/pckmd5[4:32].
'''
def getdatadir(d,pckmd5,create=True):
    d1 = pckmd5[0:2]
    d2 = pckmd5[2:4]
    d3 = pckmd5[4:32]
    fd1 = os.path.join(d,d1)
    fd2 = os.path.join(fd1,d2)
    fd3 = os.path.join(fd2,d3)
    if not os.path.exists(fd3) and create:
        # print('Creating directory ' + fd3)
        os.makedirs(fd3)
    return fd3

def getmd5_1111_dir(d,md5,create=True):
    d1 = md5[0:1]
    d2 = md5[1:2]
    d3 = md5[2:3]
    d4 = md5[3:4]
    fd1 = os.path.join(d,d1)
    fd2 = os.path.join(fd1,d2)
    fd3 = os.path.join(fd2,d3)
    fd4 = os.path.join(fd3,d4)
    if not os.path.exists(fd4) and create:
        os.makedirs(fd4)
    return fd4

def getcmd5_filename(d,md5):
    dir = getmd5_1111_dir(d,md5)
    return os.path.join(dir,md5 + '.xml')

'''
Create (if necessary) the three toplevel directories of the index and the
administration file in directory d.
'''
def createindexdirectories(d):
    if not os.path.exists(d):
        os.makedirs(d)
    if not os.path.exists(os.path.join(d,'docindex')):
        os.makedirs(os.path.join(d,'docindex'))
        os.makedirs(os.path.join(d,'vocabulary'))
        os.makedirs(os.path.join(d,'data'))
    adminfile = os.path.join(d,'admin.json')
    if not os.path.isfile(adminfile):
        admindict = {}
        admindict['docoffset'] = 0
        with open(adminfile,'w') as fp:
            json.dump(admindict,fp)

def getindexjarfilename(d):
    parentdir = os.path.dirname(d.rstrip(os.sep))
    indexbasename = os.path.basename(d.rstrip(os.sep))
    jarfilename = indexbasename + '.jar'
    return (parentdir,indexbasename,jarfilename)

def loadprojectfile(d):
    ddict = {}
    filename = os.path.join(os.path.join(d,'docindex'),'projects.json')
    if os.path.isfile(filename):
        with open(filename,'r') as fp:
            ddict.update(json.load(fp))
    return ddict

def saveprojectfile(d,ddict):
    filename = os.path.join(os.path.join(d,'docindex'),'projects.json')
    with open(filename,'w') as fp:
        json.dump(ddict,fp,indent=3)
    
'''
Load docindex json files.
'''
def loaddocindexfile(d,name):
    ddict = {}
    if d == None: return ddict
    filename = os.path.join(os.path.join(d,'docindex'),name + '.json')
    if os.path.isfile(filename):
        with open(filename,'r') as fp:
            ddict.update(json.load(fp))
    else:
        print('docindex file ' + filename + ' not found')
    return ddict

def loadsignatureindex(d): return loaddocindexfile(d,'signatures')

def loadclassmd5index(d): return loaddocindexfile(d,'classmd5s')

def loadjarmd5index(d): return loaddocindexfile(d,'jarmd5s')

def loadpackageindex(d): return loaddocindexfile(d,'packages')

def loadclassnameindex(d): return loaddocindexfile(d,'classnames')

def loadmethodnameindex(d): return loaddocindexfile(d,'methodnames')

def loadclassmd5xref(d): return loaddocindexfile(d,'classmd5xref')

def loadjarmd5xref(d): return loaddocindexfile(d,'jarmd5xref')

def loadjarnames(d): return loaddocindexfile(d,'jarnames')

def loadpackagedigest(d): return loaddocindexfile(d,'pckdigest')

def savedocindexfile(d,name,ddict):
    if not ddict is None:
        filename = os.path.join(os.path.join(d,'docindex'),name + '.json')
        with open(filename,'w') as fp:
            json.dump(ddict,fp,sort_keys=True,indent=3)
    else:
        print('Docindex file for ' + name + ' not saved: found None')

def savesignatureindex(d,ddict): savedocindexfile(d,'signatures',ddict)

def saveclassmd5index(d,ddict): savedocindexfile(d,'classmd5s',ddict)

def savejarmd5index(d,ddict): savedocindexfile(d,'jarmd5s',ddict)

def savepackageindex(d,ddict): savedocindexfile(d,'packages',ddict)

def saveclassnameindex(d,ddict): savedocindexfile(d,'classnames',ddict)

def savemethodnameindex(d,ddict): savedocindexfile(d,'methodnames',ddict)

def saveclassmd5xref(d,ddict): savedocindexfile(d,'classmd5xref',ddict)

def savejarmd5xref(d,ddict): savedocindexfile(d,'jarmd5xref',ddict)

def savejarnames(d,ddict): savedocindexfile(d,'jarnames',ddict)

def savepackagedigest(d,ddict): return savedocindexfile(d,'pckdigest',ddict)

def loadvocabulary(d):
    ddict = {}
    if d == None: return ddict
    fdir = os.path.join(d,'vocabulary')
    if os.path.exists(fdir):
        for f in os.listdir(fdir):
            filename = os.path.join(fdir,f)
            featuresetname = f.replace('.json','')
            with open(filename,'r') as fp:
                ddict[featuresetname] = json.load(fp)
    return ddict

def savevocabulary(d,ddict):
    fdir = os.path.join(d,'vocabulary')
    if not os.path.exists(fdir):
        os.makedirs(fdir)
    print('Saving vocabulary files ...')
    for fs in ddict:
        filename = os.path.join(fdir,fs + '.json')
        with open(filename,'w') as fp:
            json.dump(ddict[fs],fp,sort_keys=True,indent=3)

def loaddocoffset(d):
    if d == None: return 0
    adminfile = os.path.join(d,'admin.json')
    if os.path.isfile(adminfile):
        with open(adminfile,'r') as fp:
            d = json.load(fp)
        if 'docoffset' in d:
            return int(d['docoffset'])
        else:
            print('Admin file is corrupted')
    else:
        print('Admin file not found')

def loaddocumentsfile(d,pckmd5):
    if d == None: return {}
    fdir = getdatadir(os.path.join(d,'data'),pckmd5)
    filename = os.path.join(fdir,pckmd5 + '_documents.json')
    if os.path.isfile(filename):
        with open(filename,'r') as fp:
            return json.load(fp)
    else:
        return {}


def loaddatafiles(d,pckmd5):
    ddict = {}
    if d == None: return ddict
    fdir = getdatadir(os.path.join(d,'data'),pckmd5)
    if os.path.isdir(fdir):
        files = os.listdir(fdir)
        for f in files:
            if f.endswith('_documents.json'): continue
            fs = f[33:-5]
            # print(fs)
            with open(os.path.join(fdir,f)) as fp:
                ddict[fs] = json.load(fp)
    return ddict
    

def savedocumentsfile(d,pckmd5,ddict):
    fdir = getdatadir(os.path.join(d,'data'), pckmd5)
    # print('Saving documents file in ' + fdir + ' ...')
    filename = os.path.join(fdir,pckmd5 + '_documents.json')
    with open(filename,'w') as fp:
        json.dump(ddict,fp)   
                                            
def savedatafiles(d,pckmd5,ddict):
    fdir = getdatadir(os.path.join(d,'data'), pckmd5)
    # print('Saving data files in ' + fdir + ' ...')
    for fs in ddict:
        filename = os.path.join(fdir,pckmd5 + '_' + fs + '.json')
        with open(filename,'w') as fp:
            json.dump(ddict[fs],fp)

def getxrootnode(filename):
    return ET.parse(filename)

def getxnode(filename,nodename):
    xroot = ET.parse(filename)
    if not xroot is None:
        return xroot.find(nodename)
