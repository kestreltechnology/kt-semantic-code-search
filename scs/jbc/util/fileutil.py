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

import json
import os
import xml.etree.ElementTree as ET

from scs.jbc.util.Config import Config

config = Config()

"""
Create (if necessary) and return the directory d/pckmd5[0:2]/pckmd5[2:4]/pckmd5[4:32].
"""
def get_postings_dir(d,pckmd5,create=True):
    d1 = pckmd5[0:2]
    d2 = pckmd5[2:4]
    d3 = pckmd5[4:32]
    fd1 = os.path.join(d,d1)
    fd2 = os.path.join(fd1,d2)
    fd3 = os.path.join(fd2,d3)
    if not os.path.exists(fd3) and create:
        print('Creating directory ' + fd3)
        os.makedirs(fd3)
    return fd3

"""
Create (if necessary) and return the directory d/md5[0]/md5[1]/md5[2]/md5[3]
"""
def get_md5_1111_dir(d,md5,create=True):
    d1 = md5[0]
    d2 = md5[1]
    d3 = md5[2]
    d4 = md5[3]
    fd1 = os.path.join(d,d1)
    fd2 = os.path.join(fd1,d2)
    fd3 = os.path.join(fd2,d3)
    fd4 = os.path.join(fd3,d4)
    if not os.path.exists(fd4) and create:
        os.makedirs(fd4)
    return fd4

"""
Create (if necessary) and return the directory d/md5[0]/md5[1]/md5[2]/md5[3]
"""
def get_cmd5_filename(d,md5):
    dir = get_md5_1111_dir(d,md5)
    return os.path.join(dir,md5 + '.xml')

"""
Create (if necessary) the three toplevel directories of the index and the
administration file in directory d.
"""
def create_index_directories(d):
    if not os.path.exists(d):
        os.makedirs(d)
    if not os.path.exists(os.path.join(d,'docindex')): os.makedirs(os.path.join(d,'docindex'))
    if not os.path.exists(os.path.join(d,'vocabulary')): os.makedirs(os.path.join(d,'vocabulary'))
    if not os.path.exists(os.path.join(d,'postings')): os.makedirs(os.path.join(d,'postings'))
    dcfile = os.path.join(d,'documentcounter.json')
    if not os.path.isfile(dcfile):
        dcdict = {}
        dcdict['docoffset'] = 0
        with open(dcfile,'w') as fp:
            json.dump(dcdict,fp)

"""
Create (if necessary) the features and features/docindex directories
"""
def create_features_docindex_directory(d):
    if not os.path.exists(d): os.makedirs(d)
    docindexdir = os.path.join(d,'docindex')
    if not os.path.exists(docindexdir): os.makedirs(docindexdir)
     
def get_indexjar_filename(d):
    parentdir = os.path.dirname(d.rstrip(os.sep))
    indexbasename = os.path.basename(d.rstrip(os.sep))
    jarfilename = indexbasename + '.jar'
    return (parentdir,indexbasename,jarfilename)

def load_features_jarmanifest(d):
    ddict = {}
    filename = os.path.join(d,'features-jarmanifest.json')
    if os.path.isfile(filename):
        with open(filename,'r') as fp:
            ddict.update(json.load(fp))
    return ddict

def save_features_jarmanifest(d,ddict):
    filename = os.path.join(d,'features-jarmanifest.json')
    with open(filename,'w') as fp:
        json.dump(ddict,fp,indent=3)

def load_features_classmd5_index(d):
    ddict = {}
    filename = os.path.join(d,'features-classmd5s.json')
    if os.path.isfile(filename):
        with open(filename,'r') as fp:
            ddict.update(json.load(fp))
    return ddict

def save_features_classmd5_index(d,ddict):
    filename = os.path.join(d,'features-classmd5s.json')
    with open(filename,'w') as fp:
        json.dump(ddict,fp,indent=3)

def load_project_file(d):
    ddict = {}
    filename = os.path.join(os.path.join(d,'docindex'),'projects.json')
    if os.path.isfile(filename):
        with open(filename,'r') as fp:
            ddict.update(json.load(fp))
    return ddict

def save_project_file(d,ddict):
    filename = os.path.join(os.path.join(d,'docindex'),'projects.json')
    with open(filename,'w') as fp:
        json.dump(ddict,fp,indent=3)
    
"""
Load docindex json files.
"""
def load_docindex_file(d,name):
    ddict = {}
    if d == None: return ddict
    filename = os.path.join(os.path.join(d,'docindex'),name + '.json')
    if os.path.isfile(filename):
        with open(filename,'r') as fp:
            ddict.update(json.load(fp))
    else:
        print('docindex file ' + filename + ' not found')
    return ddict

def load_signature_index(d): return load_docindex_file(d,'signatures')

def load_classmd5_index(d): return load_docindex_file(d,'classmd5s')

def load_jarmd5_index(d): return load_docindex_file(d,'jarmd5s')

def load_package_index(d): return load_docindex_file(d,'packages')

def load_classname_index(d): return load_docindex_file(d,'classnames')

def load_methodname_index(d): return load_docindex_file(d,'methodnames')

def load_classmd5_xref(d): return load_docindex_file(d,'classmd5xref')

def load_jarmd5_xref(d): return load_docindex_file(d,'jarmd5xref')

def load_jarnames(d): return load_docindex_file(d,'jarnames')

def load_jar_manifest(d): return load_docindex_file(d,'jarmanifest')

def load_package_digest(d): return load_docindex_file(d,'pckdigest')


"""
save docindex json files
"""
def save_docindex_file(d,name,ddict):
    if not ddict is None:
        filename = os.path.join(os.path.join(d,'docindex'),name + '.json')
        with open(filename,'w') as fp:
            json.dump(ddict,fp,sort_keys=True,indent=3)
    else:
        print('Docindex file for ' + name + ' not saved: found None')

def save_signature_index(d,ddict): save_docindex_file(d,'signatures',ddict)

def save_classmd5_index(d,ddict): save_docindex_file(d,'classmd5s',ddict)

def save_jarmd5_index(d,ddict): save_docindex_file(d,'jarmd5s',ddict)

def save_package_index(d,ddict): save_docindex_file(d,'packages',ddict)

def save_classname_index(d,ddict): save_docindex_file(d,'classnames',ddict)

def save_methodname_index(d,ddict): save_docindex_file(d,'methodnames',ddict)

def save_classmd5_xref(d,ddict): save_docindex_file(d,'classmd5xref',ddict)

def save_jarmd5_xref(d,ddict): save_docindex_file(d,'jarmd5xref',ddict)

def save_jarnames(d,ddict): save_docindex_file(d,'jarnames',ddict)

def save_jarmanifest(d,ddict): save_docindex_file(d,'jarmanifest',ddict)

def save_package_digest(d,ddict): return save_docindex_file(d,'pckdigest',ddict)

def load_vocabulary(d):
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

def save_vocabulary(d,ddict):
    fdir = os.path.join(d,'vocabulary')
    if not os.path.exists(fdir):
        os.makedirs(fdir)
    for fs in ddict:
        filename = os.path.join(fdir,fs + '.json')
        with open(filename,'w') as fp:
            json.dump(ddict[fs],fp,sort_keys=True,indent=3)

def load_docoffset(d):
    if d == None: return 0
    dcfile = os.path.join(d,'documentcounter.json')
    if os.path.isfile(dcfile):
        with open(dcfile,'r') as fp:
            d = json.load(fp)
        if 'docoffset' in d:
            return int(d['docoffset'])
        else:
            print('Documentcounter file is corrupted')
    else:
        print('Documentcounter file not found')
        return 0

def save_docoffset(d,c):
    dcfile = os.path.join(d,'documentcounter.json')
    dcdict = {}
    dcdict['docoffset'] = c
    with open(dcfile,'w') as fp:
        json.dump(dcdict,fp)
    

def load_documents_file(d,pckmd5):
    if d == None: return {}
    fdir = get_postings_dir(os.path.join(d,'postings'),pckmd5)
    filename = os.path.join(fdir,pckmd5 + '_documents.json')
    if os.path.isfile(filename):
        with open(filename,'r') as fp:
            return json.load(fp)
    else:
        return {}


def load_postings_files(d,pckmd5):
    ddict = {}
    if d == None: return ddict
    fdir = get_postings_dir(os.path.join(d,'postings'),pckmd5)
    if os.path.isdir(fdir):
        files = os.listdir(fdir)
        for f in files:
            if f.endswith('_documents.json'): continue
            fs = f[33:-5]
            # print(fs)
            with open(os.path.join(fdir,f)) as fp:
                ddict[fs] = json.load(fp)
    return ddict
    

def save_documents_file(d,pckmd5,ddict):
    fdir = get_postings_dir(os.path.join(d,'postings'), pckmd5)
    filename = os.path.join(fdir,pckmd5 + '_documents.json')
    with open(filename,'w') as fp:
        json.dump(ddict,fp)   
                                            
def save_postings_files(d,pckmd5,ddict):
    fdir = get_postings_dir(os.path.join(d,'postings'), pckmd5)
    for fs in ddict:
        filename = os.path.join(fdir,pckmd5 + '_' + fs + '.json')
        with open(filename,'w') as fp:
            json.dump(ddict[fs],fp)

def get_xnode(filename,nodename):
    xroot = ET.parse(filename)
    if not xroot is None:
        return xroot.find(nodename)

def load_features_file(featurespath,cmd5):
    filename = get_cmd5_filename(featurespath,cmd5)
    return get_xnode(filename,'class')


def get_algorithms_dir():
    return  os.path.join(config.datadir,'algorithms')

def get_algorithms_query_dir():
    return os.path.join(get_algorithms_dir(),'queries')

def get_algorithms_indexedfeatures_dir():
    return os.path.join(get_algorithms_dir(),'indexedfeatures')

def get_algorithms_query(q):
    filename = os.path.join(get_algorithms_query_dir(),q)
    if os.path.isfile(filename): return filename

def get_algorithms_indexedfeatures(f):
    filename = os.path.join(get_algorithms_indexedfeatures_dir(),f)
    if os.path.isfile(filename): return filename
