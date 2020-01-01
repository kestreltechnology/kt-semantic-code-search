# ------------------------------------------------------------------------------
# Python API to access CodeHawk Binary Analyzer analysis results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2019 Kestrel Technology LLC
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

from scs.x86x.util.Config import Config

class KTError(Exception):

    def wrap(self):
        lines = []
        lines.append('*' * 80)
        lines.append(self.__str__())
        lines.append('*' * 80)
        return '\n'.join(lines)

class KTFileNotFoundError(KTError):

    def __init__(self,filename):
        KTError.__init__(self,"File " + filename + " not found")
        self.filename = filename


class KTXmlParseError(KTError):

    def __init__(self,filename,errorcode,position):
        KTError.__init__(self,'Xml parse error')
        self.filename = filename
        self.errorcode = errorcode
        self.position = position

    def __str__(self):
        return ('XML parse error in ' + filename + ' (errorcode: '
                    + str(self.errorcode) + ') at position ' + str(self.position))

class KTJsonParseError(KTError):

    def __init__(self,filename,e):
        KTError.__init__(self,'Json Parse Error')
        self.filename = filename
        self.valueerror = e

    def __str__(self):
        return 'JSON parse error in file: ' + self.filename + ': ' + str(self.valueerror)


def get_ioc_featurenames_file():
    filename = os.path.join(Config().featuresdir,'ioc_feature_names.json')
    if not os.path.isfile(filename):
        raise KTFileNotFoundError(filename)
    try:
        with open(filename,'r') as fp:
            return json.load(fp)
    except ValueError as error:
        raise KTJsonParseError(filename,error)

def get_project_dictionary(path,filename):
    filename = os.path.join(path,filename)
    if os.path.isfile(filename):
        with open(filename,'r') as fp:
            executables = json.load(fp)
            return executables['executables']
    raise KTCHBFileNotFoundError('File does not exist: ' + filename)

def get_executable_dir(path,xfile):
    xdir = os.path.join(path,xfile + '.ch')
    return os.path.join(xdir,'x')

def get_statistics_dir(path,xfile):
    return os.path.join(path,xfile + '.chs')

def get_pe_header_filename(path,xrec):
    try:
        path = os.path.join(path,xrec['path'])
        xfile = xrec['file']                            
        xxfile = xfile.replace('.','_')
        fdir = get_executable_dir(path,xfile)
        return os.path.join(fdir,xxfile + '_pe_header.xml')
    except Exception as e:
        print(str(e))
        print(str(xrec))
        raise

def get_features_filename(path,xrec):
    try:
        path = os.path.join(path,xrec['path'])
        xfile = xrec['file']
        xxfile = xfile.replace('.','_')
        fdir = get_statistics_dir(path,xfile)
        return os.path.join(fdir,xxfile + '_features.json')
    except Exception as e:
        print(str(e))
        print(str(xrec))
        raise

def get_results_dir(path,xfile):
    rdir = os.path.join(path,xfile + '.ch')
    return os.path.join(rdir,'results')

def get_xmd5_filename(path,xrec):
    path = os.path.join(path,xrec['path'])
    xfile = xrec['file']
    xxfile = xfile.replace('.','_')
    return os.path.join(get_results_dir(path,xfile),xxfile + '_md5.json')

def get_metadata_filename(key,xrec):
    vtmetadir = Config().vtmetadir
    if vtmetadir is None:
        print('Metadata directory not available')
        exit(1)
    sha256 = xrec['sha256'] if 'sha256' in xrec else xrec['sha-256']
    shadir = os.path.join(sha256[0],os.path.join(sha256[1],sha256[2]))
    path = os.path.join(vtmetadir,shadir)
    return os.path.join(path,key + '_vtmeta')

def get_fnmd5_dict(path,xrec):
    filename = get_xmd5_filename(path,xrec)
    if os.path.isfile(filename):
        with open(filename,'r') as fp:
            functionmd5s = json.load(fp)
            return functionmd5s['md5s']
    return {}

def get_pe_xnode(path,xrec):
    filename = get_pe_header_filename(path,xrec)
    if os.path.isfile(filename):
        try:
            tree = ET.parse(filename)
            peheader = tree.getroot().find('pe-header')
        except ET.ParseError as e:
            raise KTCHBXmlParseError(filename,e.code,e.position)
        return peheader
    else:
        raise KTCHBFileNotFoundError('File not found: ' + filename)

def get_semantic_features(path,xrec):
    filename = get_features_filename(path,xrec)
    if os.path.isfile(filename):
        with open(filename,'r') as fp:
            return json.load(fp)
    else:
        return {}

def get_vtmetadata_dict(key,xrec):
    filename = get_metadata_filename(key,xrec)
    if os.path.isfile(filename):
        with open(filename,'r') as fp:
            vtmetadata = json.load(fp)
        print(str(vtmetadata.keys()))
        print(str(vtmetadata['results'].keys()))
        return vtmetadata['results']
    return {}

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

def load_xmd5_index(d): return load_docindex_file(d,'xmd5s')

def load_xmd5_xref(d): return load_docindex_file(d,'xmd5xref')

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

def load_postings_files(d):
    ddict = {}
    if d == None: return ddict
    fdir = os.path.join(d,'postings')
    if os.path.isdir(fdir):
        files = os.listdir(fdir)
        for f in files:
            if f.endswith('_documents.json'): continue
            featuresetname = f.replace('.json','')
            with open(os.path.join(fdir,f)) as fp:
                ddict[featuresetname] = json.load(fp)
    return ddict

def save_postings_files(d,ddict):
    fdir = os.path.join(d,'postings')
    for fs in ddict:
        filename = os.path.join(fdir,fs + '.json')
        with open(filename,'w') as fp:
            json.dump(ddict[fs],fp)

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

def save_xmd5_index(d,ddict): save_docindex_file(d,'xmd5s',ddict)

def save_xmd5_xref(d,ddict): save_docindex_file(d,'xmd5xref',ddict)

def save_vocabulary(d,ddict):
    fdir = os.path.join(d,'vocabulary')
    if not os.path.exists(fdir):
        os.makedirs(fdir)
    for fs in ddict:
        filename = os.path.join(fdir,fs + '.json')
        with open(filename,'w') as fp:
            json.dump(ddict[fs],fp,sort_keys=True,indent=3)

def save_similar(results, filename):
    results_dict = {}
    for m in sorted(results['exes'],key=lambda m:(m['score'],m['name'][0]),reverse=True):
        results_dict[ ','.join([ str(x) for x in m['name']]) ] = m['score']
    with open(filename,'w') as fp:
        json.dump(results_dict, fp, sort_keys=True, indent=3)
