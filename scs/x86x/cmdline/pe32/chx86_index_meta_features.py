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

import argparse
import json
import os

import scs.x86x.util.fileutil as UF
from scs.x86x.util.Config import Config

from scs.x86x.features.VTMetaData import VTMetaData
from scs.x86x.features.VTMetaDataRecorder import VTMetaDataRecorder
from scs.x86x.index.IndexAdministrator import IndexAdministrator

def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('indexpath',help='directory to save the indexed features')
    parser.add_argument('--exclude_clusters','-x',nargs='*',default=[],
                            help='exclude executables from these clusters')
    parser.add_argument('--include_clusters','-i',nargs='*',default=[],
                            help='only include executables from these clusters'),    
    args = parser.parse_args()
    return args


def satisfies_spec(r,includes,excludes):
    if len(includes) > 0:
        for i in includes:
            if (not 'clusters' in r) or all([ not c.startswith(i) for c in r['clusters'] ]):
                return False
        else:
            return True
    if len(excludes) > 0:
        if not 'clusters' in r: return True
        for x in excludes:
            if any([ c.startswith(x) for c in r['clusters'] ]):
                return False
        else:
            return True
    return True

featuresets = [ 'size', 'submission_names', 'tags', 'detection_rate', 'type',
                    'magic', 'entry_point', 'trid_stemmed',
                    'detections_stemmed', 'detectors', 'non_detectors',
                    'section_names', 'named_section_md5s',
                    'named_section_virtual_addresses',
                    'named_section_raw_sizes', 'named_section_virtual_sizes',
                    'resource_file_types', 'resource_types', 'resource_languages',
                    'signers', 'counter_signers', 'publishers', 'signing_date',
                    'runtime_dlls', 'mutexes_created', 'mutexes_opened',
                    'imported_libraries', 'imported_functions',
                    'files_copied_src', 'files_copied_dst',
                    'files_deleted', 'files_downloaded',
                    'files_moved_src', 'files_moved_dst',
                    'files_opened', 'files_read',
                    'files_replaced', 'files_written',
                    'processes_created', 'processes_injected',
                    'processes_shellcmds', 'processes_terminated',
                    'network_dns_ip', 'network_dns_hostname',
                    'network_http_url', 'network_http_method', 'network_http_user_agent',
                    'network_tcp', 'network_udp',
                    'registry_deleted', 'registry_set' ]


if __name__ == '__main__':

    args = parse()

    indexadmin = IndexAdministrator(args.indexpath)
    recorder = VTMetaDataRecorder('metadata',featuresets)
    
    for root,dirs, files in os.walk(Config().vtmetadir):
        for name in files:
            if name.endswith('vtmeta'):
                recorder.reset()
                filename = os.path.join(root,name)
                print(filename)
                with open(filename,'r') as fp:
                    vtmetadata = json.load(fp)['results']
                if len(vtmetadata) > 0:
                    try:
                        vtmeta = VTMetaData(vtmetadata)
                        name = vtmeta.sha256[:3] + ':' + name
                    except:
                        print('Problem loading ' + filename)
                        raise
                else:
                    print('No meta data found for: ' + key)
                    vtmeta = None
                indexadmin.index_meta_features(name[:-7],[ recorder ],vtmeta)
    indexadmin.save_features()
