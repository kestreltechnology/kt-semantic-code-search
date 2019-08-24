# ------------------------------------------------------------------------------
# Python API to access CodeHawk Binary Analyzer analysis results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2019 Kestrel Technology LLC
#
# Permission is he/eby granted, free of charge, to any person obtaining a copy
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

class VTMetaBehaviourFileSystem(object):

    def __init__(self,data):
        self.data = data
        self.copied = [ f['src'] + ':to:' + f['dst'] for f in self.data['copied'] ]
        self.copiedsrc = [ f['src'] for f in self.data['copied'] ]
        self.copieddst = [ f['dst'] for f in self.data['copied'] ]
        self.deleted = [ f['path'] for f in self.data['deleted'] ]
        self.downloaded = self.data['downloaded']
        self.moved = [ f['src'] + ':to:' + f['dst'] for f in  self.data['moved'] ]
        self.movedsrc = [ f['src'] for f in self.data['moved'] ]
        self.moveddst = [ f['dst'] for f in self.data['moved'] ]
        self.opened = [ f['path'] for f in self.data['opened'] ]
        self.read = [ f['path'] for f in self.data['read'] ]
        self.replaced = [ f['replaced'] + ':with:' + f['replacement'] for f in self.data['replaced'] ]
        self.written = [ f['path'] for f in self.data['written'] ]

class VTMetaBehaviourMutex(object):

    def __init__(self,data):
        self.data = data
        self.created = [ m['mutex'] for m in self.data['created'] ]
        self.opened = [ m['mutex'] for m in self.data['opened'] ]

class VTMetaBehaviourNetwork(object):

    def __init__(self,data):
        self.data = data
        self.dns_ip = [ f['ip'] for f in self.data['dns'] ]
        self.dns_hostname = [ f['hostname'] for f in self.data['dns'] ]
        self.http_url = [ f['url'] for f in self.data['http'] ]
        self.http_method = [ f['method'] for f in self.data['http' ] ]
        self.http_user_agent = [ str(f['user-agent']) for f in self.data['http'] ]
        self.tcp = self.data['tcp']
        self.udp = self.data['udp']

class VTMetaBehaviourProcess(object):

    def __init__(self,data):
        self.data = data
        self.created = [ f['proc'] for f in self.data['created'] ]
        self.injected = [ f['proc'] for f in self.data['injected'] ]
        self.shellcmds = [ f['cmd'] for f in self.data['shellcmds'] ]
        self.terminated = [ f['proc'] for f in self.data['terminated'] ]

class VTMetaBehaviourRegistry(object):

    def __init__(self,data):
        self.data = data
        self.deleted = self.data['deleted']
        #self.set = self.data['set']
        self.type = [ f['type'] for f in self.data['set'] ]
        self.val = [ f['val'] for f in self.data['set'] ]
        self.key = [ f['key'] for f in self.data['set'] ]

class VTMetaBehaviourService(object):

    def __init__(self,data):
        self.data = data
        self.controlled = self.data['controlled']
        self.created = self.data['created']
        self.deleted = self.data['deleted']
        self.opened = self.data['opened']
        self.opened_managers = self.data['opened-managers']
        self.started = self.data['started']

class VTMetaBehaviourWindows(object):

    def __init__(self,data):
        self.data = data
        self.searched = self.data['searched']

class VTMetaBehaviourV1(object):

    def __init__(self,data):
        self.data = data
        self.filesystem = VTMetaBehaviourFileSystem(self.data['filesystem'])
        self.hooking = self.data['hooking']
        self.hosts_file = None
        self.mutex = VTMetaBehaviourMutex(self.data['mutex'])
        self.network = VTMetaBehaviourNetwork(self.data['network'])
        self.process = VTMetaBehaviourProcess(self.data['process'])
        self.registry = VTMetaBehaviourRegistry(self.data['registry'])
        self.runtime_dlls = [ d['file'] for d in self.data['runtime-dlls'] ]
        self.service = VTMetaBehaviourService(self.data['service'])
        self.windows = VTMetaBehaviourWindows(self.data['windows'])


class VTMetaExifTool(object):

    def __init__(self,data):
        self.data = data
        self.codesize = int(self.data.get('CodeSize','0'))
        self.companyname = self.data.get('CompanyName','')
        self.entrypoint = self.data.get('EntryPoint','')
        self.filedescription = self.data.get('FileDescription','')
        self.fileflagsmask = self.data.get('FileFlagsMask','')
        self.fileOS = self.data.get('FileOS','')
        self.filesubtype = self.data.get('FileSubtype','')
        self.filetype = self.data.get('FileType','')
        self.filetypeextension = self.data.get('FileTypeExtension','')
        self.fileversion = self.data.get('FileVersion','')
        self.fileversionnumber = self.data.get('FileVersionNumber','')
        self.imageversion = self.data.get('ImageVersion','')
        self.initializeddatasize = int(self.data.get('InitializedDataSize','0'))
        self.internalname = self.data.get('InternalName','')
        self.languagecode = self.data.get('LanguageCode','')
        self.legalcopyright = self.data.get('LegalCopyright','')
        self.linkerversion = self.data.get('LinkerVersion','')
        self.mimetype = self.data.get('MIMEType','')
        self.machinetype = self.data.get('MachineType','')
        self.osversion = self.data.get('OSVersion','')
        self.objectfiletype = self.data.get('ObjectFileType','')
        self.originalfilename = self.data.get('OriginalFileName','')
        self.petype = self.data.get('PEType','')
        self.productname = self.data.get('ProductName','')
        self.productversion = self.data.get('ProductVersion','')
        self.productversionnumber = self.data.get('ProductVersionNumber','')
        self.subsystem = self.data.get('Subsystem','')
        self.timestamp = self.data.get('TimeStamp','')
        self.uninitializeddatasize = int(self.data.get('UninitializedDataSize','0'))

class VTMetaImportLibrary(object):

    def __init__(self,name,data):
        self.name = name.lower()
        self.data = data

class VTMetaImports(object):

    def __init__(self,data):
        self.data = data
        self.dlls = [ VTMetaImportLibrary(d,data[d]) for d in self.data ]

    def get_imported_libraries(self):
        return [ d.name for d in self.dlls ]

    def get_imported_functions(self):
        result = []
        for d in self.dlls:
            result.extend( [ d.name + ':' + f for f in  d.data ])
        return result

class VTMetaPEResourceDetail(object):

    def __init__(self,detail):
        self.detail = detail
        self.filetype = self.detail['filetype']
        self.lang = self.detail['lang']
        self.sha256 = self.detail['sha256']
        self.type = self.detail['type']

class VTMetaPEResourceDetails(object):

    def __init__(self,data):
        self.data = data
        self.details = [ VTMetaPEResourceDetail(d) for d in self.data ]

    def get_file_types(self):
        return [ d.filetype for d in self.details ]

    def get_types(self):
        return [ d.type for d in self.details ]

    def get_languages(self):
        return [ d.lang for d in self.details ]

    def get_sha256s(self):
        return [ d.sha256 for d in self.details ]


class VTMetaPEResourceLangs(object):

    def __init__(self,data):
        self.data = data

class VTMetaPEResourceList(object):

    def __init__(self,data):
        self.data = data

class VTMetaPEResourceTypes(object):

    def __init__(self,data):
        self.data = data

class VTMetaPESection(object):

    def __init__(self,data):
        self.data = data
        self.name = self.data[0]
        self.virtual_address = hex(self.data[1])
        self.virtual_size = hex(self.data[2])
        self.raw_size = hex(self.data[3])
        self.entropy = self.data[4]
        self.md5 = self.data[5]

class VTMetaPESections(object):

    def __init__(self,data):
        self.data = data
        self.size = len(self.data)
        self.sections = [ VTMetaPESection(s) for s in self.data ]

    def get_section_names(self): return [ s.name for s in self.sections ]

    def get_section_md5s(self): return [ s.md5 for s in self.sections ]

    def get_named_section_md5s(self):
        return [ s.name + ':' + s.md5 for s in self.sections ]

    def get_named_section_virtual_addresses(self):
        return [ s.name + ':' + s.virtual_address for s in self.sections ]

    def get_section_raw_sizes(self):
        return [ str(s.raw_size) for s in self.sections ]

    def get_named_section_raw_sizes(self):
        return [ s.name + ':' + str(s.raw_size) for s in self.sections ]

    def get_section_virtual_sizes(self):
        return [ str(s.virtual_size) for s in self.sections ]

    def get_named_section_virtual_sizes(self):
        return [ s.name + ':' + str(s.virtual_size) for s in self.sections ]


class VTMetaSigner(object):

    def __init__(self,data):
        self.data = data
        self.algorithm = self.data['algorithm']
        self.name = self.data['name']
        self.serialnumber = self.data['serial number']
        self.status = self.data['status']
        self.thumbprint = self.data['thumbprint']
        self.validfrom = self.data['valid from']
        self.validto = self.data['valid to']
        self.validusage = self.data['valid usage']
    

class VTMetaSigCheck(object):

    def __init__(self,data):
        self.data = data
        self.copyright = self.data.get('copyright','')
        self.countersigners = self.data.get('counter signers','')
        self.countersignersdetails = [ VTMetaSigner(s) for s in self.data['counter signers details'] ] if 'counter signer details' in self.data else []
        self.description = self.data.get('description','')
        self.fileversion = self.data.get('file version','')
        self.internalname = self.data.get('internal name','')
        self.linkdate = self.data.get('link date','')
        self.originalname = self.data.get('original name','')
        self.product = self.data.get('product','')
        self.publisher = self.data.get('publisher','')
        self.signers = self.data.get('signers','')
        self.signersdetails = [ VTMetaSigner(s) for s in self.data['signers details'] ] if 'signers details' in self.data else []
        self.signingdate = self.data.get('signing date','')
        self.verified = self.data.get('verified','')



class VTMetaAdditionalInfo(object):

    def __init__(self,info):
        self.info = info
        self.behaviour_v1 = None    # VTMetaBehaviourV1
        self.exiftool = None        # VTMetaExifTool
        self.imports = None         # VTMetaImports
        self.magic = self.info['magic'] if 'magic' in self.info else None
        self.pe_entry_point = self.info['pe-entry-point'] if 'pe-entry-point' in self.info else None
        self.pe_machine_type = self.info['pe-machine-type'] if 'pe-machine-type' in self.info else None
        self.pe_time_stamp = self.info['pe-time-stamp'] if 'pe-time-stamp' in self.info else None
        self.trid = self.info['trid'] if 'trid' in self.info else None
        self.pe_resource_details = None  #  VTMetaPEResourceDetails
        self.pe_resource_langs = None    #  VTMetaPEResourceLangs
        self.pe_resource_list = None     #  VTMetaPEResourceList
        self.pe_resource_types = None    #  VTMetaPEResourceTypes
        self.pe_sections = None          #  VTMetaPESections
        self.sigcheck = None             #  VTMetaSigCheck
        self._initialize()

    def has_magic(self): return not self.magic is None

    def has_exif(self): return not self.exiftool is None

    def get_exif(self): return self.exiftool

    def has_entry_point(self): return not self.pe_entry_point is None

    def has_time_stamp(self): return not self.pe_time_stamp is None

    def has_trid(self): return not self.trid is None

    def has_imports(self): return not self.imports is None

    def get_imports(self): return self.imports

    def has_sections(self): return not self.pe_sections is None

    def get_sections(self): return self.pe_sections

    def has_resource_details(self): return not self.pe_resource_details is None

    def get_resource_details(self): return self.pe_resource_details

    def has_behaviour_v1(self): return not self.behaviour_v1 is None

    def get_behaviour_v1(self): return self.behaviour_v1

    def has_sigcheck(self): return not self.sigcheck is None

    def get_sigcheck(self): return self.sigcheck

    def _initialize(self):
        if 'behaviour-v1' in self.info:
            self.behaviour_v1 = VTMetaBehaviourV1(self.info['behaviour-v1'])
        if 'exiftool' in self.info:
            self.exiftool = VTMetaExifTool(self.info['exiftool'])
        if 'imports' in self.info:
            self.imports = VTMetaImports(self.info['imports'])
        if 'pe-resource-detail' in self.info:
            self.pe_resource_details = VTMetaPEResourceDetails(self.info['pe-resource-detail'])
        if 'pe-resource-langs' in self.info:
            self.pe_resource_langs = VTMetaPEResourceLangs(self.info['pe-resource-langs'])
        if 'pe-resource-list' in self.info:
            self.pe_resource_list = VTMetaPEResourceList(self.info['pe-resource-list'])
        if 'pe-resource-types' in self.info:
            self.pe_resource_types = VTMetaPEResourceTypes(self.info['pe-resource-types'])
        if 'sections' in self.info:
            self.pe_sections = VTMetaPESections(self.info['sections'])
        if 'sigcheck' in self.info:
            self.sigcheck = VTMetaSigCheck(self.info['sigcheck'])
            
            
            
class VTMetaScans(object):

    def __init__(self,scans):
        self.scans = scans
        self.size = len(self.scans)

    def get_detecting_engines(self):
        return [ k for k in self.scans if self.scans[k]['detected'] ]

    def get_non_detecting_engines(self):
        return [ k for k in self.scans if not self.scans[k]['detected'] ]

    def get_results(self):
        result = {}           #  name -> count
        for k in self.scans:
            if self.scans[k]['detected']:
                name = self.scans[k]['result']
                result.setdefault(name,0)
                result[name] += 1
        return result

    def __str__(self):
        lines = []
        lines.append('Detecting engines: ' + str(len(self.get_detecting_engines()))
                         + ' (out of ' + str(self.size) +')')
        for (r,c) in sorted(self.get_results().items()):
            lines.append(str(c).rjust(6) + '  ' + r)
        return '\n'.join(lines)



class VTMetaData(object):

    def __init__(self,metadata):

        self.results = metadata
        self.first_seen = self.results.get('first_seen','')
        self.last_seen = self.results.get('last_seen','')
        self.scan_date = self.results.get('scan_date','')
        self.md5 = self.results['md5']
        self.sha256 = self.results['sha256']
        self.size = self.results.get('size','')
        self.submission_names = self.results['submission_names']
        self.tags = self.results['tags']
        self.times_submitted = self.results['times_submitted']
        self.total = self.results['total']
        self.type = self.results['type']
        self.positives = None
        self.scans = None
        self.additional_info = None   # VTMetaAdditionalInfo
        self._initialize()

    def has_additional_info(self): return not self.additional_info is None

    def has_exif(self):
        return self.has_additional_info() and self.additional_info.has_exif()

    def get_exif(self):
        if self.has_exif():
            return self.additional_info.get_exif()

    def get_code_size(self):
        if self.has_exif():
            return self.get_exif().codesize
        return 0

    def get_company_name(self):
        if self.has_exif():
            return self.get_exif().companyname
        return ''

    def get_exif_entry_point(self):
        if self.has_exif():
            return self.get_exif().entrypoint
        return ''

    def get_file_description(self):
        if self.has_exif():
            return self.get_exif().filedescription
        return ''

    def get_file_os(self):
        if self.has_exif():
            return self.get_exif().fileOS
        return ''

    def get_exif_file_type(self):
        if self.has_exif():
            return self.get_exif().filetype
        return ''

    def get_file_version(self):
        if self.has_exif():
            return self.get_exif().fileversion
        return ''

    def get_file_version_number(self):
        if self.has_exif():
            return self.get_exif().fileversionnumber
        return ''

    def get_image_version(self):
        if self.has_exif():
            return self.get_exif().imageversion
        return ''

    def get_initialized_data_size(self):
        if self.has_exif():
            return self.get_exif().initializeddatasize
        return 0

    def get_exif_internal_name(self):
        if self.has_exif():
            return self.get_exif().internalname
        return ''

    def get_language_code(self):
        if self.has_exif():
            return self.get_exif().languagecode
        return ''

    def get_legal_copyright(self):
        if self.has_exif():
            return self.get_exif().legalcopyright
        return ''

    def get_machine_type(self):
        if self.has_exif():
            return self.get_exif().machinetype
        return ''

    def get_os_version(self):
        if self.has_exif():
            return self.get_exif().osversion
        return ''

    def get_exif_original_filename(self):
        if self.has_exif():
            return self.get_exif().originalfilename
        return ''

    def get_pe_type(self):
        if self.has_exif():
            return self.get_exif().petype
        return ''

    def get_exif_product_name(self):
        if self.has_exif():
            return self.get_exif().productname
        return ''

    def get_exif_product_version(self):
        if self.has_exif():
            return self.get_exif().productversion
        return ''

    def get_product_version_number(self):
        if self.has_exif():
            return self.get_exif().productversionnumber
        return ''

    def get_subsystem(self):
        if self.has_exif():
            return self.get_exif().subsystem
        return ''

    def get_exif_timestamp(self):
        if self.has_exif():
            return self.get_exif().timestamp
        return ''

    def get_exif_timestamp_yyyy(self):
        timestamp = self.get_exif_timestamp()
        if timestamp == '':
            return timestamp
        else:
            return timestamp[:4]

    def get_exif_timestamp_yyyy_mm(self):
        timestamp = self.get_exif_timestamp()
        if timestamp == '':
            return timestamp
        else:
            return timestamp[:7]

    def get_exif_timestamp_yyyy_mm_dd(self):
        timestamp = self.get_exif_timestamp()
        if timestamp == '':
            return timestamp
        else:
            return timestamp[:10]

    def get_uninitialized_data_size(self):
        if self.has_exif():
            return self.get_exif().uninitializeddatasize
        return 0

    def has_magic(self):
        return self.has_additional_info() and self.additional_info.has_magic()

    def get_magic(self):
        if self.has_additional_info(): return self.additional_info.magic

    def has_entry_point(self):
        return self.has_additional_info() and self.additional_info.has_entry_point()

    def get_entry_point(self):
        if self.has_additional_info(): return self.additional_info.pe_entry_point

    def has_time_stamp(self):
        return self.has_additional_info() and self.additional_info.has_time_stamp()

    def get_time_stamp(self):
        if self.has_additional_info(): return self.additional_info.pe_time_stamp

    def has_trid(self):
        return self.has_additional_info() and self.additional_info.has_trid()

    def get_trid(self):
        if self.has_additional_info(): return self.additional_info.trid

    def has_imports(self):
        return self.has_additional_info() and self.additional_info.has_imports()

    def get_imports(self):
        if self.has_imports(): return self.additional_info.get_imports()

    def get_imported_libraries(self):
        if self.has_imports():
            return self.get_imports().get_imported_libraries()
        return []

    def get_imported_functions(self):
        if self.has_imports():
            return self.get_imports().get_imported_functions()
        return []

    def has_sections(self):
        return self.has_additional_info() and self.additional_info.has_sections()

    def get_sections(self):
        if self.has_sections(): return self.additional_info.get_sections()

    def get_section_names(self):
        if self.has_sections():
            return self.get_sections().get_section_names()
        return []

    def get_section_md5s(self):
        if self.has_sections():
            return self.get_sections().get_section_md5s()
        return []

    def get_named_section_md5s(self):
        if self.has_sections():
            return self.get_sections().get_named_section_md5s()
        return []

    def get_named_section_virtual_addresses(self):
        if self.has_sections():
            return self.get_sections().get_named_section_virtual_addresses()
        return []

    def get_section_raw_sizes(self):
        if self.has_sections():
            return  self.get_sections().get_raw_sizes()
        return []

    def get_named_section_raw_sizes(self):
        if self.has_sections():
            return self.get_sections().get_named_section_raw_sizes()
        return []

    def get_section_virtual_sizes(self):
        if self.has_sections():
            return self.get_sections().get_virtual_sizes()
        return []

    def get_named_section_virtual_sizes(self):
        if self.has_sections():
            return self.get_sections().get_named_section_virtual_sizes()
        return []

    def has_resource_details(self):
        return self.has_additional_info() and self.additional_info.has_resource_details()

    def get_resource_details(self):
        if self.has_resource_details(): return self.additional_info.get_resource_details()

    def get_resource_file_types(self):
        if self.has_resource_details():
            return self.get_resource_details().get_file_types()
        return []

    def get_resource_types(self):
        if self.has_resource_details():
            return self.get_resource_details().get_types()
        return []

    def get_resource_languages(self):
        if self.has_resource_details():
            return self.get_resource_details().get_languages()
        return []

    def get_resource_sha256s(self):
        if self.has_resource_details():
            return self.get_resource.details().get_sha256s()
        return []

    def has_sigcheck(self):
        return self.has_additional_info() and self.additional_info.has_sigcheck()

    def get_sigcheck(self):
        if self.has_sigcheck(): return self.additional_info.get_sigcheck()

    def get_publisher(self):
        if self.has_sigcheck():
            return self.get_sigcheck().publisher

    def get_signers(self):
        if self.has_sigcheck():
            return self.get_sigcheck().signers.split('; ')
        return []

    def get_counter_signers(self):
        if self.has_sigcheck():
            return self.get_sigcheck().countersigners.split('; ')
        return []

    def get_signers_details(self):
        if self.has_sigheck():
            return self.get_sigcheck().signersdetails
        return []

    def get_counter_signers_details(self):
        if self.has_sigcheck():
            return self.get_sigcheck().countersignersdetails
        return []

    def get_copyright(self):
        if self.has_sigcheck():
            return self.get_sigcheck().copyright

    def get_description(self):
        if self.has_sigcheck():
            return self.get_sigcheck().description

    def get_original_name(self):
        if self.has_sigcheck():
            return self.get_sigcheck().originalname

    def get_product(self):
        if self.has_sigcheck():
            return self.get_sigcheck().product

    def get_signing_date(self):
        if self.has_sigcheck():
            return self.get_sigcheck().signingdate

    def get_verified(self):
        if self.has_sigcheck():
            return self.get_sigcheck().verified

    def has_behaviour(self):
        return self.has_additional_info() and self.additional_info.has_behaviour_v1()

    def get_behaviour(self):
        if self.has_behaviour(): return self.additional_info.get_behaviour_v1()

    def get_runtime_dlls(self):
        if self.has_behaviour():
            return self.get_behaviour().runtime_dlls
        return []

    def get_files_copied(self):
        if self.has_behaviour():
            return self.get_behaviour().filesystem.copied
        return []

    def get_files_copied_src(self):
        if self.has_behaviour():
            return self.get_behaviour().filesystem.copiedsrc
        return []

    def get_files_copied_dst(self):
        if self.has_behaviour():
            return self.get_behaviour().filesystem.copieddst
        return []

    def get_files_deleted(self):
        if self.has_behaviour():
            return self.get_behaviour().filesystem.deleted
        return []

    def get_files_downloaded(self):
        if self.has_behaviour():
            return self.get_behaviour().filesystem.downloaded
        return []

    def get_files_moved(self):
        if self.has_behaviour():
            return self.get_behaviour().filesystem.moved
        return []

    def get_files_moved_src(self):
        if self.has_behaviour():
            return self.get_behaviour().filesystem.movedsrc
        return []

    def  get_files_moved_dst(self):
        if self.has_behaviour():
            return self.get_behaviour().filesystem.moveddst
        return []

    def get_files_opened(self):
        if self.has_behaviour():
            return self.get_behaviour().filesystem.opened
        return []

    def get_files_read(self):
        if self.has_behaviour():
            return self.get_behaviour().filesystem.read
        return []

    def get_files_replaced(self):
        if self.has_behaviour():
            return self.get_behaviour().filesystem.replaced
        return []

    def get_files_written(self):
        if self.has_behaviour():
            return self.get_behaviour().filesystem.written
        return []

    def get_network_dns_ip(self):
        if self.has_behaviour():
            return self.get_behaviour().network.dns_ip
        return []

    def get_network_dns_hostname(self):
        if self.has_behaviour():
            return self.get_behaviour().network.dns_hostname
        return []

    def get_network_http_url(self):
        if self.has_behaviour():
            return self.get_behaviour().network.http_url
        return []

    def get_network_http_method(self):
        if self.has_behaviour():
            return self.get_behaviour().network.http_method
        return []

    def get_network_http_user_agent(self):
        if self.has_behaviour():
            return self.get_behaviour().network.http_user_agent
        return []

    def get_network_tcp(self):
        if self.has_behaviour():
            return self.get_behaviour().network.tcp
        return []

    def get_network_udp(self):
        if self.has_behaviour():
            return self.get_behaviour().network.udp
        return []

    def get_mutexes_created(self):
        if self.has_behaviour():
            return self.get_behaviour().mutex.created
        return []

    def get_mutexes_opened(self):
        if self.has_behaviour():
            return self.get_behaviour().mutex.opened
        return []

    def get_processes_created(self):
        if self.has_behaviour():
            return self.get_behaviour().process.created
        return []

    def get_processes_injected(self):
        if self.has_behaviour():
            return self.get_behaviour().process.injected
        return []

    def get_processes_shellcmds(self):
        if self.has_behaviour():
            return self.get_behaviour().process.shellcmds
        return []

    def get_processes_terminated(self):
        if self.has_behaviour():
            return self.get_behaviour().process.terminated
        return []

    def get_registry_deleted(self):
        if self.has_behaviour():
            return self.get_behaviour().registry.deleted
        return []

    def get_registry_type(self):
        if self.has_behaviour():
            return self.get_behaviour().registry.type
        return []

    def get_registry_val(self):
        if self.has_behaviour():
            return self.get_behaviour().registry.val
        return []

    def get_registry_key(self):
        if self.has_behaviour():
            return self.get_behaviour().registry.key
        return []

    def _initialize(self):
        if 'positives' in self.results:
            self.positives = self.results['positives']
        if 'additional_info' in self.results:
            self.additional_info = VTMetaAdditionalInfo(self.results['additional_info'])
        if 'scans' in self.results:
            self.scans = VTMetaScans(self.results['scans'])
                                                            

        
