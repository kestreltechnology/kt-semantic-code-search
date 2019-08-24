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

virus_stemmings = {
    'ADWARE': 'Adware',
    'ADW': 'Adware',
    'AdPlugin': 'AdPlugin',
    'Adware': 'Adware',
    'AdWare': 'Adware',
    'Agent': 'Agent',
    'Application.Bundler': 'Application.Bundler',
    'Application.Generic': 'Application.Generic',
    'Application.Hacktool': 'HackTool',
    'Application.Win32.AdWare': 'Adware',
    'Application.Win32.Amonetize': 'Amonetize',
    'Application.Win32.Bundler': 'Application.Bundler',
    'Application.Win32.BrowseFox': 'BrowseFox',
    'Application.Win32.DomaIQ': 'DomaIQ',
    'Application.Win32.DownloadAdmin': 'DownloadAdmin',
    'Application.Win32.ICLoader': 'ICLoader',
    'Application.Win32.InstallCore': 'InstallCore',
    'Application.Win32.LoadMoney': 'LoadMoney',
    'Application.Win32.MultiPlug': 'MultiPlug',
    'Application.Win32.OutBrowse': 'OutBrowse',
    'Application.Win32.SoftPulse': 'SoftPulse',
    'Application.Win32.Techsnab': 'Techsnab',
    'Artemis': 'Artemis',
    'Atros': 'Atros',
    'AutoIt': 'AutoIt',
    'Autoit': 'AutoIt',
    'BC.Win.Virus.Ransom': 'Ransom',
    'BDS/Backdoor': 'Backdoor',
    'BDS/Simda': 'Simda',
    'BKDR_SIMDA': 'Simda',
    'Backdoor': 'Backdoor',
    'Browse': 'BrowseFox',
    'BScope.Backdoor': 'Backdoor',
    'BScope.Malware-Cryptor': 'Cryptor',
    'BScope.Trojan': 'Trojan',
    'BackDoor': 'Backdoor',
    'BehavesLike.Win32.Adware': 'Adware',
    'BehavesLike.Win32.Backdoor': 'Backdoor',
    'BehavesLike.Win32.BadFile': 'BehavesLike.BadFile',
    'BehavesLike.Win32.BrowseFox': 'BrowseFox',
    'BehavesLike.Win32.Chir': 'Chir',
    'BehavesLike.Win32.Downloader': 'Downloader',
    'BehavesLike.Win32.Dropper': 'Dropper',
    'BehavesLike.Win32.Expiro': 'Expiro',
    'BehavesLike.Win32.Fujacks': 'Fujacks',
    'BehavesLike.Win32.Injector': 'Injector',
    'BehavesLike.Win32.Keylog': 'KeyLogger',
    'BehavesLike.Win32.MultiPlug': 'MultiPlug',
    'BehavesLike.Win32.Mydoom': 'Mydoom',
    'BehavesLike.Win32.PWSOnlineGames': 'OnlineGames',
    'BehavesLike.Win32.PWSZbot': 'Zbot',
    'BehavesLike.Win32.RAHack': 'RAHack',
    'BehavesLike.Win32.Ramnit': 'Ramnit',
    'BehavesLike.Win32.Ransom': 'Ransom',
    'BehavesLike.Win32.Rootkit': 'Rootkit',
    'BehavesLike.Win32.Sality': 'Sality',
    'BehavesLike.Win32.Spybot': 'Spybot',
    'BehavesLike.Win32.Spyware': 'Spyware',
    'BehavesLike.Win32.Sytro': 'Sytro',
    'BehavesLike.Win32.Trojan': 'Trojan',
    'BehavesLike.Win32.Virut': 'Virut',
    'BehavesLike.Win32.Worm': 'Worm',
    'BehavesLike.Win32.Zbot': 'Zbot',
    'BehavesLike.Win32.ZBot': 'Zbot',
    'BundleApp': 'BundleApp',
    'Crossrider': 'Crossrider',
    'Crypt': 'Crypt',
    'DomaIQ': 'DomaIQ',
    'DownloadAdmin': 'DownloadAdmin',
    'Downloader': 'Downloader',
    'Downware.InstallCore': 'InstallCore',
    'DR/AutoIt': 'AutoIt',
    'Dropped:Application.Bundler.Outbrowse': 'OutBrowse',
    'Dropper': 'Dropper',
    'Email-Worm': 'Email-worm',
    'EmailWorm': 'Email-worm',
    'Gen:Application.Bundler.Firseria': 'Firseria',
    'Gen:Trojan': 'Trojan',
    'Gen:Variant.Adware': 'Adware',
    'Gen:Variant.Application.Bundler': 'Bundler',
    'Gen:Variant.Application.Graftor': 'Graftor',
    'Gen:Variant.Application.Kazy': 'Kazy',
    'Gen:Variant.Application.LoadMoney': 'LoadMoney',
    'Gen:Variant.AutoIt': 'AutoIt',
    'Gen:Variant.Application.Mikey': 'Mikey',
    'Gen:Variant.Barys': 'Barys',
    'Gen:Variant.Graftor': 'Graftor',
    'Gen:Variant.Injector': 'Injector',
    'Gen:Variant.Kazy': 'Kazy',
    'Gen:Variant.Mikey': 'Mikey',
    'Gen:Variant.Strictor': 'Strictor',
    'Gen:Variant.Symmi': 'Symmi',
    'Gen:Variant.Zbot': 'Zbot',
    'Gen:Variant.Zusy': 'Zusy',
    'Generic': 'Generic',
    'GrayWare': 'Grayware',
    'HEUR/QVM19.1.Virus.Win32.Sality': 'Sality',
    'HEUR/QVM08.0.Virus.Win32.Virut': 'Virut',
    'HT_BROWSEFOX': 'BrowseFox',
    'HW32.Packed': 'HW32.Packed',
    'HackTool': 'HackTool',
    'Hacktool': 'HackTool',
    'Heur.Trojan': 'Trojan',
    'Heur:Backdoor': 'Backdoor',
    'Heur:Trojan': 'Trojan',
    'I-Worm': 'I-Worm',
    'Inject': 'Injector',
    'InstallCore': 'InstallCore',
    'Jelbrus': 'Jelbrus',
    'LoadMoney': 'LoadMoney',
    'LockScreen': 'LockScreen',
    'MSIL/BrowseFox': 'BrowseFox',
    'MSIL/Soft32Downloader': 'Downloader',
    'Mal/Ramnit': 'Ramnit',
    'Mal/Ransom': 'Ransom',
    'Mal/Sality': 'Sality',
    'Mal/Simda': 'Simda',
    'Mal/Upatre': 'Upatre',
    'Mal/Zbot': 'Zbot',
    'Mal_Allaple': 'WormAllaple',
    'Malware-Cryptor': 'Cryptor',
    'Malware/Win32.SAPE': 'SAPE',
    'MemScan:Application.Bundler.Outbrowse': 'OutBrowse',
    'MultiPlug': 'MultiPlug',
    'Multiplug': 'MultiPlug',
    'MysticCompressor': 'MysticCompressor',
    'MyWebSearch': 'MyWebSearch',
    'NS:Downloader': 'Downloader',
    'NS:Trojan': 'Trojan',
    'NSIS.Adware': 'Adware',
    'NSIS.Application.OutBrowse': 'OutBrowse',
    'NSIS:Downloader': 'Downloader',
    'NSIS:OutBrowse': 'OutBrowse',
    'NSIS/Trojan': 'Trojan',
    'NSIS:Adware': 'Adware',
    'Net-Worm.Win32.Allaple': 'WormAllaple',
    'Net-Worm:W32/Allaple': 'WormAllaple',
    'Net.Risk.Adware': 'Adware',
    'NetWorm.Win32.Allaple': 'WormAllaple',
    'Nsis.Adware': 'Adware',
    'Nsis.Trojan': 'Trojan',
    'not-a-virus:HEUR:AdWare.Win32': 'Adware',
    'not-a-virus:AdWare.NSIS': 'Adware;NSIS',
    'not-a-virus:HEUR:AdWare.Win32.OutBrowse': 'OutBrowse',
    'Obfuscated': 'Obfuscated',
    'OScope.Malware-Cryptor.Win32.Allaple': 'WormAllaple',
    'OutBrowse': 'OutBrowse',
    'P2P-Worm': 'P2PWorm',
    'P2PWorm': 'P2PWorm',
    'PE:AdWare': 'Adware',
    'PE:Adware.BrowseFox': 'BrowseFox',
    'PE:Adware.MultiPlug': 'MultiPlug',
    'PE:Backdoor': 'Backdoor',
    'PE:Dropper': 'Dropper',
    'PE:Malware.Adware': 'Adware',
    'PE:Malware.Agent': 'Agent',
    'PE:Malware.DownloadAdmin': 'DownloadAdmin',
    'PE:Malware.Graftor': 'Graftor',
    'PE:Malware.Hacktool': 'HackTool',
    'PE:Malware.Kazy': 'Kazy',
    'PE:Malware.Outbrowse': 'OutBrowse',
    'PE:Malware.Techsnab': 'Techsnab',
    'PE:Malware.RDM': 'RDM',
    'PE:Malware.Strictor': 'Strictor',
    'PE:Malware.BrowseFox': 'BrowseFox',
    'PE:Packer': 'Packer',
    'PE:RootKit': 'Rootkit',
    'PE:Spyware': 'Spyware',
    'PE:Stealer': 'Stealer',
    'PE:Trojan': 'Trojan',
    'PE:Virus.Expiro': 'Expiro',
    'PE:Virus.Parite': 'Parite',
    'PE:Virus.Ramnit': 'Ramnit',
    'PE:Virus.Sality': 'Sality',
    'PE:Virus.Virut': 'Virut',
    'PE:Win32.Parite': 'Parite',
    'PE:Win32.Sality': 'Sality',
    'PE:Win32.Virut': 'Virut',
    'PE:Worm': 'Worm',
    'PE_Chir': 'Chir',
    'PE_EXPIRO': 'Expiro',
    'PE_FUJACKS': 'Fujacks',
    'PE_JADTRE': 'Jadtre',
    'PE_PARITE': 'Parite',
    'PE_NIMNUL': 'Nimnul',
    'PE_RAMNIT': 'Ramnit',
    'PE_SALITY': 'Sality',
    'PE_VIRLOCK': 'Virlock',
    'PE_VIRUT': 'Virut',
    'PE_VIRUX': 'Virux',
    'PSW.Generic': 'PSW.Generic',
    'PSW.OnlineGames': 'OnlineGames',
    'PUA.Amonetize': 'Amonetize',
    'PUA.BrowseFox': 'BrowseFox',
    'PUA.DomaIQ': 'DomaIQ',
    'PUA.Downloader': 'Downloader',
    'PUA.DownloadAdmin': 'DownloadAdmin',
    'PUA.HackTool': 'HackTool',
    'PUA.ICLoader': 'ICLoader',
    'PUA.InstallCore': 'InstallCore',
    'PUA.LoadMoney': 'LoadMoney',
    'PUA.MultiPlug': 'MultiPlug',
    'PUA.Multiplug': 'MultiPlug',
    'PUA.OutBrowse': 'OutBrowse',
    'PUA.SoftPulse': 'SoftPulse',
    'PUA.Softonic': 'Softonic',
    'PUA.Solimba': 'Solimba',
    'PUA.Techsnab': 'Techsnab',
    'PUA.Win32.Amonetize': 'Amonetize',
    'PUA.Win32.DownloadAdmin': 'DownloadAdmin',
    'PUA.Win32.LoadMoney': 'LoadMoney',
    'PUA.Win32.MyWebSearch': 'MyWebSearch',
    'PUA.Win32.Softonic': 'Softonic',
    'PUA.Win32.Techsnab': 'Techsnab',
    'PUA/BrowseFox': 'BrowseFox',
    'PUA/DomaIQ': 'DomaIQ',
    'PUA/DownloadAdmin': 'DownloadAdmin',
    'PUA/Firseria': 'Firseria',
    'PUA/InstallCore': 'InstallCore',
    'PUA/LoadMoney': 'LoadMoney',
    'PUA/MultiPlug': 'MultiPlug',
    'PUA/Outbrowse': 'OutBrowse',
    'PUA/SoftPulse': 'SoftPulse',
    'PUA/Softpulse': 'Softpulse',
    'PUA/Solimba': 'Solimba',
    'PUA/Techsnab': 'Techsnab',
    'PUP.Adware.BrowseFox': 'BrowseFox',
    'PUP.Adware.Downloader': 'Downloader',
    'PUP.Adware.RecordPage': 'RecordPage',
    'PUP.CrossRider': 'CrossRider',
    'PUP.DomaIQ': 'DomaIQ',
    'PUP.Downloader': 'Downloader',
    'PUP.HackTool': 'HackTool',
    'PUP.Optional.Amonetize': 'Amonetize',
    'PUP.Optional.DomaIQ': 'DomaIQ',
    'PUP.Optional.DownLoadAdmin': 'DownloadAdmin',
    'PUP.Optional.Downloader': 'Downloader',
    'PUP.Optional.Firseria': 'Firseria',
    'PUP.Optional.InstallCore': 'InstallCore',
    'PUP.Optional.Jelbrus': 'Jelbrus',
    'PUP.Optional.LoadMoney': 'LoadMoney',
    'PUP.Optional.MultiPlug': 'MultiPlug',
    'PUP.Optional.OutBrowse': 'OutBrowse',
    'PUP.Optional.RecordPage': 'RecordPage',
    'PUP.Optional.RollAround': 'RollAround',
    'PUP.Optional.SofTonic': 'Softonic',
    'PUP.Optional.Solimba': 'Solimba',
    'PUP.Softonic': 'Softonic',
    'PUP/BrowseFox': 'BrowseFox',
    'PUP/BrowserFox': 'BrowseFox',
    'PUP/Win32.Amonetize': 'Amonetize',
    'PUP/Win32.BrowseFox': 'BrowseFox',
    'PUP/Win32.CrossRider': 'CrossRider',
    'PUP/Win32.DomaIQ': 'DomaIQ',
    'PUP/Win32.DownloadAdmin': 'DownloadAdmin',
    'PUP/Win32.Downloader':  'Downloader',
    'PUP/Win32.Firseria': 'Firseria',
    'PUP/Win32.LoadMoney': 'LoadMoney',
    'PUP/Win32.MultiPlug': 'MultiPlug',
    'PUP/Win32.OutBrowse': 'OutBrowse',
    'PUP/Win32.SoftPulse': 'SoftPulse',
    'PUP/Win32.Softonic': 'Softonic',
    'PUP/Win32.Solimba': 'Solimba',
    'PUP/Win32.Techsnab': 'Techsnab',
    'PWS-OnlineGames': 'OnlineGames',
    'PWS-Zbot': 'Zbot',
    'PWS.OnLineGames': 'OnlineGames',
    'PWS:Win32/OnLineGames': 'OnlineGames',
    'PWS:Win32/Zbot':  'PWS-Zbot',
    'PWSZbot':  'PWS-Zbot',
    'Packed': 'Packed',
    'Packer.VirLock': 'Virlock',
    'Password-Stealer': 'Password-Stealer',
    'RDN/Generic Backdoor': 'Backdoor',
    'RDN/Generic BackDoor': 'Backdoor',
    'RDN/Generic Downloader': 'Downloader',
    'RDN/Generic Dropper': 'Dropper',
    'RDN/Ransom': 'Ransom',
    'Ransom': 'Ransom',
    'RiskWare[Downloader': 'Downloader',
    'Riskware': 'Riskware',
    'Rootkit': 'Rootkit',
    'RootKit': 'Rootkit',
    'SAPE': 'SAPE',
    'SH.Adware':  'Adware',
    'SH.Trojan':  'Trojan',
    'Spyware': 'Spyware',
    'SScope.Adware.MultiPlug': 'MultiPlug',
    'SScope.Adware.Multiplug': 'Multiplug',
    'SScope.Adware.Softpulse': 'SoftPulse',
    'SScope.Backdoor': 'Backdoor',
    'SScope.Downware.DownloadAdmin': 'DownloadAdmin',
    'SScope.Injector': 'Injector',
    'SScope.Malware-Cryptor': 'Cryptor',
    'SScope.Trojan': 'Trojan',
    'Signed-Adware.Outbrowse': 'OutBrowse',
    'Simda': 'Simda',
    'SoftPulse': 'SoftPulse',
    'Softonic': 'Softonic',
    'SoftwareBundler:Win32/OutBrowse': 'OutBrowse',
    'Solimba': 'Solimba',
    'Suspicious.Cloud': 'Suspicious.Cloud',
    'TR/Agent': 'TR/Agent',
    'TR/Crypt': 'TR/Crypt',
    'TR/Dldr': 'TR/Dldr',
    'TR/Downloader': 'Downloader',
    'TR/Dropper': 'Dropper',
    'TR/ExtenBro': 'ExtenBro',
    'TR/Graftor': 'Graftor',
    'TR/Kazy': 'Kazy',
    'TR/Kryptik': 'Kryptik',
    'TR/OnLineGame': 'OnlineGames',
    'TR/Onlinegames': 'OnlineGames',
    'TR/PSW.OGames': 'OnlineGames',
    'TR/PWS.OnlGame': 'OnlineGames',
    'TR/Rogue': 'TR/Rogue',
    'TR/Rootkit': 'Rootkit',
    'TR/Spy': 'TR/Spy',
    'TR/Symmi': 'TR/Symmi',
    'TR/Zusy': 'Zusy',
    'TSPY_ZBOT': 'Zbot',
    'TROJ': 'Trojan',
    'Trj/Downloader': 'Downloader',
    'Trj/Dropper': 'Dropper',
    'Trj/OnlineGames': 'OnlineGames',
    'Trj/Ransom': 'Ransom',
    'Trj/Zbot': 'Zbot',
    'Troj': 'Trojan',
    'Trojware': 'Trojan',
    'Unwanted-Program': 'Unwanted-Program',
    'Upatre': 'Upatre',
    'Virus': 'Virus',
    'W32.Autoit': 'AutoIt',
    'W32.Backdoor': 'Backdoor',
    'W32.Chir': 'Chir',
    'W32.Cryptic': 'Cryptic',
    'W32.Dropper': 'Dropper',
    'W32.Elkern': 'Elkern',
    'W32.Expiro': 'Expiro',
    'W32.FamVT': 'FamVT',
    'W32.Fujack': 'Fujacks',
    'W32.Hfs':  'W32.Hfs',
    'W32.Jadtre': 'Jadtre',
    'W32.Madang': 'Madang',
    'W32.MultiPlug': 'MultiPlug',
    'W32.MyDoom': 'Mydoom',
    'W32.Mydoom': 'Mydoom',
    'W32.OnlineGame': 'OnlineGames',
    'W32.Rahack': 'RAHack',
    'W32.Ramnit': 'Ramnit',
    'W32.Ransomlock': 'Ransom',
    'W32.Sality': 'Sality',
    'W32.Trojan': 'Trojan',
    'W32.Virut': 'Virut',
    'W32.Wapomi': 'Wapomi',
    'W32/A-': 'Eldorado',
    'W32/ALLAPLE': 'WormAllaple',
    'W32/Adware': 'Adware',
    'W32/Agent': 'Agent',
    'W32/Allaple': 'WormAllaple',
    'W32/Amonetize': 'Amonetize',
    'W32/AutoIt': 'AutoIt',
    'W32/Autoit': 'AutoIt',
    'W32/Backdoor': 'Backdoor',
    'W32/Brontok': 'Brontok',
    'W32/Cekar': 'Cekar',
    'W32/Chir': 'Chir',
    'W32/Detnat': 'Detnat',
    'W32/DomaIQ': 'DomaIQ',
    'W32/DownloadAdmin': 'DownloadAdmin',
    'W32/DownldAdmin.A.gen!Eldorado': 'Eldorado',
    'W32/DownloAdmin.B.gen!Eldorado': 'Eldorado',
    'W32/Download': 'Downloader',
    'W32/Elkern': 'Elkern',
    'W32/EmailWorm': 'Email-worm',
    'W32/Expiro': 'Expiro',
    'W32/Fujack': 'Fujacks',
    'W32/Generic': 'Generic',
    'W32/GenTroj': 'Trojan',
    'W32/Graftor': 'Graftor',
    'W32/Hacktool': 'HackTool',
    'W32/Heuristic-210!Eldorado': 'Eldorado',
    'W32/Inject': 'Injector',
    'W32/Jadtre': 'Jadtre',
    'W32/Kazy': 'Kazy',
    'W32/Kryptik': 'Kryptik',
    'W32/LoadMoney': 'LoadMoney',
    'W32/MSIL_Bladabind.I2.gen!Eldorado': 'Eldorado',
    'W32/Madang': 'Madang',
    'W32/MultiPlug': 'MultiPlug',
    'W32/MyDoom': 'Mydoom',
    'W32/Mydoom': 'Mydoom',
    'W32/Mywebsearch.K.gen!Eldorado': 'Eldorado',
    'W32/Nimnnul': 'Nimnul',
    'W32/Obfuscated': 'Obfuscated',
    'W32/OnlineGames': 'OnlineGames',
    'W32/Onlinegames': 'OnlineGames',
    'W32/OutBrowse': 'OutBrowse',
    'W32/Outbrowse': 'OutBrowse',
    'W32/Patched.S.gen!Eldorado': 'Eldorado',
    'W32/Parite': 'Parite',
    'W32/RAHack': 'RAHack',
    'W32/Rahack': 'RAHack',
    'W32/Ramnit': 'Ramnit',
    'W32/Ransom': 'Ransom',
    'W32/SomotoBetterInstaller.F.!Eldorado': 'Eldorado',
    'W32/SuspPack.FW.gen!Eldorado': 'Eldorado',
    'W32/Sytro': 'Sytro',
    'W32/S-': 'Eldorado',
    'W32/Sality': 'Sality',
    'W32/Socks': 'Socks',
    'W32/SoftPulse': 'SoftPulse',    
    'W32/Sytro': 'Sytro',
    'W32/Trojan': 'Trojan',
    'W32/Upatre': 'Upatre',
    'W32/Viking': 'Viking',
    'W32/Virlock': 'Virlock',
    'W32/Virtob': 'Virtob',
    'W32/VirRansom': 'Ransom',
    'W32/VirRnsm': 'Ransom',
    'W32/Virut': 'Virut',
    'W32/Worm-': 'Worm',
    'W32/Worm.': 'Worm',
    'W32/Zbot': 'Zbot',
    'WIN.Downloader': 'Downloader',
    'WIN.Spy.Onlinegames': 'OnlineGames',
    'WIN.Worm.': 'Worm',
    'Win.Virus.Sality': 'Sality',
    'WORM': 'Worm',
    'Win-Trojan': 'Trojan',
    'Win.Adware': 'Adware',
    'Win.Trojan': 'Trojan',
    'Win32.Adware': 'Adware',
    'Win.Worm': 'Worm',
    'Win32:Allaple': 'WormAllaple',
    'Win32.Application.Agent': 'Agent',
    'Win32.Application.BrowseFox': 'BrowseFox',
    'Win32.Application.InstallCore': 'InstallCore',
    'Win32.Application.OutBrowse': 'OutBrowse',
    'Win32.Chir': 'Chir',
    'Win32.Cryptor': 'Cryptor',
    'Win32.Backdoor':  'Backdoor',
    'Win32.Dropper': 'Dropper',
    'Win32.Expiro': 'Expiro',
    'Win32.Fujacks': 'Fujacks',
    'Win32.Jadtre': 'Jadtre',
    'Win32.Nimnul': 'Nimnul',
    'Win32.Parite': 'Parite',
    'Win32.Ramnit': 'Ramnit',
    'Win32.Risk.Adware': 'Adware',
    'Win32.Sality': 'Sality',
    'Win32.Troj': 'Trojan',
    'Win32.Virus.Ramnit': 'Ramnit',
    'Win32.Virus.Sality': 'Sality',
    'Win32.Viking': 'Viking',
    'Win32.Virlock': 'Virlock',
    'Win32.Virtob': 'Virtob',
    'Win32.Virus.Nimnul': 'Nimnul',
    'Win32.Virut':  'Virut',
    'Win32.Worm': 'Worm',
    'Win32/AdWare': 'Adware',
    'Win32/Adware': 'Adware',
    'Win32/Agent': 'Agent',
    'Win32/Allaple': 'WormAllaple',
    'Win32/Backdoor': 'Backdoor',
    'Win32/Chir': 'Chir',
    'Win32/Cryptor': 'Cryptor',
    'Win32/Dellboy': 'Dellboy',
    'Win32/DomaIQ': 'DomaIQ',
    'Win32/Expiro': 'Expiro',
    'Win32/Gamepass':  'Gamepass',
    'Win32/ICLoader': 'ICLoader',
    'Win32/Jadtre': 'Jadtre',
    'Win32/Madang': 'Madang',
    'Win32/Mydoom': 'Mydoom',
    'Win32/Nabucur': 'Nabucur',
    'Win32/OutBrowse': 'OutBrowse',
    'Win32/PSW.OnLineGames': 'OnlineGames',
    'Win32/Parite': 'Parite',
    'Win32/Ramnit': 'Ramnit',
    'Win32/Reveton': 'Reveton',
    'Win32/RootKit': 'Rootkit',
    'Win32/Simda': 'Simda',
    'Win32/Sality': 'Sality',
    'Win32/Spy.Zbot': 'Zbot',
    'Win32/Tnega': 'Tnega',
    'Win32/Trojan': 'Trojan',
    'Win32/Viking': 'Viking',
    'Win32.VirLock': 'Virlock',
    'Win32/Virus.Adware':  'Adware',
    'Win32/Virus.Downloader': 'Downloader',
    'Win32/Virut': 'Virut',
    'Win32/Wapomi': 'Wapomi',
    'Win32/Zbot': 'Zbot',
    'Win32:Adware': 'Adware',
    'Win32:Agent': 'Agent',
    'Win32:BrowseFox': 'BrowseFox',
    'Win32:Crypt-': 'Crypt',
    'Win32:DownloadAdmin': 'DownloadAdmin',
    'Win32:Downloader': 'Downloader',
    'Win32:Dropper': 'Dropper',
    'Win32:Expiro': 'Expiro',
    'Win32:GenMalicious': 'GenMalicious',
    'Win32:Injector': 'Injector',
    'Win32:Jadtre': 'Jadtre',
    'Win32.KeyLogger': 'KeyLogger',
    'Win32:Kryptik': 'Kryptik',    
    'Win32:LoadMoney': 'LoadMoney',
    'Win32:MultiPlug': 'MultiPlug',
    'Win32:Mydoom': 'Mydoom',
    'Win32:Nabucur': 'Nabucur',
    'Win32:OnLineGames': 'OnlineGames',
    'Win32:OutBrowse': 'OutBrowse',
    'Win32:Parite': 'Parite',
    'Win32:Ramnit': 'Ramnit',
    'Win32:Ransom': 'Ransom',
    'Win32:Reveton': 'Reveton',
    'Win32:Rootkit': 'Rootkit',
    'Win32:Sality': 'Sality',
    'Win32:SoftPulse': 'SoftPulse',
    'Win32:Socks': 'Socks',
    'Win32:StubOfSality': 'Sality',
    'Win32:Trojan': 'Trojan',
    'Win32:Viking': 'Viking',
    'Win32:VirLock': 'Virlock',
    'Win32.Virus.Virut': 'Virut',
    'Win32:Virut': 'Virut',
    'Win32:Zbot': 'Zbot',
    'Win-PUP/DomaIQ': 'DomaIQ',
    'Worm.Agent': 'Worm.Agent',
    'Worm.Allaple': 'WormAllaple',
    'Worm.Generic': 'Worm',
    'Worm.Mydoom': 'Mydoom',
    'Worm.Sality': 'Sality',
    'Worm.Socks': 'Socks',
    'Worm.Viking': 'Viking',
    'Worm.Win32.Agent': 'Worm',
    'Worm.Win32.Allaple': 'WormAllaple',
    'Worm.Win32.AutoRun': 'Worm.AutoRun',
    'Worm.Win32.Chir': 'Chir',
    'Worm.Win32.Dropper': 'Worm.Dropper',
    'Worm.Win32.Mydoom': 'Mydoom',
    'Worm.Win32.Socks': 'Socks',
    'Worm.Win32.Viking': 'Viking',
    'Worm/Agent': 'Worm',
    'Worm/Allaple': 'WormAllaple',
    'Worm/AutoRun': 'Worm.AutoRun',
    'Worm/Generic': 'Worm',
    'Worm/Socks': 'Socks',
    'Worm/Sytro': 'Sytro',
    'Worm/W32.Agent': 'Worm.Agent',
    'Worm/S32.Mydoom': 'Mydoom',
    'Worm/W32.Sytro': 'Sytro',
    'Worm/Win32.Agent': 'Worm.Agent',
    'Worm/Win32.Nimda': 'Nimda',
    'Worm/Win32.Socks': 'Socks',
    'Worm/Win32.Viking': 'Viking',
    'Worm:Win32/Allaple': 'WormAllaple',
    'Worm:Win32/Chir': 'Chir',
    'Worm:Win32/Mydoom': 'Mydoom',
    'Worm:Win32/Sality': 'Sality',
    'Worm.Allaple': 'WormAllaple',
    'Worm.AllApleT': 'WormAllaple',
    'Worm[Email]/Win32.Mydoom': 'Mydoom',
    'Worm[Net]/Win32.Allaple': 'WormAllaple',
    'Worm[P2P]/Win32.Sytro': 'Sytro',
    'Zbot': 'Zbot',
    'a variant of Win32/Adware.ICLoader': 'ICLoader',
    'a variant of Win32/Adware.LoadMoney': 'LoadMoney',
    'a variant of Win32/Adware.MultiPlug': 'MultiPlug',
    'a variant of Win32/Agent': 'Agent',
    'a variant of Win32/Allaple': 'WormAllaple',
    'a variant of Winn32/Amonetize': 'Amonetize',
    'a variant of Win32/BrowseFox': 'BrowseFox',
    'a variant of Win32/DownloadAdmin': 'DownloadAdmin',
    'a variant of Win32/Expiro': 'Expiro',
    'a variant of Win32/HackTool': 'HackTool',
    'a variant of Win32/Injector': 'Injector',
    'a variant of Win32/InstallCore': 'InstallCore',
    'a variant of Win32/Kryptik': 'Kryptik',
    'a variant of Win32/LoadMoney': 'LoadMoney',
    'a variant of Win32/Madang': 'Madang',
    'a variant of Win32/OutBrowse': 'OutBrowse',
    'a variant of Win32/PSW.OnLineGames': 'OnlineGames',
    'a variant of Win32/Ramnit': 'Ramnit',
    'a variant of Win32/Spy': 'Spyware',
    'a variant of Win32/Techsnab': 'Techsnab',
    'a variant of Win32/TrojanDownloader': 'TrojanDownloader',
    'a variant of Win32/Virlock': 'Virlock',
    'not-a-virus:Adware.Agent': 'Agent',
    'not-a-virus:Adware.NSIS.Agent': 'Agent',
    'not-a-virus:AdWare.Win32.Agent': 'Agent',
    'not-a-virus:AdWare.Win32.BrowseFox': 'BrowseFox',
    'not-a-virus:AdWare.Win32.ICLoader': 'ICLoader',
    'not-a-virus:AdWare.Win32.MultiPlug': 'MultiPlug',
    'not-a-virus:AdWare.Win32.OutBrowse': 'OutBrowse',
    'not-a-virus:AdWare.Win32.Techsnab': 'Techsnab',
    'not-a-virus:AdWare.Techsnab': 'Techsnab',
    'not-a-virus:Downloader': 'Downloader',
    'not-a-virus:WebToolbar': 'WebToolbar',
    'suspected of Trojan': 'Trojan'
    }

def stem_virus(v):
    for (long,stem) in virus_stemmings.items():
        if v.startswith(long): return stem
    return v


def stem_trid(t):
    if t.startswith('NSIS'): return 'NSIS'
    if 'Borland' in t: return 'Borland'
    if 'Visual Basic' in t: return 'Visual Basic'
    return t

class VTScanRecorder(object):

    def __init__(self,scans):
        self.scans = scans

    def get_scans(self): return self.scans.get_results()

    def get_stemmed_scans(self):
        viruses = {}
        for (v,c) in self.get_scans().items():
            v = stem_virus(v)
            viruses.setdefault(v,0)
            viruses[v] += c
        return viruses

    def get_detecting_engines(self):
        return self.scans.get_detecting_engines()

    def get_non_detecting_engines(self):
        return self.scans.get_non_detecting_engines()
        
        

class VTMetaDataRecorder(object):

    def  __init__(self,name,featuresets):
        self.name = name
        self.results = {}
        self.featuresets = featuresets
        for s in self.featuresets:
            self.results[s] = {}

    def includes(self,featureset): return featureset in self.featuresets

    def reset(self):
        for s in self.featuresets:
            self.results[s] = {}

    def add_term(self,featureset,term,n=1):
        if not featureset in self.results:
            raise KTFeaturesetNotFound(featureset,featuresetnames)
        try:
            self.results[featureset].setdefault(term,0)
            self.results[featureset][term] += n
        except:
            print('featureset: ' + featureset)
            print('term: ' + str(term))
            raise

    # identifiers

    def get_md5(self,vtmeta): return vtmeta.md5

    def get_sha256(self,vtmeta): return vtmeta.sha256

    # ----------------------------------------------------- features: basic info

    def get_size(self,vtmeta):
        if not vtmeta.size is None:
            if self.includes('size'):
                self.add_term('size',str(vtmeta.size),1)
            if self.includes('size-category'):
                category = categorize_size(int(vtmeta.size))
                self.add_term('size-category',category,1)

    def get_submission_names(self,vtmeta):
        if self.includes('submission_names'):
            for n in vtmeta.submission_names:
                self.add_term('submission_names',n,1)

    def get_tags(self,vtmeta):
        if self.includes('tags'):
            for t in vtmeta.tags:
                self.add_term('tags',t,1)

    def get_scan_count(self,vtmeta):
        if self.includes('scan_count'):
            self.add_term('scan_count',str(vtmeta.total),1)

    def get_positives(self,vtmeta):
        if self.includes('positives') and not vtmeta.positives is None:
            self.add_term('positives',str(vtmeta.positives),1)

    def get_detection_rate(self,vtmeta):
        if (self.includes('detection_rate') and not vtmeta.positives is None):
            positives = float(vtmeta.positives)
            total = float(vtmeta.total)
            rate = int(100.0 * positives / total)
            self.add_term('detection_rate',rate,1)

    def get_type(self,vtmeta):
        if self.includes('type'):
            self.add_term('type',str(vtmeta.type))

    def get_magic(self,vtmeta):
        if self.includes('magic') and vtmeta.has_magic():
            self.add_term('magic',vtmeta.get_magic(),1)

    def get_entry_point(self,vtmeta):
        if self.includes('entry_point') and vtmeta.has_entry_point():
            self.add_term('entry_point',vtmeta.get_entry_point(),1)

    def get_trid(self,vtmeta):
        if vtmeta.has_trid():
            if self.includes('trid'):
                self.add_term('trid',vtmeta.get_trid(),1)
            if self.includes('trid_stemmed'):
                for t in [ stem_trid(t) for t in vtmeta.get_trid().split('\n') ]:
                    self.add_term('trid_stemmed',t,1)

    # ------------------------------------------------------- features: exif ---

    def get_exif(self,vtmeta):
        if vtmeta.has_exif():
            def add(fs,t):
                if self.includes(fs):
                    self.add_term(fs,t)
            add('codesize',vtmeta.get_code_size())
            add('company_name',vtmeta.get_company_name())
            add('exif_entry_point',vtmeta.get_exif_entry_point())
            add('file_description',vtmeta.get_file_description())
            add('file_os',vtmeta.get_file_os())
            add('file_type',vtmeta.get_exif_file_type())
            add('file_version',vtmeta.get_file_version())
            add('file_version_number',vtmeta.get_file_version_number())
            add('image_version',vtmeta.get_image_version())
            add('initialized_data_size',vtmeta.get_initialized_data_size())
            add('internal_name',vtmeta.get_exif_internal_name())
            add('language_code',vtmeta.get_language_code())
            add('legal_copyright',vtmeta.get_legal_copyright())
            add('machinetype',vtmeta.get_machine_type())
            add('original_filename',vtmeta.get_exif_original_filename())
            add('osversion',vtmeta.get_os_version())
            add('petype',vtmeta.get_pe_type())
            add('productname',vtmeta.get_exif_product_name())
            add('product_version',vtmeta.get_exif_product_version())
            add('product_version_number',vtmeta.get_product_version_number())
            add('subsystem',vtmeta.get_subsystem())
            add('timestamp',vtmeta.get_exif_timestamp())
            add('timestamp_yyyy',vtmeta.get_exif_timestamp_yyyy())
            add('timestamp_yyyy_mm',vtmeta.get_exif_timestamp_yyyy_mm())
            add('timestamp_yyyy_mm_dd',vtmeta.get_exif_timestamp_yyyy_mm_dd())
            add('uninitialized_data_size',vtmeta.get_uninitialized_data_size())
                                

    # ------------------------------------------------------ features: scans ---

    def get_scans(self,vtmeta):
        if not vtmeta.scans is None:
            scans = VTScanRecorder(vtmeta.scans)
            if self.includes('detections'):
                detections = scans.get_scans()
                for (v,c) in detections: self.add_term('detections',v,c)
            if self.includes('detections_stemmed'):
                detections = scans.get_stemmed_scans().items()
                for (v,c) in detections: self.add_term('detections_stemmed',v,c)
            if self.includes('detectors'):
                detectors = scans.get_detecting_engines()
                for d in detectors: self.add_term('detectors',d)
            if self.includes('non_detectors'):
                nondetectors = scans.get_non_detecting_engines()
                for d in nondetectors: self.add_term('non_detectors',d)

    # ---------------------------------------------------- features: imports ---

    def get_imports(self,vtmeta):
        if vtmeta.has_imports():
            if self.includes('imported_libraries'):
                for n in vtmeta.get_imported_libraries():
                    self.add_term('imported_libraries',n)
            if self.includes('imported_functions'):
                for n in vtmeta.get_imported_functions():
                    self.add_term('imported_functions',n)

    # --------------------------------------------------- features: sections ---

    def get_section_data(self,vtmeta):
        if vtmeta.has_sections():
            def add(fs,f):
                if self.includes(fs):
                    for n in f():
                        self.add_term(fs,n)
            add('section_names',vtmeta.get_section_names)
            add('section_raw_sizes',vtmeta.get_section_raw_sizes)
            add('section_virtual_sizes',vtmeta.get_section_virtual_sizes)
            add('named_section_md5s',vtmeta.get_named_section_md5s)
            add('named_section_virtual_addresses',vtmeta.get_named_section_virtual_addresses)
            add('named_section_raw_sizes',vtmeta.get_named_section_raw_sizes)
            add('named_section_virtual_sizes',vtmeta.get_named_section_virtual_sizes)

    # -------------------------------------------------- features: resources ---

    def get_resource_data(self,vtmeta):
        if vtmeta.has_resource_details():
            if self.includes('resource_file_types'):
                for n in vtmeta.get_resource_file_types():
                    self.add_term('resource_file_types',n)
            if self.includes('resource_types'):
                for n in vtmeta.get_resource_types():
                    self.add_term('resource_types',n)
            if self.includes('resource_languages'):
                for n in vtmeta.get_resource_languages():
                    self.add_term('resource_languages',n)

    # --------------------------------------------------- features: sigcheck ---

    def get_sigcheck_data(self,vtmeta):
        if vtmeta.has_sigcheck():
            if self.includes('product'):
                self.add_term('product',vtmeta.get_product())
            if self.includes('original_name'):
                self.add_term('original_name',vtmeta.get_original_name())
            if self.includes('publishers'):
                self.add_term('publishers',vtmeta.get_publisher())
            if self.includes('signers'):
                for n in vtmeta.get_signers():
                    self.add_term('signers',n)
            if self.includes('counter_signers'):
                for n in vtmeta.get_counter_signers():
                    self.add_term('counter_signers',n)
            if self.includes('signing_date'):
                self.add_term('signing_date',vtmeta.get_signing_date())
            if self.includes('verified'):
                self.add_term('verified',vtmeta.get_verified())

    # -------------------------------------------------- features: behaviour ---

    def get_behaviour_data(self,vtmeta):
        if vtmeta.has_behaviour():
            def add(fs,f):
                if self.includes(fs):
                    for n in f():
                        self.add_term(fs,n)
            add('runtime_dlls',vtmeta.get_runtime_dlls)
            add('mutexes_created',vtmeta.get_mutexes_created)
            add('mutexes_opened',vtmeta.get_mutexes_opened)
            add('files_copied',vtmeta.get_files_copied)
            add('files_copied_src',vtmeta.get_files_copied_src)
            add('files_copied_dst',vtmeta.get_files_copied_dst)
            add('files_deleted',vtmeta.get_files_deleted)
            add('files_downloaded',vtmeta.get_files_downloaded)
            add('files_moved',vtmeta.get_files_moved)
            add('files_moved_src',vtmeta.get_files_moved_src)
            add('files_moved_dst',vtmeta.get_files_moved_dst)
            add('files_opened',vtmeta.get_files_opened)
            add('files_read',vtmeta.get_files_read)
            add('files_replaced',vtmeta.get_files_replaced)
            add('files_written',vtmeta.get_files_written)
            add('network_dns_ip',vtmeta.get_network_dns_ip)
            add('network_dns_hostname',vtmeta.get_network_dns_hostname)
            add('network_http_url',vtmeta.get_network_http_url)
            add('network_http_method',vtmeta.get_network_http_method)
            add('network_http_user_agent',vtmeta.get_network_http_user_agent)
            add('network_tcp',vtmeta.get_network_tcp)
            add('network_udp',vtmeta.get_network_udp)
            add('processes_created',vtmeta.get_processes_created)
            add('processes_injected',vtmeta.get_processes_injected)
            add('processes_shellcmds',vtmeta.get_processes_shellcmds)
            add('processes_terminated',vtmeta.get_processes_terminated)
            add('registry_deleted',vtmeta.get_registry_deleted)
            add('registry_type',vtmeta.get_registry_type)
            add('registry_val',vtmeta.get_registry_val)
            add('registry_key',vtmeta.get_registry_key)

    # --------------------------------------------------------------- record ---

    def record(self,vtmeta):
        self.get_size(vtmeta)
        self.get_entry_point(vtmeta)
        self.get_submission_names(vtmeta)
        self.get_tags(vtmeta)
        self.get_exif(vtmeta)
        self.get_scan_count(vtmeta)
        self.get_positives(vtmeta)
        self.get_detection_rate(vtmeta)
        self.get_type(vtmeta)
        self.get_magic(vtmeta)
        self.get_trid(vtmeta)
        self.get_scans(vtmeta)
        self.get_imports(vtmeta)        
        self.get_section_data(vtmeta)
        self.get_resource_data(vtmeta)
        self.get_sigcheck_data(vtmeta)
        self.get_behaviour_data(vtmeta)



    

    

    
