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

import datetime

class PropertyFormatter(object):

    def __init__(self,specs):
        self.specs = specs     # featureset -> report spec list

    def add_spec(self,fs,fsformat=[ "default" ]):
        self.specs[fs] = fsformat

    def get_featuresets(self): return self.specs.keys()

    def filter_featureset(self,fsspecs,fsproperties):
        filtertext = fsspecs[fsspecs.index("startswith") + 1]
        keys = list(fsproperties.keys())
        for t in keys:
            if not str(t).startswith(filtertext):
                del fsproperties[t]
        return fsproperties

    def format_properties(self,doccount,properties,reps=None):
        lines = []

        for fs in properties:
            lines.append(['\n' + fs])
            fsproperties = properties[fs]
            fsreps = reps[fs] if reps is not None else None
            fsspecs = self.specs[fs]
            lines.append(self.format_featureset(doccount,fs,fsspecs,fsproperties,fsreps))

        lines = [ '\n'.join(line) for line in lines ]
        return '\n'.join(lines)

    def format_properties_as_dict(self, doccount, properties,reps=None):
        lines = {}

        for fs in properties:
            fsproperties = properties[fs]            
            fsreps = reps[fs] if reps is not None else None
            fsspecs = self.specs[fs]

            lines[fs] = self.format_featureset_as_dict(doccount,fs,fsspecs,fsproperties,fsreps)
        return lines

    def format_featureset(self,doccount,fs,fsspecs,fsproperties,fsreps=None):
        if fs == 'detection_rate':
            return self.format_detection_rate(fsspecs,fsproperties)
        if fs == 'detections_stemmed':
            return self.format_detections(fsspecs,fsproperties)
        if fs == 'detectors' or fs == 'non_detectors':
            return self.format_detectors(doccount,fsspecs,fsproperties)
        if fs == 'size' or fs == 'entry_point':
            return self.format_multiplicity(fsspecs,fsproperties,fsreps)
        if fs == 'signing_date':
            return self.format_signing_date(fsspecs,fsproperties)
        if fs == 'imported_functions':
            return self.format_imported_functions(doccount,fsspecs,fsproperties,fsreps)
        else:
            lines = []
            if "startswith" in fsspecs:
                fsproperties = filter_featureset(fsspecs, fsproperties)
            for t in sorted(fsproperties,key=lambda x:(fsproperties[x],x)):
                if fsreps is None:
                    lines.append(str(fsproperties[t]).rjust(6) + '  ' + t)
                else:
                    lines.append((str(fsproperties[t]) + ' ( ' + str(fsreps[t]) + ' ) ').rjust(6) + '  ' +  t)
            return lines

    def format_featureset_as_dict(self, doccount, fs, fsspecs, fsproperties,fsreps=None):
        if fs == 'imported_functions':
            return self.format_imported_functions_as_list(doccount, fsspecs, fsproperties)
        else:
            if "startswith" in fsspecs:
                fsproperties = filter_featureset(fsspecs, fsproperties)
            return fsproperties

    def format_imported_functions(self,doccount,fsspecs,fsproperties,fsreps=None):
        lines = []
        for spec in fsspecs:
            if spec == 'multiplicity':
                total = sum([fsproperties[t] for t in fsproperties ])
                distinct = len(fsproperties)
                if distinct > 0 and doccount > 0:
                    multiplicity = float(total)/float(distinct)
                    coverage =  (float(total) / float(distinct)) / float(doccount)
                else:
                    multiplicity = 0.0
                    coverage = 0.0
                lines.append('Multiplicity (' + str(total) + '/' + str(distinct) + '): '
                                 + '{0:.2f}'.format(multiplicity)
                                 + ' (coverage: ' + '{0:.3f}'.format(coverage) + ')')
            elif spec == 'distribution':
                distro = {}  #  appearance count -> function count
                for t in fsproperties:
                    fncount = fsproperties[t]
                    distro.setdefault(fncount,0)
                    distro[fncount] += 1
                lines.append('Distribution of appearance counts')
                for c in sorted(distro):
                    lines.append(str(c).rjust(4) + ': ' + str(distro[c]).rjust(4))
            elif spec == 'default':
                for t in sorted(fsproperties,key=lambda x:fsproperties[x]):
                    if fsreps is None:
                        lines.append(str(fsproperties[t]).rjust(6) + '  ' + t)
                    else:
                        lines.append((str(fsproperties[t]) + ' ( ' + str(fsreps[t]) + ' ) ').rjust(6) + '  ' +  t)
        return lines

    def format_imported_functions_as_list(self, doccount, fsspecs, fsproperties):
        lines = []
        for spec in fsspecs:
            if spec == 'multiplicity':
                total = sum([fsproperties[t] for t in fsproperties ])
                distinct = len(fsproperties)
                lines.append( str(total) + ' / ' + str(distinct) )
        return lines

    def format_detection_rate(self,fsspecs,fsproperties):
        lines = []
        for spec in fsspecs:
            if spec == 'range':
                mindet = 100
                maxdet = 0
                for t in [ int(t) for t in fsproperties ]:
                    if t < mindet: mindet = t
                    if t > maxdet: maxdet = t
                lines.append('minimum detections: ' + str(mindet)
                            + '; maximum detections: ' + str(maxdet))
            elif spec == 'histogram':
                h = {}
                for i in range(0,(maxdet+10),10): h[i] = 0
                for t in [ int(t) for t in fsproperties ]:
                    h[int(t/10) * 10] += fsproperties[str(t)]
                maxh = max(h[x] for x in range(0,(maxdet+10),10))
                for i in range(0,(maxdet+10),10):
                    lines.append(str(i).rjust(4) + '  ' + ('=' * int(80 * float(h[i]/maxh))))
            elif spec == 'default':
                h = {}
                for i in range(0,(maxdet+10),10): h[i] = 0
                for t in [ int(t) for t in fsproperties ]:
                    h[int(t/10) * 10] += fsproperties[str(t)]
                for i in sorted(h):
                    lines.append(str(i) + ' ' + str(h[i]))
        return lines

    def format_detections(self,fsspecs,fsproperties):
        lines = []
        for spec in fsspecs:
            if spec.startswith('max'):
                count = int(spec.split(':')[1])
                for t in list(sorted(fsproperties,key=lambda x:fsproperties[x],reverse=True))[:count]:
                    lines.append(str(fsproperties[t]).rjust(6) + '  ' +  t)
            elif spec == 'default':
                for t in sorted(fsproperties,key=lambda x:fsproperties[x]):
                    lines.append(str(fsproperties[t]).rjust(6) + '  ' +  t)
        return lines

    def format_detectors(self,doccount,fsspecs,fsproperties):
        lines = []
        for spec in fsspecs:
            if spec == 'group':
                lowcutoff = int(0.1 * float(doccount))
                highcutoff = int(0.9  * float(doccount))
                high = []
                low = []
                medium = []
                for t in fsproperties:
                    count = fsproperties[t]
                    if count >= highcutoff:
                        high.append((count,t))
                    elif count <= lowcutoff:
                        low.append((count,t))
                    else:
                        medium.append((count,t))
                lines.append('High rate:')
                for (c,t) in sorted(high): lines.append(str(c).rjust(5) + '  ' + t)
                lines.append('\nLow rate:')
                for (c,t) in sorted(low): lines.append(str(c).rjust(5) + '  ' + t)
                lines.append('\nMedium rate:')
                for (c,t) in sorted(medium): lines.append(str(c).rjust(5) + '  ' + t)
            elif spec == 'default':
                for t in sorted(fsproperties,key=lambda x:fsproperties[x]):
                    lines.append(str(fsproperties[t]).rjust(6) + '  ' +  t)
        return lines

    def format_multiplicity(self,fsspecs,fsproperties,fsreps=None):
        lines = []
        for spec in fsspecs:
            if spec == 'multiplicity':
                minval = min([ int(t) for t in fsproperties ])
                maxval = max([ int(t) for t in fsproperties ])
                total = sum([fsproperties[t] for t in fsproperties])
                distinct = len(fsproperties)
                lines.append('Multiplicity (' + str(total) + '/' + str(distinct) + '): '
                                 + '{0:.2f}'.format(float(total)/float(distinct))
                                 + '; [ ' + str(minval) + ' - ' + str(maxval) + ']')
            elif spec == 'default':
                for t in sorted(fsproperties,key=lambda x:fsproperties[x]):
                    if fsreps is None:
                        lines.append(str(fsproperties[t]).rjust(6) + '  ' + t)
                    else:
                        lines.append((str(fsproperties[t]) + ' ( ' + str(fsreps[t]) + ' ) ').rjust(6) + '  ' +  t)

        return lines

    def format_signing_date(self,fsspecs,fsproperties):
        lines = []
        for spec in fsspecs:
            if spec == 'standard':
                for t in fsproperties:
                    signdate = t.split(' ')
                    if len(signdate) == 3:
                        ampm = signdate[1]
                        date = [ int(t) for t in signdate[2].split('/') ]
                        time = [ int(t) for t in signdate[0].split(':') ]
                        if time[0] == 12 and ampm == 'AM': hr = time[0] - 12
                        elif time[0] == 12 or ampm == 'AM': hr = time[0]
                        else: hr = time[0] + 12
                        minutes = time[1]
                        month = date[0]
                        day = date[1]
                        year = date[2]
                        newdate = '{:%Y-%m-%d %H:%M}'.format(datetime.datetime(year, month, day, hr, minutes))
                        lines.append(newdate + ' (' + str(fsproperties[t]) + ')')
                    else:
                        lines.append(t)
            elif spec == 'default':
                for t in sorted(fsproperties,key=lambda x:fsproperties[x]):
                    lines.append(str(fsproperties[t]).rjust(6) + '  ' +  t)
        return sorted(lines)
            

            
                
                
                
                
                
        
                
                
            
            
