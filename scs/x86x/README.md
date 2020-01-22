## X86 Malware Similarity Search

Similarity search on x86 executables can be performed using VirusTotal meta data
(in json format) and/or based on features extracted by the
[CodeHawk Binary Analyzer](https://github.com/kestreltechnology/CodeHawk-Binary).
For the similarity search based on meta data the executables themselves are not
required.

- set PYTHONPATH  (adjust for local path to kt-semantic-code-search):
  ```
  > export PYTHONPATH=$HOME/kt-semantic-code-search
  ```

The VirusTotal meta data file names are assumed to end with the suffix "vtmeta".
The following script can be used to extract and index the features:
```
> cd scs/x86x/cmdline/pe32
> python chx86_index_meta_features {path to meta data} {path to store index}
```
This will read all files found in a the directory or subdirectory of the path
to meta data specified and index the features specified in the script file,
which includes basic information about the executable, liike size, submission
names and entry point, as well as data about VirusTotal detections and
runtime behavior obtained by the VirusTotal engines, and static data like
imported libraries and library functions. A full list is given in the
script file.

Once an index directory has been created the following script can be used to
search for executable that have particular features, as specified in a
pattern, given in json format:
```
> python chx86_find_similar {path to index} {pattern file}
```
Example patterns are provided in the directory scs/x86xdata/vtmeta_patterns.

Patterns consist of two parts: The first part specifies the features to be
searched for; the second part specifies which other properties are to be
output, in what format.
