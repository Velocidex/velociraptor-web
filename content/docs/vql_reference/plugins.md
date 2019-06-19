---
title: VQL PLugins
weight: 10
---

VQL plugins are the data sources of VQL queries. While SQL queries
refer to static tables of data, VQL queries refer to plugins, which
generate data rows to be filtered by the query.

Unlike SQL, VQL plugins also receive keyword arguments. When the
plugin is evaluated it simply generates a sequence of rows which are
further filtered by the query.

This allows VQL statements to be chained naturally since plugin args
may also be other queries.

{{% notice note %}}

VQL plugins are not the same as VQL functions. A plugin is the subject
of the VQL query - i.e. plugins always follow the `FROM` keyword,
while functions (which return a single value instead of a sequence of
rows) are only present in column specification (e.g. after `SELECT`)
or in condition clauses (i.e. after the `WHERE` keyword).

{{% /notice %}}

## parse_records_with_regex

Arg | Description
----|------------
file|One or more files to parse
regex|One or more regular expressions to match within the file.
accessor|The accessor to use for openning the file.

Parses a file with a set of regexp and yields matches as records.  The
file is read into a large buffer. Then each regular expression is
applied to the buffer, and all matches are emitted as rows.

The regular expressions are specified in the [Go
syntax](https://golang.org/pkg/regexp/syntax/). They are expected to
contain capture variables to name the matches extracted.

For example, consider a HTML file with simple links. The regular
expression might be:

```
regex='<a.+?href="(?P<Link>[^"]+?)"'
```

To produce rows with a column Link.

The aim of this plugin is to split the file into records which can be
further parsed. For example, if the file consists of multiple records,
this plugin can be used to extract each record, while
parse_string_with_regex() can be used to further split each record
into elements. This works better than trying to write a more complex
regex which tries to capture a lot of details in one pass.


### Example

Here is an example of parsing the /var/lib/dpkg/status files. These
files consist of records separated by empty lines:

```
Package: ubuntu-advantage-tools
Status: install ok installed
Priority: important
Section: misc
Installed-Size: 74
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 17
Conffiles:
 /etc/cron.daily/ubuntu-advantage-tools 36de53e7c2d968f951b11c64be101b91
 /etc/update-motd.d/80-esm 6ffbbf00021b4ea4255cff378c99c898
 /etc/update-motd.d/80-livepatch 1a3172ffaa815d12b58648f117ffb67e
Description: management tools for Ubuntu Advantage
 Ubuntu Advantage is the professional package of tooling, technology
 and expertise from Canonical, helping organisations around the world
 manage their Ubuntu deployments.
 .
 Subscribers to Ubuntu Advantage will find helpful tools for accessing
 services in this package.
Homepage: https://buy.ubuntu.com
```

The following query extracts the fields in two passes. The first pass
uses parse_records_with_regex() to extract records in blocks, while
using parse_string_with_regex() to further break the block into
fields.

```sql
SELECT parse_string_with_regex(
   string=Record,
   regex=['Package:\\s(?P<Package>.+)',
     'Installed-Size:\\s(?P<InstalledSize>.+)',
     'Version:\\s(?P<Version>.+)',
     'Source:\\s(?P<Source>.+)',
     'Architecture:\\s(?P<Architecture>.+)']) as Record
   FROM parse_records_with_regex(
     file=linuxDpkgStatus,
     regex='(?sm)^(?P<Record>Package:.+?)\\n\\n')
```

## parse_csv

Arg | Description
----|------------
filename|One or more files to parse
accessor|The accessor to use for openning the file.


Parses records from a CSV file. We expect the first row of the CSV
file to contain column names.  This parser specifically supports
Velociraptor's own CSV dialect and so it is perfect for post
processing already existing CSV files.

The types of each value in each column is deduced based on
Velociraptor's standard encoding scheme. Therefore types are properly
preserved when read from the CSV file.

For example, downloading the results of a hunt in the GUI will produce
a CSV file containing artifact rows collected from all clients.  We
can then use the `parse_csv()` plugin to further filter the CSV file,
or to stack using group by.

### Example

The following stacks the result from a
`Windows.Applications.Chrome.Extensions` artifact:

```sql
SELECT count(items=User) As TotalUsers, Name
FROM parse_csv(filename="All Windows.Applications.Chrome.Extensions.csv")
Order By TotalUsers
Group By Name
```


## parse_evtx

Arg | Description
----|------------
filename|One or more files to parse
accessor|The accessor to use for openning the file.


This plugin parses windows events from the Windows Event log files (EVTX).

A windows event typically contains two columns. The `EventData`
contains event specific structured data while the `System` column
contains common data for all events - including the Event ID.

You should probably almost always filter by one or more event ids
(using the `System.EventID.Value` field).

### Example

```sql
SELECT System.TimeCreated.SystemTime as Timestamp,
       System.EventID.Value as EventID,
       EventData.ImagePath as ImagePath,
       EventData.ServiceName as ServiceName,
       EventData.ServiceType as Type,
       System.Security.UserID as UserSID,
       EventData as _EventData,
       System as _System
FROM watch_evtx(filename=systemLogFile) WHERE EventID = 7045
```

## olevba

Arg | Description
----|------------
file|One or more files to parse
accessor|The accessor to use for openning the file.
max_size|Maximum size of file we load into memory.

This plugin parses the provided files as OLE documents in order to
recover VB macro code. A single document can have multiple code
objects, and each such code object is emitted as a row.


## splitparser

Arg | Description
----|------------
filenames|One or more files to parse
accessor|The accessor to use for openning the file.
regex|The split regular expression (e.g. a comma)
columns|If the first row is not the headers, this arg must provide a list of column names for each value.
first_row_is_headers|A bool indicating if we should get column names from the first row.
count|Only split into this many columns if possible.

This plugin is a more generalized parser for delimited files. It is
not as smart as the `parse_csv()` plugin but can use multiple
delimiters.


## info

This plugin returns a single row with information about the current
system. The information includes the Hostname, Uptime, OS, Platform
etc.

This plugin is very useful in preconditions as it restricts a query to
certain OS or versions.


```sql
SELECT OS from info() where OS = "windows"
```


## pslist

Arg | Description
----|------------
pid|A pid to list. If this is provided we are able to operate much faster by only opening a single process.


Lists running processes.

When specifying the pid this operation is much faster so if you are
interested in specific processes, the pid should be
specified. Otherwise, the plugin returns all processes one on each
row.

## scope

The scope plugin returns the current scope as a single row.

The main use for this plugin is as a NOOP plugin in those cases we
dont want to actually run anything.

### Example

```sql
SELECT 1+1 As Two FROM scop()
```

## environ

Arg | Description
----|------------
vars|One or more names of environment variables to lookup (optional)

The row returned will have all environment variables as columns. If
the var parameter is provided, only those variables will be provided.


## execve

Arg | Description
----|------------
argv|One or more strings forming the arguments of the shell command.
sep|The serparator that will be used to split the stdout into rows.
length|Size of buffer to capture output per row.


This plugin launches an external command and captures its STDERR,
STDOUT and return code. The command's stdout is split using the `sep`
parameter as required.

This plugin is mostly useful for running arbitrary code on the
client. If you do not want to allow arbitrary code to run, you can
disable this by setting the `prevent_execve` flag in the client's
config file. Be aware than many artifacts require running external
commands to collect their output though.

We do not actually transfer the external program to the system
automatically. If you need to run programs which are not usually
installed (e.g. Sysinternal's autoruns.exe) you will need to map them
from a share (requiring direct access to the AD domain) or download
them using the `http_client()` plugin.

## yara

Arg | Description
----|------------
rules|Yara rules in the yara DSL.
files|The list of files to scan.
accessor|Accessor (e.g. NTFS)
context|How many bytes to include around each hit
start|The start offset to scan
end|End scanning at this offset (100mb)
number|Stop after this many hits (1).
blocksize|Blocksize for scanning (1mb).

The `yara()` plugin applies a signature consisting of multiple rules
across files. You can read more about [yara
rules](https://yara.readthedocs.io/en/v3.4.0/writingrules.html). The
accessor is used to open the various files which allow this plugin to
work across raw ntfs, zip members etc.

Scanning proceeds by reading a block from the file, then applying the
yara rule on the block. This will fail if the signature is split
across block boundary.

{{% notice note %}}

By default only the first 100mb of the file are scanned and
scanning stops after one hit is found.

{{% /notice %}}

## proc_yara

Arg | Description
----|------------
rules|Yara rules in the yara DSL.
pid|The process id to scan.
context|How many bytes to include around each hit

This plugin uses yara's own engine to scan process memory for the signatures.

{{% notice note %}}

Process memory access depends on having the [SeDebugPrivilege](https://support.microsoft.com/en-au/help/131065/how-to-obtain-a-handle-to-any-process-with-sedebugprivilege) which depends on how Velociraptor was started. Even when running as System, some processes are not accessible.

{{% /notice %}}

## glob

Arg | Description
----|------------
globs|One or more glob patterns to apply to the filesystem.
accessor|An accessor to use.

The `glob()` plugin is one of the most used plugins. It applies a glob
expression in order to search for files by file name. The glob
expression allows for wildcards, alternatives and character
classes. Globs support both forward and backslashes as path
separators. They also support quoting to delimit components.

A glob expression consists of a sequence of components separated by
path separators. If a separator is included within a component it is
possible to quote the component to keep it together. For example, the
windows registry contains keys with forward slash in their
names. Therefore we may use these to prevent the glob from getting
confused:

```
HKEY_LOCAL_MACHINE\Microsoft\Windows\"Some Key With http://www.microsoft.com/"\Some Value
```

Glob expressions are case insensitive and may contain the following wild cards:

* The `*` matches one or more characters.
* The `?` matches a single character.
* Alternatives are denoted by braces and comma delimited: `{a,b}`
* Recursive search is denoted by a `**`. By default this searches 3 directories deep. If you need to increase it you can add a depth number (e.g. `**10`)

By default globs do not expand environment variables. If you need to
expand environment variables use the `expand()` function explicitly:

```sql
glob(globs=expand(string="%SystemRoot%\System32\Winevt\Logs\*"))
```

### Example

The following searches the raw NTFS disk for event logs.

```sql
SELECT FullPath FROM glob(
   globs="C:\Windows\System32\Winevt\Logs\*.evtx",
   accessor="ntfs")
```
## read_file

Arg | Description
----|------------
chunk|length of each chunk to read from the file.
max_length|Max length of the file to read.
filenames|One or more files to open.
accessor|An accessor to use.

This plugin reads a file in chunks and returns each chunks as a separate row.

It is useful when we want to report file contents for small files like
configuration files etc.

The returned row contains the following columns: data, offset, filename

## stat

Arg | Description
----|------------
filename|One or more files to open.
accessor|An accessor to use.

Get file information. Unlike glob() this does not support wildcards.

## read_key_values

Arg | Description
----|------------
globs|Globs to apply.
accessor|An accessor to use.

This is a convenience plugin which applies the globs to the registry
accessor to find keys. For each key the plugin then lists all the
values within it, and returns a row which has the value names as
columns, while the cells contain the value's stat info (and data
content available in the `Data` field).

This makes it easier to access a bunch of related values at once.


## http_client


Arg | Description
----|------------
url|The URL to access.
params|A dictionary of key/values to encode into the request
headers|A dictionary of additional headers
method|The method to use (GET/POST)
chunk_size|Size of buffers to read per row
disable_ssl_security|If this is true disable SSL security verification.

This plugin makes a HTTP connection using the specified method. The
headers and parameters may be specified. The plugin reads the
specified number of bytes per returned row.

If `disable_ssl_security` is specified we do not enforce SSL
integrity. This is required to connect to self signed ssl web
sites. For example many API handlers are exposed over such
connections.

The `http_client()` plugin allows use to interact with any web
services. If the web service returns a json blob, we can parse it with
the `parse_json()` function (or `parse_xml()` for SOAP
endpoints). Using the parameters with a POST method we may actually
invoke actions from within VQL (e.g. send an SMS via an SMS gateway
when a VQL event is received).So this is a very powerful plugin.

### Example

The following VQL returns the client's external IP as seen by the
externalip service.

```sql
SELECT Content as IP from http_client(url='http://www.myexternalip.com/raw')
```

## upload

Arg | Description
----|------------
file|The file to upload
accessor|An accessor to use.

This plugin uploads the specified file to the server. If Velociraptor
is run locally the file will be copied tothe `--dump_dir` path or
added to the triage evidence container.

This functionality is also available using the upload() function which
might be somewhat easier to use.

## authenticode

Arg | Description
----|------------
filename|The filename of the executable

Uses the Windows API to extract and verify the file's authenticode
signature. Since we use the windows API this can only work with the
"file" accessor.

## certificates

Collect certificate from the system trust store.

## users

Display information about workstation local users. This is obtained
through the NetUserEnum() API.

## wmi

Arg | Description
----|------------
query|The WMI query to issue.
namespace|The WMI namespace to use (ROOT/CIMV2)

This plugin issues a WMI query and returns its rows directly. The
exact format of the returned row depends on the WMI query issued.

This plugin creates a bridge between WMI and VQL and it is a very
commonly used plugin for inspecting the state of windows systems.
