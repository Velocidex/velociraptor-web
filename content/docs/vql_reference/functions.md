---
title: VQL Functions
weight: 40
---

VQL Functions operate on value to return other values. Functions are
useful to transform values obtained from a VQL row.

{{% notice note %}}
VQL plugins are not the same as VQL functions. A plugin is the subject
of the VQL query - i.e. plugins always follow the `FROM` keyword,
while functions (which return a single value instead of a sequence of
rows) are only present in column specification (e.g. after `SELECT`)
or in condition clauses (i.e. after the `WHERE` keyword).
{{% /notice %}}



## array

This function accepts arbitrary arguments and creates an array by
flattening the arguments. For example `array(a=1, b=2)` will return
`[1, 2]`.

You can use this to flatten a subquery as well:

```sql
SELECT array(a1={ SELECT User FROM Artifact.Windows.System.Users() }) as Users FROM scope()
```

Will return a single row with Users being an array of names.

## atoi

Arg | Description | Type
----|-------------|-----
string | A string to convert to int | string (required)

Converts a string to an integer.

## authenticode

Arg | Description | Type
----|-------------|-----
filename | The filename to parse. | string (required)

Uses the Windows API to extract and verify the file's authenticode
signature. Since we use the windows API this can only work with the
"file" accessor.

## base64decode

Arg | Description | Type
----|-------------|-----
string | A string to decode | string (required)

Decodes a base64 encoded string.

## base64encode

Arg | Description | Type
----|-------------|-----
string | A string to encode | string (required)

Encodes a binary string to base64.

## basename

Arg | Description | Type
----|-------------|-----
path | Extract directory name of path | string (required)

Splits the path on separator and return the basename.

## binary_parse

Arg | Description | Type
----|-------------|-----
offset | Start parsing from this offset. | int64
string | The string to parse. | string (required)
profile | The profile to use. | string
iterator | An iterator to begin with. | string
target | The target type to fetch. | string

Parse a binary string with profile based parser.

This plugin extract binary data from strings. It works by applying a
profile to the binary string and generating an object from that. Profiles use the same syntax as Rekall or Volatility. For example a profile might be:

```json
{
  "StructName": [10, {
     "field1": [2, ["unsigned int"]],
     "field2": [6, ["unsigned long long"]],
  }]
}
```

The profile is compiled and overlayed on top of the offset specified,
then the object is emitted with its required fields.

### Example:

```
velociraptor query 'select binary_parse(profile=profile, string="hello world", target="X", offset=2) as Item from scope()' --env profile='{"X":[10,{"field1":[0,["unsigned short"]]}]}'
[
 {
  "Item": {
    "field1": "27756"
   }
 }
]
```

## collect

Launch an artifact collection against a client.

Arg | Description | Type
----|-------------|-----
client_id | The client id to schedule a collection on | string (required)
artifacts | A list of artifacts to collect |  list of string (required)
env | Parameters to apply to the artifacts | vfilter.Any

## compress

Arg | Description | Type
----|-------------|-----
path | A VFS path to compress |  list of string (required)

Compress a file in the server's FileStore. A compressed
file is archived so it takes less space. It is still possible to see
the file and read it but not to seek within it.

## count

Counts the items.

Arg | Description | Type
----|-------------|-----
items |  | vfilter.Any (required)

## dict

Construct a dict from arbitrary keyword args. The dictionary can be
referenced later by VQL expressions.

## dirname

Arg | Description
----|------------
path|The path to use

Splits the path on separator and return the directory name.

## encode

Arg | Description | Type
----|-------------|-----
string |  | vfilter.Any (required)
type |  | string (required)

Encodes a string as as different type. Currently supported types include 'hex', 'base64'.

## environ

Arg | Description | Type
----|-------------|-----
var | Extract the var from the environment. | string (required)

Returns the value of the environment variable specified.

## expand

Arg | Description | Type
----|-------------|-----
path | A path with environment escapes | string (required)

This function expands environment variables into the path. It is
normally needed after using registry values of type REG_EXPAND_SZ as
they typically contain environment strings. Velociraptor does not
automatically expand such values since environment variables typically
depend on the specific user account which reads the registry value
(different user accounts can have different environment variables).

## file_store


Arg | Description | Type
----|-------------|-----
path | A VFS path to convert |  list of string (required)

Resolves file store paths into full filesystem paths. This function is
only available on the server. It can be used to find the backing file
behind a filestore path so it can be passed on to an external program.

Velociraptor uses the concept of a Virtual File System to manage the
information about clients etc. The VFS path is a path into the file
store. Of course ultimately (at least in the current implementation)
the file store is storing files on disk, but the disk filename is not
necessarily the same as the VFS path (for example non representable
characters are escaped).

You can use the `file_store()` function to return the real file path
on disk. This probably only makes sense for VQL queries running on the
server which can independently open the file.

In future the file store may be abstracted (e.g. files may not be
locally stored at all) and this function may stop working.

## filter

Arg | Description | Type
----|-------------|-----
list | A list of items too filter |  list of string (required)
regex | A regex to test each item |  list of string (required)

Returns another array filtered by the regular expression.

## format

Arg | Description | Type
----|-------------|-----
format | Format string to use | string (required)
args | An array of elements to apply into the format string. | Any

Format one or more items according to a format string. The format
string is interpreted using [the standard golang fmt
package](https://golang.org/pkg/fmt/).

The function returns a string.

## get

Arg | Description | Type
----|-------------|-----
item |  | vfilter.Any (required)
member |  | string (required)

Gets the member field from item. This is useful to index an item from
an array. For example:

### Example

```sql
select get(item=[dict(foo=3), 2, 3, 4], member='0.foo') AS Foo from scope()

[
 {
   "Foo": 3
 }
]
```

## getpid

Returns Velociraptor's own pid.

## grep

Arg | Description | Type
----|-------------|-----
path | path to open. | string (required)
accessor | An accessor to use. | string
keywords | Keywords to search for. |  list of string (required)
context | Extract this many bytes as context around hits. | int

Search a file for keywords.

## hash


Arg | Description | Type
----|-------------|-----
path | Path to open and hash. | string (required)
accessor | The accessor to use | string

This function calculates the MD5, SHA1 and SHA256 hashes of the file.

## humanize

Arg | Description | Type
----|-------------|-----
bytes | Format bytes with units | int64

Formats a byte count in human readable way (e.g. Mb, Gb etc).

## if

Arg | Description
----|------------
condition|  A condition (either a value or a subquery)
then|  a value if the condition is true
else|  a value if the condition is false

This function evaluates a condition. Note that the values used in the
`then` or `else` clause are evaluated lazily. They may be expressions
that involve stored queries (i.e. queries stored using the `LET`
keyword). These queries will not be evaluated if they are not needed.

This allows a query to cheaply branch. For example, if a parameter is
given, then perform hash or upload to the server. See the
`Windows.Search.FileFinder` for an example of how `if()` is used.

## int


Arg | Description | Type
----|-------------|-----
int | The integer to round | vfilter.Any

Truncate a float to an integer.

## ip

Arg | Description | Type
----|-------------|-----
netaddr4_le | A network order IPv4 address (as little endian). | int64
netaddr4_be | A network order IPv4 address (as big endian). | int64


Converts an ip address encoded in various ways. If the IP address is
encoded as 32 bit integer we can use netaddr4_le or netaddr4_be to
print it in a human readable way.

This currently does not support IPv6 addresses. Those are usually
encoded as an array of 8 bytes which makes it easy to format using the
`format()` function:

```
  format(format="%x:%x:%x:%x:%x:%x:%x:%x", value)
```

## join

Arg | Description | Type
----|-------------|-----
sep | The separator | string
array | The array to join |  list of string (required)

Joins the array into a string separated by the sep character.

## label

Arg | Description | Type
----|-------------|-----
client_id | Client ID to label. | string (required)
labels | A list of labels to apply |  list of string (required)
op | An operation on the labels (add, remove) | string


Add the labels to the client. If op is 'remove' then remove these labels.

This function only works when run on the server.

## lowcase

Arg | Description | Type
----|-------------|-----
string | A string to lower | string (required)

Converts a string to lower case.

## max

Arg | Description | Type
----|-------------|-----
items |  | vfilter.Any (required)

This finds the smallest number in the aggregate. It is only meaningful
in a group by query.

### Example

The following query lists all the processes and shows the largest
bash pid of all bash processes.

```SQL
SELECT Name, max(items=Pid) as LargestPid from pslist() Where Name =~ 'bash' group by Name
```

## min

Arg | Description | Type
----|-------------|-----
items |  | vfilter.Any (required)

This finds the smallest number in the aggregate. It is only meaningful
in a group by query.

### Example

The following query lists all the processes and shows the smallest
bash pid of all bash processes.

```SQL
SELECT Name, min(items=Pid) as SmallestPid from pslist() Where Name =~ 'bash' group by Name
```

## now

Returns the current time as seconds since the unix epoch.

## parse_float

Arg | Description | Type
----|-------------|-----
string | A string to convert to int | string (required)

Convert a string to a float.

## parse_json

Arg | Description | Type
----|-------------|-----
data | Json encoded string. | string (required)

This function parses a json string into a dict.

Note that when VQL dereferences fields in a dict it returns a Null for
those fields that do not exist. Thus there is no error in actually
accessing missing fields, the column will just return nil.

## parse_json_array

Arg | Description | Type
----|-------------|-----
data | Json encoded string. | string (required)

This function is similar to `parse_json()` but works for a JSON list
instead of an object.

## parse_pe

Arg | Description | Type
----|-------------|-----
file | The PE file to open. | string (required)
accessor | The accessor to use. | string

Parse a PE file.

## parse_string_with_regex

Arg | Description | Type
----|-------------|-----
string | A string to parse. | string (required)
regex | The regex to apply. |  list of string (required)

Parse a string with a set of regex and extract fields. Returns a dict
with fields populated from all regex capture variables.

## parse_xml

Arg | Description | Type
----|-------------|-----
file | XML file to open. | string (required)
accessor | The accessor to use | string

This function parses the xml file into a dict like object which can
then be queried.

## rate

Arg | Description | Type
----|-------------|-----
x | The X float | float64 (required)
y | The Y float | float64 (required)

Calculates the rate (derivative) between two quantities. For example
if a monitoring plugin returns an absolute value sampled in time
(e.g. bytes transferred sampled every second) then the rate() plugin
can calculate the average bytes/sec.

This function works by remembering the values of x and y from the
previous row and applying the current rows values.

## regex_replace

Arg | Description | Type
----|-------------|-----
source | The source string to replace. | string (required)
replace | The substitute string. | string (required)
re | A regex to apply | string (required)

Search and replace a string with a regexp. Note you can use $1 to
replace the capture string.

## scope

return the scope as a dict.

## split

Arg | Description
----|------------
string|The string to split
sep|A regex to serve as a separator.

Splits a string into an array based on a regexp separator.

## tempfile

Arg | Description | Type
----|-------------|-----
data | Data to write in the tempfile. |  list of string (required)
extension | An extension to place in the tempfile. | string

Create a temporary file and write some data into it. The file will be
removed when the query completes.

## timestamp

Arg | Description | Type
----|-------------|-----
epoch |  | int64
winfiletime |  | int64

Convert seconds from epoch into a string.

## upcase

Arg | Description | Type
----|-------------|-----
string | A string to lower | string (required)

Converts a string to upper case

## upload

Arg | Description | Type
----|-------------|-----
accessor | The accessor to use | string
file | The file to upload | string (required)
name | The name of the file that should be stored on the server | string

This function uploads the specified file to the server. If Velociraptor
is run locally the file will be copied to the `--dump_dir` path or
added to the triage evidence container.

## url

Arg | Description | Type
----|-------------|-----
scheme | The scheme to use | string
host | The host component | string
path | The path component | string
fragment | The fragment | string
parse | A url to parse | string

This function parses or constructs URLs. A URL may be constructed from
scratch by providing all the components or it may be parsed from an
existing URL.

The returned object is a [golang
URL](https://golang.org/pkg/net/url/#URL) and can be serialized again
using its `String` method.

This function is important when constructing parameters for certain
accessors which receive a URL. For example the `zip` accessor requires
its file names to consist of URLs. The Zip accessor interprets the URL
in the following way:

- The scheme is the delegate accessor to use.
- The path is the delegate accessor's filename
- The fragment is used by the zip accessor to retrieve the zip member itself.

In this case it is critical to properly escape each level - it is not
possible in the general case to simply append strings. You need to use
the `url()` function to build the proper url.

## utf16

Arg | Description | Type
----|-------------|-----
string | A string to decode | string (required)

Converts a UTF16 encoded string to a normal utf8 string.
