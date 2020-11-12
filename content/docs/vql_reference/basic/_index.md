---
title: Basic VQL functions and plugins
weight: 10
linktitle: Basic VQL
index: true
---

VQL provides a basic set of functions and plugins allowing
queries to maniulate data and implement logic. This page details
those plugins which are considered foundational to the VQL
language and therefore may be useful in all types of artifacts.

{{% notice note %}}
VQL plugins are not the same as VQL functions. A plugin is the subject
of the VQL query - i.e. plugins always follow the `FROM` keyword,
while functions (which return a single value instead of a sequence of
rows) are only present in column specification (e.g. after `SELECT`)
or in condition clauses (i.e. after the `WHERE` keyword).
{{% /notice %}}

## array
<span class='vql_type pull-right'>Function</span>

Create an array with all the args.

This function accepts arbitrary arguments and creates an array by
flattening the arguments. For example `array(a=1, b=2)` will return
`[1, 2]`.

You can use this to flatten a subquery as well:

```sql
SELECT array(a1={ SELECT User FROM Artifact.Windows.System.Users() }) as Users FROM scope()
```

Will return a single row with Users being an array of names.



## atoi
<span class='vql_type pull-right'>Function</span>

Convert a string to an int.

Arg | Description | Type
----|-------------|-----
string|A string to convert to int|Any (required)


## base64decode
<span class='vql_type pull-right'>Function</span>

Decodes a base64 encoded string.

Arg | Description | Type
----|-------------|-----
string|A string to decode|string (required)


## base64encode
<span class='vql_type pull-right'>Function</span>

Encodes a string into base64.

Arg | Description | Type
----|-------------|-----
string|A string to decode|string (required)


## basename
<span class='vql_type pull-right'>Function</span>

Return the basename of the path.

Arg | Description | Type
----|-------------|-----
path|Extract directory name of path|string (required)


## copy
<span class='vql_type pull-right'>Function</span>

Copy a file.

Arg | Description | Type
----|-------------|-----
filename|The file to copy from.|string (required)
accessor|The accessor to use|string
dest|The destination file to write.|string (required)
permissions|Required permissions (e.g. 'x').|string


## count
<span class='vql_type pull-right'>Function</span>

Counts the items.

Arg | Description | Type
----|-------------|-----
items||Any


## dict
<span class='vql_type pull-right'>Function</span>

Construct a dict from arbitrary keyword args.


## dirname
<span class='vql_type pull-right'>Function</span>

Return the directory path.

Arg | Description | Type
----|-------------|-----
path|Extract directory name of path|string (required)


## encode
<span class='vql_type pull-right'>Function</span>

Encodes a string as as different type. Currently supported types include 'hex', 'base64'.

Arg | Description | Type
----|-------------|-----
string||Any (required)
type||string (required)


## enumerate
<span class='vql_type pull-right'>Function</span>

Collect all the items in each group by bin.

Arg | Description | Type
----|-------------|-----
items||Any


## environ
<span class='vql_type pull-right'>Function</span>

Get an environment variable.

Arg | Description | Type
----|-------------|-----
var|Extract the var from the environment.|string (required)


## expand
<span class='vql_type pull-right'>Function</span>

Expand the path using the environment.

This function expands environment variables into the path. It is
normally needed after using registry values of type REG_EXPAND_SZ as
they typically contain environment strings. Velociraptor does not
automatically expand such values since environment variables typically
depend on the specific user account which reads the registry value
(different user accounts can have different environment variables).


Arg | Description | Type
----|-------------|-----
path|A path with environment escapes|string (required)


## filter
<span class='vql_type pull-right'>Function</span>

Filters a strings array by regex.


Arg | Description | Type
----|-------------|-----
list|A list of items to filter|list of string (required)
regex|A regex to test each item|list of string (required)


## format
<span class='vql_type pull-right'>Function</span>

Format one or more items according to a format string.

Arg | Description | Type
----|-------------|-----
format|Format string to use|string (required)
args|An array of elements to apply into the format string.|Any


## get
<span class='vql_type pull-right'>Function</span>

Gets the member field from item.

This is useful to index an item from an array. For example:

### Example

```sql
select get(item=[dict(foo=3), 2, 3, 4], member='0.foo') AS Foo from scope()

[
 {
   "Foo": 3
 }
]
```


Arg | Description | Type
----|-------------|-----
item||Any
member||string
field||Any
default||Any


## getpid
<span class='vql_type pull-right'>Function</span>

Returns the current pid of the process.


## humanize
<span class='vql_type pull-right'>Function</span>

Format items in human readable way.

Formats a byte count in human readable way (e.g. Mb, Gb etc).


Arg | Description | Type
----|-------------|-----
bytes|Format bytes with units|int64


## if
<span class='vql_type pull-right'>Function</span>

Conditional execution of query

This function evaluates a condition. Note that the values used in the
`then` or `else` clause are evaluated lazily. They may be expressions
that involve stored queries (i.e. queries stored using the `LET`
keyword). These queries will not be evaluated if they are not needed.

This allows a query to cheaply branch. For example, if a parameter is
given, then perform hash or upload to the server. See the


Arg | Description | Type
----|-------------|-----
condition||Any (required)
then||LazyExpr (required)
else||LazyExpr


## join
<span class='vql_type pull-right'>Function</span>

Join all the args on a separator.

Joins the array into a string separated by the sep character.


Arg | Description | Type
----|-------------|-----
array|The array to join|list of string (required)
sep|The separator|string


## len
<span class='vql_type pull-right'>Function</span>

Returns the length of an object.

Arg | Description | Type
----|-------------|-----
list|A list of items too filter|Any (required)


## log
<span class='vql_type pull-right'>Function</span>

Log the message.

Arg | Description | Type
----|-------------|-----
message|Message to log.|string (required)


## lowcase
<span class='vql_type pull-right'>Function</span>



Arg | Description | Type
----|-------------|-----
string|A string to lower|string (required)


## max
<span class='vql_type pull-right'>Function</span>

Finds the largest item in the aggregate.

It is only meaningful in a group by query.

### Example

The following query lists all the processes and shows the largest
bash pid of all bash processes.

```SQL
SELECT Name, max(items=Pid) as LargestPid from pslist() Where Name =~ 'bash' group by Name
```


Arg | Description | Type
----|-------------|-----
items||Any


## min
<span class='vql_type pull-right'>Function</span>

Finds the smallest item in the aggregate.

It is only meaningful in a group by query.

### Example

The following query lists all the processes and shows the smallest
bash pid of all bash processes.

```SQL
SELECT Name, min(items=Pid) as SmallestPid from pslist() Where Name =~ 'bash' group by Name
```


Arg | Description | Type
----|-------------|-----
items||Any


## now
<span class='vql_type pull-right'>Function</span>

Returns current time in seconds since epoch.

Arg | Description | Type
----|-------------|-----
string|A string to convert to int|Any (required)


## path_join
<span class='vql_type pull-right'>Function</span>

Build a path by joining all components.

Arg | Description | Type
----|-------------|-----
components|Path components to join.|list of string (required)


## query
<span class='vql_type pull-right'>Function</span>

Launch a subquery and materialize it into a list of rows.

Arg | Description | Type
----|-------------|-----
vql||StoredQuery (required)


## rand
<span class='vql_type pull-right'>Function</span>

Selects a random number.

Arg | Description | Type
----|-------------|-----
range|Selects a random number up to this range.|int64


## read_file
<span class='vql_type pull-right'>Function</span>

Read a file into a string.

Arg | Description | Type
----|-------------|-----
length|Max length of the file to read.|int
filename|One or more files to open.|string (required)
accessor|An accessor to use.|string


## scope
<span class='vql_type pull-right'>Function</span>

return the scope.


## serialize
<span class='vql_type pull-right'>Function</span>

Encode an object as a string (csv or json).

Arg | Description | Type
----|-------------|-----
item|The item to encode|Any (required)
format|Encoding format (csv,json)|string


## sleep
<span class='vql_type pull-right'>Function</span>

Sleep for the specified number of seconds. Always returns true.

Arg | Description | Type
----|-------------|-----
time|The number of seconds to sleep|int64


## split
<span class='vql_type pull-right'>Function</span>

Splits a string into an array based on a regexp separator.

Arg | Description | Type
----|-------------|-----
string|The value to split|string (required)
sep|The serparator that will be used to split|string (required)


## str
<span class='vql_type pull-right'>Function</span>

Normalize a String.

Arg | Description | Type
----|-------------|-----
str|The string to normalize|Any (required)


## strip
<span class='vql_type pull-right'>Function</span>

Strip a prefix from a string.

Arg | Description | Type
----|-------------|-----
string|The string to strip|string (required)
prefix|The prefix to strip|string


## timestamp
<span class='vql_type pull-right'>Function</span>

Convert from different types to a time.Time.

Arg | Description | Type
----|-------------|-----
epoch||Any
winfiletime||int64
string|Guess a timestamp from a string|string
us_style|US Style Month/Day/Year|bool


## upcase
<span class='vql_type pull-right'>Function</span>



Arg | Description | Type
----|-------------|-----
string|A string to lower|string (required)


## url
<span class='vql_type pull-right'>Function</span>

Construct a URL or parse one.

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


Arg | Description | Type
----|-------------|-----
scheme|The scheme to use|string
host|The host component|string
path|The path component|string
fragment|The fragment|string
parse|A url to parse|string


## utf16
<span class='vql_type pull-right'>Function</span>

Parse input from utf16.

Arg | Description | Type
----|-------------|-----
string|A string to decode|string (required)


## utf16_encode
<span class='vql_type pull-right'>Function</span>

Encode a string to utf16 bytes.

Arg | Description | Type
----|-------------|-----
string|A string to decode|string (required)

