---
title: VQL Functions
linktitle: VQL Functions
description: VQL Functions operate on value to return other values.
date: 2019-02-01
publishdate: 2019-02-01
lastmod: 2019-02-01
categories: [vql]
keywords: []
menu:
  docs:
    parent: "vql_reference"
    weight: 10
weight: 1
draft: false
aliases: []
toc: true
---

Functions are useful to transform values obtained from a VQL row.

{{% notice note %}}
VQL plugins are not the same as VQL functions. A plugin is the subject
of the VQL query - i.e. plugins always follow the `FROM` keyword,
while functions (which return a single value instead of a sequence of
rows) are only present in column specification (e.g. after `SELECT`)
or in condition clauses (i.e. after the `WHERE` keyword).
{{% /notice %}}



## parse_json

Arg | Description
----|------------
data|A string containing a serialized json object.

This function parses a json string into a dict.

Note that when VQL dereferences fields in a dict it returns a Null for
those fields that do not exist. Thus there is no error in actually
accessing missing fields, the column will just return nil.


## parse_json_array

Arg | Description
----|------------
data|A string containing a serialized json array.

This function is similar to `parse_json()` but works for a JSON list
instead of an object.



## parse_xml

Arg | Description
----|------------
file|A single file to parse
accessor|The accessor to use for openning the file.


This function parses the xml file into a dict like object which can
then be queried.

## environ

Arg | Description
----|------------
var|The name of the environment variable to lookup

Returns the value of the environment variable specified.

## dirname

Arg | Description
----|------------
path|The path to use

Splits the path on separator and return the directory name.

## basename

Arg | Description
----|------------
path|The path to use

Splits the path on separator and return the basename.

## tempfile

Arg | Description
----|------------
data|The data to store in the temp file.
extension|A file extension to add to the file.

Create a temporary file and write some data into it. The file will be
removed when the query completes.

## format

Arg | Description
----|------------
format|A format string to use.
args|A list of args to interpolate into the format string.

Format one or more items according to a format string. The format
string is interpreted using [the standard golang fmt
package](https://golang.org/pkg/fmt/).

The function returns a string.

## base64decode

Arg | Description
----|------------
string|A string to decode

Decodes a base64 encoded string.


## ip

Arg | Description
----|------------
netaddr4_le|An IPv4 address as a little endian integer.
netaddr4_be|An IPv4 address as a big endian integer.

Converts an ip address encoded in various ways. If the IP address is
encoded as 32 bit integer we can use netaddr4_le or netaddr4_be to
print it in a human readable way.

This currently does not support IPv6 addresses. Those are usually
encoded as an array of 8 bytes which makes it easy to format using the
`format()` function:

```
  format(format="%x:%x:%x:%x:%x:%x:%x:%x", value)
```

## lowcase

Arg | Description
----|------------
string|A string to decode

Converts a string to lower case.

## upcase

Arg | Description
----|------------
string|A string to decode

Converts a string to upper case

## atoi

Arg | Description
----|------------
string|A string to decode

Converts a string to an integer.

## now

Returns the current time as seconds since the unix epoch.

## utf16

Arg | Description
----|------------
string|A string to decode

Converts a UTF16 encoded string to a normal utf8 string.

## hash

Arg | Description
----|------------
path|A file to hash
accessor|The accessor to use for openning the file.

This function calculates the MD5, SHA1 and SHA256 hashes of the file.

## humanize

Arg | Description
----|------------
bytes|Number of bytes

Formats a byte count in human readable way (e.g. Mb, Gb etc).

## array

This function accepts arbitrary arguments and creates an array by
flattening the arguments. For example `array(a=1, b=2)` will return
`[1, 2]`.

You can use this to flatten a subquery as well:

```sql
SELECT array(a1={ SELECT User FROM Artifact.Windows.System.Users() }) as Users FROM scope()
```

Will return a single row with Users being an array of names.

## join

Arg | Description
----|------------
array|An array of strings
sep|A separator (by default comma)

Joins the array into a string separated by the sep character.

## filter

Arg | Description
----|------------
array|An array of strings
regex|A regular expression to apply to the array

Returns another array filtered by the regular expression.

## getpid

Returns Velociraptor's own pid.

## url

Arg | Description
----|------------
scheme|The scheme to use
host|The host component
path|The path component
fragment|The fragment component
parse|A url to parse

This function parses or constructs URLs. A URL may be constructed from
scratch by providing all the components or it may be parsed from an
existing URL.

The returned object is a [golang
URL](https://golang.org/pkg/net/url/#URL) and can be serialized again
using its `String` method.

This function is important when constructing parameters for certain
accessors which receive a URL. For exampel the `zip` accessor requires
its file names to consist of URLs. The Zip accessor interprets the URL
in the following way:

- The scheme is the delegate accessor to use.
- The path is the delegate accessor's filename
- The fragment is used by the zip accessor to retrieve the zip member itself.

In this case it is critical to properly escape each level - it is not
possible in the geenral case to simply append strings. You need to use
the `url()` function to build the proper url.


## upload

Arg | Description
----|------------
file|The file to upload
name|The name it should be uploaded under
accessor|An accessor to use.

This function uploads the specified file to the server. If Velociraptor
is run locally the file will be copied tothe `--dump_dir` path or
added to the triage evidence container.

## expand

Arg | Description
----|------------
path|A path string to expand.

This function expands environment variables into the path. It is
normally needed after using registry values of type REG_EXPAND_SZ as
they typically contain environment strings. Velociraptor does not
automatically expand such values since environment variables typically
depend on the specific user account which reads the registry value
(different user accounts can have different environment variables).
