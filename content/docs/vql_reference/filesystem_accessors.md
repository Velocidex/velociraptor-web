---
title: Filesystem Accessors
weight: 80
---

## Filesystem Accessors

Many VQL plugins operate on files. However how we read files on the
endpoint can vary - depending on what we actually mean by a file. For
example, Velociraptor is able to read files parsed from the NTFS
parser, compressed files within Zip archives, or even files downloaded
from a URL. VQL specifies the way a file is read via an `accessor`
(essentially a file access driver), and a `path` which encodes how the
accessor will actually access the file.


## Simple filesystem accessors

### The file accessor

The `file` accessor uses the normal OS filesystem APIs to access files
and directories.

The limitations with this method is that some files are locked if they
are in use and we are not able to read them. For example, the registry
hives or the page file.

The path parameter is passed directly to the filesystem
APIs. Velociraptor supports both forward and reverse slashes on all
supported operating systems.

{{% notice note %}}

   On windows, Velociraptor emulates the top level directory as a list
   of available drives. For example, listing the "/" directory will
   yield directories such as "C:", "D:" etc. Therefore Velociraptor
   paths always have a / at the top level, typically followed by a
   drive letter then the rest of the path.

{{% /notice %}}

### The ntfs accessor

The `ntfs` accessor uses Velociraptor's built in NTFS parser to
extract directory information and file contents.

This bypasses the normal file locking mechanism and allows us to
download and read locked files like registry hives.

The path is interpreted as a raw device, followed by an NTFS path. For
example the path `\\.\c:\Windows\System32` refers to the System32
directory as parsed by the ntfs parser from the raw device
`\\.\c:`. Supported raw devices include volume shadow copies (VSC) as
well.

As a convenience, the ntfs accessor recognizes a drive letter and
automatically maps it to the raw device. I.e. the following paths are
equivalent `\\.\c:\Windows` and `C:\Windows`.

Listing the top level directory will display all physical drives and
Volume Shadow Copies available on the machine.

{{% notice note %}}

The backslash character is considered the path separator only for
paths following the device name. Supported device names include the
backslash as part of their name. For example, listing the top level
directory will show `\\.\c:` as a single device, even though it
contains backslashes.

{{% /notice %}}

### The registry accessor

The `registry` accessor uses the OS APIs to view the registry as a
filesystem. You can use this to navigate the endpoint's registry hives
interactively.

Since registry values are typically small, Velociraptor also gets the
values in the directory listing as well, so it is not usually
necessary to download files from the registry hive.

{{% notice note %}}

The Windows registry differs from a regular filesystem in that Key names may have forward slash, and value names may contain both forward and backward slashes. Therefore it is difficult to properly split a path into the correct key and value. Velociraptor treats a path as a list of components. Velociraptor will surround component names with quotes if they contain slashes to allow the path to be broken back into components. For example, `HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Word\Security\Trusted Documents\TrustRecords\"%USERPROFILE%/Desktop/test.docx"` represents the value named `%USERPROFILE%/Desktop/test.docx`.

{{% /notice %}}

## Other filesystem accessors

### The data accessor

Sometimes it is necessary to pass a string to a plugin which expects a
filename (for example `yara()` plugin. In this case it is possible to
specify the `data` accessor which creates an in memory file from the
filename path passed to it.

### The zip accessor

Zip files contain compressed members. It is sometimes useful to be
able to treat members of the zip archive as simple files, then we can
scan or list them using other plugins.

The `zip` accessor makes that possible. However the accessor requires
an underlying file to actually unzip. Therefore the `zip` accessor
requires a url:

* The scheme part is used to specify the underlying accessor to access
  the zip file.

* The path part is used to specify the path to pass to the underlying
  accessor.

* The fragment part is used to specify the path within the zip file to
  access.

{{% notice tip %}}

Do not attempt to construct the url by manually concatenating parts
because this does not properly handle escaping. Instead use the
`url()` function. For example `url(scheme='ntfs',
path="C:/Users/Test/my.zip", fragment="1.txt").String` will produce
the required url: `ntfs://C:/Users/Test/my.zip#1.txt` to access the
file 1.txt within the my.zip file as extracted by the ntfs raw parser.

{{% /notice %}}


### The raw_reg accessor

Parsing of raw registry hives is provided by the `raw_reg`
accessor. Similarly to the zip accessor above, the `raw_reg` accessor
requires an underlying file to read. Therefore it also requires a path
formatted as a url:

* The scheme part is used to specify the underlying accessor to access
  the raw registry hive file.

* The path part is used to specify the path to pass to the underlying
  accessor.

* The fragment part is used to specify the key or value within the
   registry hive to access.

Note that this accessor usually requires an underlying file that is
accessed by the raw NTFS parser (since registry hives are locked at
runtime).
