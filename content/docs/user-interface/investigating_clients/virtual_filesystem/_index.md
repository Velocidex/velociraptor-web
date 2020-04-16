---
title: The Virtual File System
linktitle: Client VFS
weight: 40
---

If we had to investigate a machine interactively we would probably
start off by using Windows Explorer or a similar tool to navigate the
endpoint's filesystem directly. It is convenient and intuitive!

Velociraptor provides a similar feature - the client's Virtual File
System. This feature mirrors some of the endpoint's files and
directories on the endpoint on the server and allows user to navigate
through those interactively.

After searching for a client, and selecting it you will see the option
`Virtual Filesystem` available in the side navigation bar.

![VFS](../vfs_view.png)


The interface is divided into three main parts:

1. The left side shows a tree view of the `Virtual File System` and its directories.
2. The top pane shows the file listings contained within each directory.
3. The bottom pane shows information about files selected in the file listing pane.


## File operations

Selecting a directory in the tree view will populate the file listing
pane with cached information stored on the server's. You can see the
time when that listing was actually taken from the endpoint at the top
of the table.

![VFS](../file_actions.png)


Since we can only show the information we have cached on the server,
we may not have data for a directory on the end point we have never
navigated to previously.

To refresh the server's cache you can click the "Refresh this
directory" button. This will schedule a directory listing on the
client and refresh the server's cache.

It is also possible to refresh directories recursively by clicking the
"Recursively Refresh directory" button.

{{% notice warning %}}

It may be tempting to just recursively refresh the entire endpoint's
filesystem but can take a long time and download a lot of
data. Nevertheless it may be convenient sometimes. Note that queries
have a 10 minute timeout by default so it may not completely cover the
entire filesystem in this time either.

{{% /notice %}}


## Downloading files

Sometimes we can see a file in the file listing pane and want to view
it. Since the GUI only shows information cached on the server, the
file contents are not immediately available to us.

Clicking on the "Collect From Client" button will schedule a file
collection from the endpoint (if the client is currently connected the
file will be download immediately).

![Download](../download_file.png)

You may now download the file to your computer by clicking the
download button. Alternately you can view a hexdump or text dump of
the file using the relevant tabs.

![HexView](../hexview.png)


## Filesystem Accessors

Many VQL plugins operate on files. However how we read files on the
endpoint can vary - depending on what we actually mean by file. For
example, Velociraptor is able to read files parsed from the NTFS
parser, compressed files within Zip archives, or even files downloaded
from a URL. VQL specifies the way a file is read via an `accessor`
(essentially a file access driver).

The `Virtual File System` make a number of common accessors available
for navigation, by specifying them at the top level of the tree view:

1. The `file` accessor uses the normal OS filesystem APIs to access
   files and directories.

       * The limitations with this method is that some files are
         locked if they are in use and we are not able to read
         them. For example, the registry hives or the page file.

2. The `ntfs` accessor uses Velociraptor's built in NTFS parser to
   extract directory information and file contents.

       * This bypasses the normal file locking mechanism and allows us
         to download and read locked files like registry hives.

3. The `registry` accessor uses the OS APIs to view the registry as a
   filesystem. You can use this to navigate the endpoint's registry
   hives interactively.

       * Since registry values are typically small, Velociraptor also
         gets the values in the directory listing as well, so it is
         not usually necessary to download files from the registry
         hive.


## Automation

While it is intuitive to interactively examine an endpoint using the
`Virtual File System` we typically need something a bit more
automated.

Velociraptor uses `Artifacts` to encapsulate and automate endpoint
analysis. You can read more about [Client Artifacts]({{< ref "/docs/user-interface/artifacts/client_artifacts" >}}).
