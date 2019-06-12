---
description: Various Artifacts which do not fit into other categories.
linktitle: Miscelaneous
menu:
  docs: {parent: Artifacts, weight: 30}
title: Miscelaneous Artifacts
toc: true

---
## Admin.Client.Upgrade

Remotely push new client updates.

NOTE: The updates can be pulled from any web server. You need to
ensure they are properly secured with SSL and at least a random
nonce in their path. You may configure the Velociraptor server to
serve these through the public directory.


Arg|Default|Description
---|------|-----------
clientURL|http://127.0.0.1:8000/public/velociraptor.exe|
configURL|http://127.0.0.1:8000/public/client.config.yaml|


{{% expand  "View Artifact Source" %}}

```
name: Admin.Client.Upgrade
description: |
  Remotely push new client updates.

  NOTE: The updates can be pulled from any web server. You need to
  ensure they are properly secured with SSL and at least a random
  nonce in their path. You may configure the Velociraptor server to
  serve these through the public directory.

parameters:
  - name: clientURL
    default: http://127.0.0.1:8000/public/velociraptor.exe
  - name: configURL
    default: http://127.0.0.1:8000/public/client.config.yaml

sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'
    queries:
      - |
        /* This query fetches the binary and config and stores them in
         temp files. Note that tempfiles will be automatically
         cleaned at query end.
         */
        LET tmpfiles <= SELECT tempfile(
           data=query(vql={
             SELECT Content
             FROM http_client(url=clientURL, chunk_size=30000000)
           }),
           extension=".exe") as Binary,
        tempfile(
           data=query(vql={
             SELECT Content
             FROM http_client(url=configURL)
           })) as Config from scope()

      - |
        // Run the installer.
        SELECT * from foreach(
         row=tmpfiles,
         query={
            SELECT * from execve(
               argv=[Binary, "--config", Config, "-v", "service", "install"]
            )
         })
```

{{% /expand %}}


## Admin.Events.PostProcessUploads

Sometimes we would like to post process uploads collected as part of
the hunt's artifact collections

Post processing means to watch the hunt for completed flows and run
a post processing command on the files obtained from each host.

The command will receive the list of paths of the files uploaded by
the artifact. We dont actually care what the command does with those
files - we will just relay our stdout/stderr to the artifact's
result set.


Arg|Default|Description
---|------|-----------
uploadPostProcessCommand|["/bin/ls", "-l"]\n|The command to run - must be a json array of strings! The list of files will be appended to the end of the command.\n
uploadPostProcessArtifact|Windows.Registry.NTUser.Upload|The name of the artifact to watch.\n


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Admin_Events_PostProcessUploadsDetails">View Artifact</a>
 <div class="collapse dn" id="Admin_Events_PostProcessUploadsDetails" style="width: fit-content">


```
name: Admin.Events.PostProcessUploads
description: |
  Sometimes we would like to post process uploads collected as part of
  the hunt's artifact collections

  Post processing means to watch the hunt for completed flows and run
  a post processing command on the files obtained from each host.

  The command will receive the list of paths of the files uploaded by
  the artifact. We dont actually care what the command does with those
  files - we will just relay our stdout/stderr to the artifact's
  result set.

type: SERVER_EVENT

parameters:
  - name: uploadPostProcessCommand
    description: |
      The command to run - must be a json array of strings! The list
      of files will be appended to the end of the command.
    default: |
      ["/bin/ls", "-l"]

  - name: uploadPostProcessArtifact
    description: |
      The name of the artifact to watch.
    default: Windows.Registry.NTUser.Upload

sources:
  - precondition:
      SELECT server_config FROM scope()
    queries:
      - |
        LET files = SELECT Flow,
            array(a1=parse_json_array(data=uploadPostProcessCommand),
                  a2=file_store(path=Flow.FlowContext.uploaded_files)) as Argv
        FROM watch_monitoring(artifact='System.Flow.Completion')
        WHERE uploadPostProcessArtifact in Flow.FlowContext.artifacts

      - |
        SELECT * from foreach(
          row=files,
          query={
             SELECT Flow.Urn as FlowUrn, Argv,
                    Stdout, Stderr, ReturnCode
             FROM execve(argv=Argv)
          })
```
   </div></a>

## Admin.System.CompressUploads

Compresses all uploaded files.

When artifacts collect files they are normally stored on the server
uncompressed. This artifact watches all completed flows and
compresses the files in the file store when the flow completes. This
is very useful for cloud based deployments with limited storage
space or when collecting large files.

In order to run this artifact you would normally run it as part of
an artifact acquisition process:

```
$ velociraptor --config /etc/server.config.yaml artifacts acquire Admin.System.CompressUploads
```

Note that there is nothing special about compressed files - you can
also just run `find` and `gzip` in the file store. Velociraptor will
automatically decompress the file when displaying it in the GUI
text/hexdump etc.


Arg|Default|Description
---|------|-----------
blacklistCompressionFilename|(?i).+ntuser.dat|Filenames which match this regex will be excluded from compression.


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Admin_System_CompressUploadsDetails">View Artifact</a>
 <div class="collapse dn" id="Admin_System_CompressUploadsDetails" style="width: fit-content">


```
name: Admin.System.CompressUploads
description: |
  Compresses all uploaded files.

  When artifacts collect files they are normally stored on the server
  uncompressed. This artifact watches all completed flows and
  compresses the files in the file store when the flow completes. This
  is very useful for cloud based deployments with limited storage
  space or when collecting large files.

  In order to run this artifact you would normally run it as part of
  an artifact acquisition process:

  ```
  $ velociraptor --config /etc/server.config.yaml artifacts acquire Admin.System.CompressUploads
  ```

  Note that there is nothing special about compressed files - you can
  also just run `find` and `gzip` in the file store. Velociraptor will
  automatically decompress the file when displaying it in the GUI
  text/hexdump etc.

type: SERVER_EVENT

parameters:
  - name: blacklistCompressionFilename
    description: Filenames which match this regex will be excluded from compression.
    default: '(?i).+ntuser.dat'

sources:
  - precondition:
      SELECT server_config FROM scope()
    queries:
      - |
        LET files = SELECT ClientId,
            Flow.Urn as Flow,
            Flow.FlowContext.uploaded_files as Files
        FROM watch_monitoring(artifact='System.Flow.Completion')
        WHERE Files and not Files =~ blacklistCompressionFilename

      - |
        SELECT ClientId, Flow, Files,
               compress(path=Files) as CompressedFiles
        FROM files
```
   </div></a>

## Demo.Plugins.Fifo

This is a demo of the fifo() plugin. The Fifo plugin collects and
caches rows from its inner query. Every subsequent execution of the
query then reads from the cache. The plugin will expire old rows
depending on its expiration policy - so we always see recent rows.

You can use this to build queries which consider historical events
together with current events at the same time. In this example, we
check for a successful logon preceeded by a number of failed logon
attempts.

In this example, we use the clock() plugin to simulate events. We
simulate failed logon attempts using the clock() plugin every
second. By feeding the failed logon events to the fifo() plugin we
ensure the fifo() plugin cache contains the last 5 failed logon
events.

We simulate a successful logon event every 3 seconds, again using
the clock plugin. Once a successful logon event is detected, we go
back over the last 5 login events, count them and collect the last
failed logon times (using the GROUP BY operator we group the
FailedTime for every unique SuccessTime).

If we receive more than 3 events, we emit the row.

This now represents a high value signal! It will only occur when a
successful logon event is preceeded by at least 3 failed logon
events in the last hour. It is now possible to escalate this on the
server via email or other alerts.

Here is sample output:

.. code-block:: json

    {
      "Count": 5,
      "FailedTime": [
        1549527272,
        1549527273,
        1549527274,
        1549527275,
        1549527276
      ],
      "SuccessTime": 1549527277
    }

Of course in the real artifact we would want to include more
information than just times (i.e. who logged on to where etc).



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Demo_Plugins_FifoDetails">View Artifact</a>
 <div class="collapse dn" id="Demo_Plugins_FifoDetails" style="width: fit-content">


```
name: Demo.Plugins.Fifo
description: |
  This is a demo of the fifo() plugin. The Fifo plugin collects and
  caches rows from its inner query. Every subsequent execution of the
  query then reads from the cache. The plugin will expire old rows
  depending on its expiration policy - so we always see recent rows.

  You can use this to build queries which consider historical events
  together with current events at the same time. In this example, we
  check for a successful logon preceeded by a number of failed logon
  attempts.

  In this example, we use the clock() plugin to simulate events. We
  simulate failed logon attempts using the clock() plugin every
  second. By feeding the failed logon events to the fifo() plugin we
  ensure the fifo() plugin cache contains the last 5 failed logon
  events.

  We simulate a successful logon event every 3 seconds, again using
  the clock plugin. Once a successful logon event is detected, we go
  back over the last 5 login events, count them and collect the last
  failed logon times (using the GROUP BY operator we group the
  FailedTime for every unique SuccessTime).

  If we receive more than 3 events, we emit the row.

  This now represents a high value signal! It will only occur when a
  successful logon event is preceeded by at least 3 failed logon
  events in the last hour. It is now possible to escalate this on the
  server via email or other alerts.

  Here is sample output:

  .. code-block:: json

      {
        "Count": 5,
        "FailedTime": [
          1549527272,
          1549527273,
          1549527274,
          1549527275,
          1549527276
        ],
        "SuccessTime": 1549527277
      }

  Of course in the real artifact we would want to include more
  information than just times (i.e. who logged on to where etc).
type: EVENT

sources:
  - queries:
      # This query simulates failed logon attempts.
      - LET failed_logon = SELECT Unix as FailedTime from clock(period=1)

      # This is the fifo which holds the last 5 failed logon attempts
      # within the last hour.
      - LET last_5_events = SELECT FailedTime
            FROM fifo(query=failed_logon, max_rows=5, max_age=3600)

      # We need to get it started collecting data immediately by
      # materializing the cache contents. Otherwise the fifo wont
      # start until it is first called (i.e. the first successful
      # login and we will miss the failed events before hand).
      - LET foo <= SELECT * FROM last_5_events

      # This simulates successful logon - we assume every 3 seonds.
      - LET success_logon = SELECT Unix as SuccessTime from clock(period=3)

      # For each successful logon, query the last failed logon
      # attempts from the fifo(). We also count the total number of
      # failed logons. We only actually emit results if there are more
      # than 3 failed logon attempts before each successful one.
      - |
        SELECT * FROM foreach(
          row=success_logon,
          query={
           SELECT SuccessTime,
              enumerate(items=FailedTime) as FailedTime,
              count(items=FailedTime) as Count
           FROM last_5_events GROUP BY SuccessTime
          }) WHERE Count > 3
```
   </div></a>

## Generic.Applications.Office.Keywords

Microsoft Office documents among other document format (such as
LibraOffice) are actually stored in zip files. The zip file contain
the document encoded as XML in a number of zip members.

This makes it difficult to search for keywords within office
documents because the ZIP files are typically compressed.

This artifact searches for office documents by file extension and
glob then uses the zip filesystem accessor to launch a yara scan
again the uncompressed data of the document. Keywords are more
likely to match when scanning the decompressed XML data.

The artifact returns a context around the keyword hit.

NOTE: The InternalMtime column shows the creation time of the zip
member within the document which may represent when the document was
initially created.

See
https://en.wikipedia.org/wiki/List_of_Microsoft_Office_filename_extensions
https://wiki.openoffice.org/wiki/Documentation/OOo3_User_Guides/Getting_Started/File_formats


Arg|Default|Description
---|------|-----------
documentGlobs|/*.{docx,docm,dotx,dotm,docb,xlsx,xlsm,xltx,xltm,pptx,pptm,potx,potm,ppam,ppsx,ppsm,sldx,sldm,odt,ott,oth,odm}|
searchGlob|C:\\Users\\**|
yaraRule|rule Hit {\n  strings:\n    $a = "secret" wide nocase\n    $b = "secret" nocase\n\n  condition:\n    any of them\n}\n|


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Generic_Applications_Office_KeywordsDetails">View Artifact</a>
 <div class="collapse dn" id="Generic_Applications_Office_KeywordsDetails" style="width: fit-content">


```
name: Generic.Applications.Office.Keywords
description: |
  Microsoft Office documents among other document format (such as
  LibraOffice) are actually stored in zip files. The zip file contain
  the document encoded as XML in a number of zip members.

  This makes it difficult to search for keywords within office
  documents because the ZIP files are typically compressed.

  This artifact searches for office documents by file extension and
  glob then uses the zip filesystem accessor to launch a yara scan
  again the uncompressed data of the document. Keywords are more
  likely to match when scanning the decompressed XML data.

  The artifact returns a context around the keyword hit.

  NOTE: The InternalMtime column shows the creation time of the zip
  member within the document which may represent when the document was
  initially created.

  See
  https://en.wikipedia.org/wiki/List_of_Microsoft_Office_filename_extensions
  https://wiki.openoffice.org/wiki/Documentation/OOo3_User_Guides/Getting_Started/File_formats

parameters:
  - name: documentGlobs
    default: /*.{docx,docm,dotx,dotm,docb,xlsx,xlsm,xltx,xltm,pptx,pptm,potx,potm,ppam,ppsx,ppsm,sldx,sldm,odt,ott,oth,odm}
  - name: searchGlob
    default: C:\Users\**
  - name: yaraRule
    default: |
      rule Hit {
        strings:
          $a = "secret" wide nocase
          $b = "secret" nocase

        condition:
          any of them
      }

sources:
  - queries:
      - LET office_docs = SELECT FullPath AS OfficePath,
             timestamp(epoch=Mtime.Sec) as OfficeMtime,
             Size as OfficeSize
          FROM glob(globs=searchGlob + documentGlobs)

      # A list of zip members inside the doc that have some content.
      - LET document_parts = SELECT OfficePath,
             FullPath AS ZipMemberPath
          FROM glob(globs=url(
             scheme="file", path=OfficePath, fragment="/**").String,
             accessor='zip')
          WHERE not IsDir and Size > 0

      # For each document, scan all its parts for the keyword.
      - SELECT OfficePath,
               OfficeMtime,
               OfficeSize,
               File.ModTime as InternalMtime,
               Strings.HexData as HexContext
         FROM foreach(
           row=office_docs,
           query={
              SELECT File, Strings, OfficePath,
                     OfficeMtime, OfficeSize
              FROM yara(
                 rules=yaraRule,
                 files=document_parts.ZipMemberPath,
                 context=200,
                 accessor='zip')
         })
```
   </div></a>

## Generic.Client.Stats

An Event artifact which generates client's CPU and memory statistics.

Arg|Default|Description
---|------|-----------
Frequency|10|Return stats every this many seconds.


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Generic_Client_StatsDetails">View Artifact</a>
 <div class="collapse dn" id="Generic_Client_StatsDetails" style="width: fit-content">


```
name: Generic.Client.Stats
description: An Event artifact which generates client's CPU and memory statistics.
parameters:
  - name: Frequency
    description: Return stats every this many seconds.
    default: "10"
type: EVENT

sources:
  - queries:
      - |
        SELECT * from foreach(
         row={
           SELECT UnixNano FROM clock(period=atoi(string=Frequency))
         },
         query={
           SELECT UnixNano / 1000000000 as Timestamp,
                  Times.user + Times.system as CPU,
                  MemoryInfo.RSS as RSS
           FROM pslist(pid=getpid())
         })
```
   </div></a>

## Generic.Forensic.Timeline

This artifact generates a timeline of a file glob in bodyfile
format. We currently do not calculate the md5 because it is quite
expensive.


Arg|Default|Description
---|------|-----------
timelineGlob|C:\\Users\\**|
timelineAccessor|file|


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Generic_Forensic_TimelineDetails">View Artifact</a>
 <div class="collapse dn" id="Generic_Forensic_TimelineDetails" style="width: fit-content">


```
name: Generic.Forensic.Timeline
description: |
  This artifact generates a timeline of a file glob in bodyfile
  format. We currently do not calculate the md5 because it is quite
  expensive.

parameters:
  - name: timelineGlob
    default: C:\Users\**
  - name: timelineAccessor
    default: file

sources:
  # For NTFS accessors we write the MFT id as the inode. On windows
  # the file accessor does not give the inode at all.
  - precondition:
      SELECT OS From info() where OS = 'windows' AND timelineAccessor = 'ntfs'
    queries:
      - |
        SELECT 0 AS Md5, FullPath,
               Sys.mft as Inode,
               Mode.String AS Mode, 0 as Uid, 0 as Gid, Size,
               Atime.Sec AS Atime, Mtime.Sec AS Mtime, Ctime.Sec AS Ctime
        FROM glob(globs=timelineGlob, accessor=timelineAccessor)

  # For linux we can get the Inode from Sys.Ino
  - precondition:
      SELECT * From scope() where timelineAccessor = 'file'
    queries:
      - |
        SELECT 0 AS Md5, FullPath,
               Sys.Ino as Inode,
               Mode.String AS Mode, Sys.Uid AS Uid, Sys.Gid AS Gid, Size,
               Atime.Sec AS Atime, Mtime.Sec AS Mtime, Ctime.Sec AS Ctime
        FROM glob(globs=timelineGlob, accessor=timelineAccessor)
```
   </div></a>

## Network.ExternalIpAddress

Detect the external ip address of the end point.

Arg|Default|Description
---|------|-----------
externalUrl|http://www.myexternalip.com/raw|The URL of the external IP detection site.


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Network_ExternalIpAddressDetails">View Artifact</a>
 <div class="collapse dn" id="Network_ExternalIpAddressDetails" style="width: fit-content">


```
name: Network.ExternalIpAddress
description: Detect the external ip address of the end point.
parameters:
  - name: externalUrl
    default: http://www.myexternalip.com/raw
    description: The URL of the external IP detection site.
sources:
  - precondition: SELECT * from info()
    queries:
      - SELECT Content as IP from http_client(url=externalUrl)
```
   </div></a>

## Reporting.Hunts.Details

Report details about which client ran each hunt, how long it took
and if it has completed.



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Reporting_Hunts_DetailsDetails">View Artifact</a>
 <div class="collapse dn" id="Reporting_Hunts_DetailsDetails" style="width: fit-content">


```
name: Reporting.Hunts.Details
description: |
  Report details about which client ran each hunt, how long it took
  and if it has completed.

sources:
  - precondition:
      SELECT server_config FROM scope()

    queries:
      - |
        LET hunts = SELECT basename(path=hunt_id) as hunt_id,
            create_time,
            hunt_description
        FROM hunts() order by create_time desc limit 6
      - |
        LET flows = select hunt_id,
          hunt_description,
          Fqdn,
          ClientId,
          { SELECT os_info.system FROM clients(search=ClientId) } as OS,
          timestamp(epoch=Flow.FlowContext.create_time/1000000) as create_time,
          basename(path=Flow.Urn) as flow_id,
          (Flow.FlowContext.active_time - Flow.FlowContext.create_time) / 1000000 as Duration,
          format(format='%v', args=[Flow.FlowContext.state]) as State
        FROM hunt_flows(hunt_id=hunt_id) order by create_time desc
      - |
        SELECT * from foreach(row=hunts, query=flows)
```
   </div></a>

## Windows.Applications.ChocolateyPackages

Chocolatey packages installed in a system.

Arg|Default|Description
---|------|-----------
ChocolateyInstall||


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Applications_ChocolateyPackagesDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Applications_ChocolateyPackagesDetails" style="width: fit-content">


```
name: Windows.Applications.ChocolateyPackages
description: Chocolatey packages installed in a system.
parameters:
  - name: ChocolateyInstall
    default: ""

sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'
    queries:
      - |
        LET files =
          SELECT FullPath, parse_xml(file=FullPath) AS Metadata
          -- Use the ChocolateyInstall parameter if it is set.
          FROM glob(globs=if(
             condition=ChocolateyInstall,
             then=ChocolateyInstall,
             -- Otherwise just use the environment.
             else=environ(var='ChocolateyInstall')) + '/lib/*/*.nuspec')
      - |
        SELECT * FROM if(
        condition={
            SELECT * FROM if(
               condition=ChocolateyInstall,
               then=ChocolateyInstall,
               else=environ(var="ChocolateyInstall"))
          },
        then={
            SELECT FullPath,
                   Metadata.package.metadata.id as Name,
                   Metadata.package.metadata.version as Version,
                   Metadata.package.metadata.summary as Summary,
                   Metadata.package.metadata.authors as Authors,
                   Metadata.package.metadata.licenseUrl as License
            FROM files
        })
```
   </div></a>

## Windows.Applications.Chrome.Extensions

Fetch Chrome extensions.

Chrome extensions are installed into the user's home directory.  We
search for manifest.json files in a known path within each system
user's home directory. We then parse the manifest file as JSON.

Many extensions use locale packs to resolve strings like name and
description. In this case we detect the default locale and load
those locale files. We then resolve the extension's name and
description from there.


Arg|Default|Description
---|------|-----------
extensionGlobs|\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Extensions\\*\\*\\manifest.json|


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Applications_Chrome_ExtensionsDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Applications_Chrome_ExtensionsDetails" style="width: fit-content">


```
name: Windows.Applications.Chrome.Extensions
description: |
  Fetch Chrome extensions.

  Chrome extensions are installed into the user's home directory.  We
  search for manifest.json files in a known path within each system
  user's home directory. We then parse the manifest file as JSON.

  Many extensions use locale packs to resolve strings like name and
  description. In this case we detect the default locale and load
  those locale files. We then resolve the extension's name and
  description from there.

parameters:
  - name: extensionGlobs
    default: \AppData\Local\Google\Chrome\User Data\*\Extensions\*\*\manifest.json
sources:
  - precondition: |
      SELECT OS From info() where OS = 'windows'
    queries:
      - |
        /* For each user on the system, search for extension manifests
           in their home directory. */
        LET extension_manifests = SELECT * from foreach(
          row={
             SELECT Uid, Name AS User, Directory from Artifact.Windows.Sys.Users()
          },
          query={
             SELECT FullPath, Mtime, Ctime, User, Uid from glob(
               globs=Directory + extensionGlobs)
          })

      - |
        /* If the Manifest declares a default_locale then we
           load and parse the messages file. In this case the
           messages are actually stored in the locale file
           instead of the main manifest.json file.
        */
        LET maybe_read_locale_file =
           SELECT * from if(
              condition={
                 select * from scope() where Manifest.default_locale
              },
              then={
                 SELECT Manifest,
                        Uid, User,
                        Filename as LocaleFilename,
                        ManifestFilename,
                        parse_json(data=Data) AS LocaleManifest
                 FROM read_file(
                         -- Munge the filename to get the messages.json path.
                         filenames=regex_replace(
                           source=ManifestFilename,
                           replace="\\_locales\\" + Manifest.default_locale +
                                   "\\messages.json",
                           re="\\\\manifest.json$"))
              },
              else={
                  -- Just fill in empty Locale results.
                  SELECT Manifest,
                         Uid, User,
                         "" AS LocaleFilename,
                         "" AS ManifestFilename,
                         "" AS LocaleManifest
                  FROM scope()
              })

      - |
        LET parse_json_files = SELECT * from foreach(
           row={
             SELECT Filename as ManifestFilename,
                    Uid, User,
                    parse_json(data=Data) as Manifest
             FROM read_file(filenames=FullPath)
           },
           query=maybe_read_locale_file)

      - |
        LET parsed_manifest_files = SELECT * from foreach(
          row=extension_manifests,
          query=parse_json_files)

      - |
        SELECT Uid, User,

               /* If the manifest name contains __MSG_ then the real
                  name is stored in the locale manifest. This condition
                  resolves the Name column either to the main manifest or
                  the locale manifest.
               */
               if(condition="__MSG_" in Manifest.name,
                  then=get(item=LocaleManifest,
                     member=regex_replace(
                        source=Manifest.name,
                        replace="$1",
                        re="(?:__MSG_(.+)__)")).message,
                  else=Manifest.name) as Name,

               if(condition="__MSG_" in Manifest.description,
                  then=get(item=LocaleManifest,
                     member=regex_replace(
                        source=Manifest.description,
                        replace="$1",
                        re="(?:__MSG_(.+)__)")).message,
                  else=Manifest.description) as Description,

               /* Get the Identifier and Version from the manifest filename */
               regex_replace(
                 source=ManifestFilename,
                 replace="$1",
                 re="(?:.+Extensions\\\\([^\\\\]+)\\\\([^\\\\]+)\\\\manifest.json)$") AS Identifier,
               regex_replace(
                 source=ManifestFilename,
                 replace="$2",
                 re="(?:.+Extensions\\\\([^\\\\]+)\\\\([^\\\\]+)\\\\manifest.json)$") AS Version,

               Manifest.author as Author,
               Manifest.background.persistent AS Persistent,
               regex_replace(
                 source=ManifestFilename,
                 replace="$1",
                 re="(.+Extensions\\\\.+\\\\)manifest.json$") AS Path,

               Manifest.oauth2.scopes as Scopes,
               Manifest.permissions as Permissions,
               Manifest.key as Key

        FROM parsed_manifest_files
```
   </div></a>

## Windows.Applications.OfficeMacros

Office macros are a favourite initial infection vector. Many users
click through the warning dialogs.

This artifact scans through the given directory glob for common
office files. We then try to extract any embedded macros by parsing
the OLE file structure.

If a macro calls an external program (e.g. Powershell) this is very
suspicious!


Arg|Default|Description
---|------|-----------
officeExtensions|*.{xls,xlsm,doc,docx,ppt,pptm}|
officeFileSearchGlob|C:\\Users\\**\\|The directory to search for office documents.


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Applications_OfficeMacrosDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Applications_OfficeMacrosDetails" style="width: fit-content">


```
name: Windows.Applications.OfficeMacros
description: |
  Office macros are a favourite initial infection vector. Many users
  click through the warning dialogs.

  This artifact scans through the given directory glob for common
  office files. We then try to extract any embedded macros by parsing
  the OLE file structure.

  If a macro calls an external program (e.g. Powershell) this is very
  suspicious!

parameters:
  - name: officeExtensions
    default: "*.{xls,xlsm,doc,docx,ppt,pptm}"
  - name: officeFileSearchGlob
    default: C:\Users\**\
    description: The directory to search for office documents.

sources:
  - queries:
      - |
        SELECT * FROM foreach(
           row={
              SELECT FullPath FROM glob(globs=officeFileSearchGlob + officeExtensions)
           },
           query={
               SELECT * from olevba(file=FullPath)
           })
```
   </div></a>

## Windows.Network.ArpCache

Address resolution cache, both static and dynamic (from ARP, NDP).

Arg|Default|Description
---|------|-----------
wmiQuery|SELECT AddressFamily, Store, State, InterfaceIndex, IPAddress,\n       InterfaceAlias, LinkLayerAddress\nfrom MSFT_NetNeighbor\n|
wmiNamespace|ROOT\\StandardCimv2|
kMapOfState|{\n "0": "Unreachable",\n "1": "Incomplete",\n "2": "Probe",\n "3": "Delay",\n "4": "Stale",\n "5": "Reachable",\n "6": "Permanent",\n "7": "TBD"\n}\n|


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Network_ArpCacheDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Network_ArpCacheDetails" style="width: fit-content">


```
name: Windows.Network.ArpCache
description: Address resolution cache, both static and dynamic (from ARP, NDP).
parameters:
  - name: wmiQuery
    default: |
      SELECT AddressFamily, Store, State, InterfaceIndex, IPAddress,
             InterfaceAlias, LinkLayerAddress
      from MSFT_NetNeighbor
  - name: wmiNamespace
    default: ROOT\StandardCimv2

  - name: kMapOfState
    default: |
     {
      "0": "Unreachable",
      "1": "Incomplete",
      "2": "Probe",
      "3": "Delay",
      "4": "Stale",
      "5": "Reachable",
      "6": "Permanent",
      "7": "TBD"
     }

sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'
    queries:
      - |
        LET interfaces <=
          SELECT Index, HardwareAddr, IP
          FROM Artifact.Windows.Network.InterfaceAddresses()

      - |
        LET arp_cache = SELECT if(condition=AddressFamily=23,
                    then="IPv6",
                  else=if(condition=AddressFamily=2,
                    then="IPv4",
                  else=AddressFamily)) as AddressFamily,

               if(condition=Store=0,
                    then="Persistent",
                  else=if(condition=(Store=1),
                    then="Active",
                  else="?")) as Store,

               get(item=parse_json(data=kMapOfState),
                   member=encode(string=State, type='string')) AS State,
               InterfaceIndex, IPAddress,
               InterfaceAlias, LinkLayerAddress
            FROM wmi(query=wmiQuery, namespace=wmiNamespace)
      - |
        SELECT * FROM foreach(
          row=arp_cache,
          query={
             SELECT AddressFamily, Store, State, InterfaceIndex,
                    IP AS LocalAddress, HardwareAddr, IPAddress as RemoteAddress,
                    InterfaceAlias, LinkLayerAddress AS RemoteMACAddress
             FROM interfaces
             WHERE InterfaceIndex = Index
          })
```
   </div></a>

## Windows.Network.InterfaceAddresses

Network interfaces and relevant metadata.


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Network_InterfaceAddressesDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Network_InterfaceAddressesDetails" style="width: fit-content">


```
name: Windows.Network.InterfaceAddresses
description: Network interfaces and relevant metadata.
sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'
    queries:
      - |
        LET interface_address =
           SELECT Index, MTU, Name, HardwareAddr, Flags, Addrs
           from interfaces()

      - |
        SELECT Index, MTU, Name, HardwareAddr,
           Flags, Addrs.IP as IP, Addrs.Mask as Mask
        FROM flatten(query=interface_address)
```
   </div></a>

## Windows.Network.ListeningPorts

Processes with listening (bound) network sockets/ports.


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Network_ListeningPortsDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Network_ListeningPortsDetails" style="width: fit-content">


```
name: Windows.Network.ListeningPorts
description: Processes with listening (bound) network sockets/ports.
sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'
    queries:
      - |
        LET process <= SELECT Name, Pid from pslist()

      - |
        SELECT * from foreach(
          row={
            SELECT Pid AS PortPid, Laddr.Port AS Port,
                   TypeString as Protocol, FamilyString as Family,
                   Laddr.IP as Address
            FROM netstat() where Status = 'LISTEN'
          },
          query={
            SELECT Pid, Name, Port, Protocol, Family, Address
            FROM process where Pid = PortPid
          })
```
   </div></a>

## Windows.Network.Netstat

Show information about open sockets. On windows the time when the
socket was first bound is also shown.



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Network_NetstatDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Network_NetstatDetails" style="width: fit-content">


```
name: Windows.Network.Netstat
description: |
  Show information about open sockets. On windows the time when the
  socket was first bound is also shown.

sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'
    queries:
      - |
        SELECT Pid, FamilyString as Family,
               TypeString as Type,
               Status,
               Laddr.IP, Laddr.Port,
               Raddr.IP, Raddr.Port,
               Timestamp
               FROM netstat()
```
   </div></a>

## Windows.Packs.Autoexec

Aggregate of executables that will automatically execute on the
target machine. This is an amalgamation of other tables like
services, scheduled_tasks, startup_items and more.



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Packs_AutoexecDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Packs_AutoexecDetails" style="width: fit-content">


```
name: Windows.Packs.Autoexec
description: |
  Aggregate of executables that will automatically execute on the
  target machine. This is an amalgamation of other tables like
  services, scheduled_tasks, startup_items and more.

sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'
    queries:
      - |
        SELECT * from chain(
          q1={
            SELECT Name, Command AS Path, "StartupItems" as Source
            FROM Artifact.Windows.Sys.StartupItems()
          })
```
   </div></a>

## Windows.Packs.Persistence

This artifact pack collects various persistence mechanisms in Windows.



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Packs_PersistenceDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Packs_PersistenceDetails" style="width: fit-content">


```
name: Windows.Packs.Persistence
description: |
  This artifact pack collects various persistence mechanisms in Windows.

precondition:
  SELECT OS from info() where OS = "windows"

sources:
  - name: WMI Event Filters
    description: |
      {{ DocFrom "Windows.Persistence.PermanentWMIEvents" }}

    queries:
      - SELECT * FROM Artifact.Windows.Persistence.PermanentWMIEvents()

  - name: Startup Items
    description: |
      {{ DocFrom "Windows.Sys.StartupItems" }}

    queries:
      - SELECT * FROM Artifact.Windows.Sys.StartupItems()

  - name: Debug Bootstraping
    description: |
      {{ DocFrom "Windows.Persistence.Debug" }}

      If there are any rows in the table below then executing the
      program will also launch the program listed under the Debugger
      column.

      {{ Query "SELECT Program, Debugger FROM Rows" }}

    queries:
      - SELECT * FROM Artifact.Windows.Persistence.Debug()
```
   </div></a>

## Windows.Registry.NTUser.Upload

This artifact collects all the user's NTUser.dat registry hives.

When a user logs into a windows machine the system creates their own
"profile" which consists of a registry hive mapped into the
HKEY_USERS hive. This hive file is locked as long as the user is
logged in.

This artifact bypasses the locking mechanism by extracting the
registry hives using raw NTFS parsing. We then just upload all hives
to the server.



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Registry_NTUser_UploadDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Registry_NTUser_UploadDetails" style="width: fit-content">


```
name: Windows.Registry.NTUser.Upload
description: |
  This artifact collects all the user's NTUser.dat registry hives.

  When a user logs into a windows machine the system creates their own
  "profile" which consists of a registry hive mapped into the
  HKEY_USERS hive. This hive file is locked as long as the user is
  logged in.

  This artifact bypasses the locking mechanism by extracting the
  registry hives using raw NTFS parsing. We then just upload all hives
  to the server.

sources:
  - precondition: |
      SELECT OS From info() where OS = 'windows'
    queries:
      - |
        LET users = SELECT Name, Directory as HomeDir
            FROM Artifact.Windows.Sys.Users()
            WHERE Directory

      - |
        SELECT upload(file="\\\\.\\" + HomeDir + "\\ntuser.dat",
                      accessor="ntfs") as Upload
        FROM users
```
   </div></a>

## Windows.Registry.Sysinternals.Eulacheck

Checks for the Accepted Sysinternals EULA from the registry key
"HKCU\Software\Sysinternals\[TOOL]\".  When a Sysinternals tool is
first run on a system, the EULA must be accepted. This writes a
value called EulaAccepted under that key.

Note: This artifact uses HKEY_USERS and therefore will not detect
users that are not currently logged on.


Arg|Default|Description
---|------|-----------
Sysinternals_Reg_Key|HKEY_USERS\\*\\Software\\Sysinternals\\*|


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Registry_Sysinternals_EulacheckDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Registry_Sysinternals_EulacheckDetails" style="width: fit-content">


```
name: Windows.Registry.Sysinternals.Eulacheck
description: |
  Checks for the Accepted Sysinternals EULA from the registry key
  "HKCU\Software\Sysinternals\[TOOL]\".  When a Sysinternals tool is
  first run on a system, the EULA must be accepted. This writes a
  value called EulaAccepted under that key.

  Note: This artifact uses HKEY_USERS and therefore will not detect
  users that are not currently logged on.

parameters:
   - name: Sysinternals_Reg_Key
     default: HKEY_USERS\*\Software\Sysinternals\*

sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'

    queries:
    - LET users <= SELECT Name, UUID FROM Artifact.Windows.Sys.Users()
    - |
      SELECT Key.Name as ProgramName,
             Key.FullPath as Key,
             timestamp(epoch=Key.Mtime.Sec) AS TimeAccepted,
             {
                SELECT Name FROM users WHERE UUID=regex_replace(
                   source=Key.FullPath, re=".+\\\\(S-[^\\\\]+)\\\\.+", replace="$1")
             } as User,
             EulaAccepted
      FROM read_reg_key(globs=split(string=Sysinternals_Reg_Key, sep=',[\\s]*'))
```
   </div></a>
