---
description: Various Artifacts which do not fit into other categories.
linktitle: Miscelaneous
title: Miscelaneous Artifacts
toc: true
weight: 70

---
## Admin.Client.Upgrade

Remotely push new client updates.

NOTE: The updates can be pulled from any web server. You need to
ensure they are properly secured with SSL and at least a random
nonce in their path. You may configure the Velociraptor server to
serve these through the public directory. Simply place the MSI in
the public directory within the data store and set the URL below.


Arg|Default|Description
---|------|-----------
clientURL|http://127.0.0.1:8000/public/velociraptor.msi|The URL to fetch the MSI package.

{{% expand  "View Artifact Source" %}}


```
name: Admin.Client.Upgrade
description: |
  Remotely push new client updates.

  NOTE: The updates can be pulled from any web server. You need to
  ensure they are properly secured with SSL and at least a random
  nonce in their path. You may configure the Velociraptor server to
  serve these through the public directory. Simply place the MSI in
  the public directory within the data store and set the URL below.

parameters:
  - name: clientURL
    description: The URL to fetch the MSI package.
    default: http://127.0.0.1:8000/public/velociraptor.msi

sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'
    queries:
      # Wait a random amount of time so this can be run in a
      # hunt. Otherwise all clients will attempt to download the same
      # file at the same time probably overloading the server.
      - LET _ <= SELECT sleep(time=rand(range=600)) FROM scope()

      - SELECT * from foreach(
         row={
            SELECT Content AS Binary
            FROM http_client(url=clientURL, tempfile_extension=".msi")
         },
         query={
            SELECT * from execve(
               argv=["msiexec.exe", "/i", Binary]
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
uploadPostProcessCommand|["/bin/ls", "-l"]\n|The command to run - must be a json array of strings! The list\nof files will be appended to the end of the command.\n
uploadPostProcessArtifact|Windows.Registry.NTUser.Upload|The name of the artifact to watch.\n

{{% expand  "View Artifact Source" %}}


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
                  a2=file_store(path=Flow.uploaded_files)) as Argv
        FROM watch_monitoring(artifact='System.Flow.Completion')
        WHERE uploadPostProcessArtifact in Flow.artifacts_with_results

      - |
        SELECT * from foreach(
          row=files,
          query={
             SELECT Flow.session_id as FlowId, Argv,
                    Stdout, Stderr, ReturnCode
             FROM execve(argv=Argv)
          })
```
   {{% /expand %}}

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

{{% expand  "View Artifact Source" %}}


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
      - LET files = SELECT ClientId,
            Flow.session_id as Flow,
            Flow.uploaded_files as Files
        FROM watch_monitoring(artifact='System.Flow.Completion')
        WHERE Files and not Files =~ blacklistCompressionFilename

      - SELECT ClientId, Flow, Files,
               compress(path=Files) as CompressedFiles
        FROM files
```
   {{% /expand %}}

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


{{% expand  "View Artifact Source" %}}


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
type: CLIENT_EVENT

sources:
  - queries:
      # This query simulates failed logon attempts.
      - |
        LET failed_logon = SELECT Unix as FailedTime from clock(period=1)

      # This is the fifo which holds the last 5 failed logon attempts
      # within the last hour.
      - |
        LET last_5_events = SELECT FailedTime
            FROM fifo(query=failed_logon, max_rows=5, max_age=3600)

      # We need to get it started collecting data immediately by
      # materializing the cache contents. Otherwise the fifo wont
      # start until it is first called (i.e. the first successful
      # login and we will miss the failed events before hand).
      - |
        LET foo <= SELECT * FROM last_5_events

      # This simulates successful logon - we assume every 3 seonds.
      - |
        LET success_logon = SELECT Unix as SuccessTime from clock(period=3)

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
   {{% /expand %}}

## Demo.Plugins.GUI

A demo plugin showing some GUI features.


Arg|Default|Description
---|------|-----------
ChoiceSelector|First Choice|
Flag|Y|
OffFlag||
StartDate||

{{% expand  "View Artifact Source" %}}


```
name: Demo.Plugins.GUI
description: |
  A demo plugin showing some GUI features.


parameters:
  - name: ChoiceSelector
    type: choices
    default: First Choice
    choices:
      - First Choice
      - Second Choice
      - Third Choice

  - name: Flag
    type: bool
    default: Y

  - name: OffFlag
    type: bool

  - name: StartDate
    type: timestamp
```
   {{% /expand %}}

## Elastic.Events.Clients

This server monitoring artifact will watch a selection of client
monitoring artifacts for new events and push those to an elastic
index.

NOTE: You must ensure you are collecting these artifacts from the
clients by adding them to the "Client Events" GUI.


Arg|Default|Description
---|------|-----------
WindowsDetectionPsexecService||Upload Windows.Detection.PsexecService to Elastic
WindowsEventsDNSQueries||Upload Windows.Events.DNSQueries to Elastic
WindowsEventsProcessCreation||Upload Windows.Events.ProcessCreation to Elastic
WindowsEventsServiceCreation||Upload Windows.Events.ServiceCreation to Elastic
ElasticAddresses|http://127.0.0.1:9200/|

{{% expand  "View Artifact Source" %}}


```
name: Elastic.Events.Clients
description: |
  This server monitoring artifact will watch a selection of client
  monitoring artifacts for new events and push those to an elastic
  index.

  NOTE: You must ensure you are collecting these artifacts from the
  clients by adding them to the "Client Events" GUI.

type: SERVER_EVENT

parameters:
  - name: WindowsDetectionPsexecService
    description: Upload Windows.Detection.PsexecService to Elastic
    type: bool
  - name: WindowsEventsDNSQueries
    description: Upload Windows.Events.DNSQueries to Elastic
    type: bool
  - name: WindowsEventsProcessCreation
    description: Upload Windows.Events.ProcessCreation to Elastic
    type: bool
  - name: WindowsEventsServiceCreation
    description: Upload Windows.Events.ServiceCreation to Elastic
    type: bool
  - name: ElasticAddresses
    default: http://127.0.0.1:9200/
  - name: artifactParameterMap
    type: hidden
    default: |
      Artifact,Parameter
      Windows.Detection.PsexecService,WindowsDetectionPsexecService
      Windows.Events.DNSQueries,WindowsEventsDNSQueries
      Windows.Events.ProcessCreation,WindowsEventsProcessCreation
      Windows.Events.ServiceCreation,WindowsEventsServiceCreation

sources:
  - queries:
      - LET artifacts_to_watch = SELECT Artifact FROM parse_csv(
             filename=artifactParameterMap, accessor='data')
        WHERE get(item=scope(), member=Parameter) = "Y" AND log(
          message="Uploading artifact " + Artifact + " to Elastic")

      - LET events = SELECT * FROM foreach(
          row=artifacts_to_watch,
          async=TRUE,   // Required for event queries in foreach()
          query={
             SELECT *, "Artifact_" + Artifact as _index,
                    Artifact,
                    timestamp(epoch=now()) AS timestamp
             FROM watch_monitoring(artifact=Artifact)
          })

      - SELECT * FROM elastic_upload(
          query=events,
          type="ClientEvents",
          addresses=split(string=ElasticAddresses, sep=","))
```
   {{% /expand %}}

## Elastic.Flows.Upload

This server side event monitoring artifact waits for new artifacts
to be collected from endpoints and automatically uploads those to an
elastic server.

We use the artifact name as the name of the index. This allows users
to adjust the index size/lifetime according to the artifact it is
holding.


Arg|Default|Description
---|------|-----------
ArtifactNameRegex|.|Only upload these artifacts to elastic
elasticAddresses|http://127.0.0.1:9200/|

{{% expand  "View Artifact Source" %}}


```
name: Elastic.Flows.Upload
description: |
  This server side event monitoring artifact waits for new artifacts
  to be collected from endpoints and automatically uploads those to an
  elastic server.

  We use the artifact name as the name of the index. This allows users
  to adjust the index size/lifetime according to the artifact it is
  holding.

type: SERVER_EVENT

parameters:
  - name: ArtifactNameRegex
    default: .
    description: Only upload these artifacts to elastic
  - name: elasticAddresses
    default: http://127.0.0.1:9200/

sources:
  - queries:
      - LET completions = SELECT * FROM watch_monitoring(
             artifact="System.Flow.Completion")
             WHERE Flow.artifacts_with_results =~ ArtifactNameRegex

      - LET documents = SELECT * FROM foreach(row=completions,
          query={
             SELECT * FROM foreach(
                 row=Flow.artifacts_with_results,
                 query={
                     SELECT *, _value AS Artifact,
                            timestamp(epoch=now()) AS timestamp,
                            ClientId, Flow.session_id AS FlowId,
                            "artifact_" + regex_replace(source=_value,
                               re='[/.]', replace='_') as _index
                     FROM source(
                        client_id=ClientId,
                        flow_id=Flow.session_id,
                        artifact=_value)
                 })
          })

      - SELECT * FROM elastic_upload(
            query=documents,
            addresses=split(string=elasticAddresses, sep=","),
            index="velociraptor",
            type="artifact")
```
   {{% /expand %}}

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
documentGlobs|/*.{docx,docm,dotx,dotm,docb,xlsx,xlsm,xltx,xltm,p ...|
searchGlob|C:\\Users\\**|
yaraRule|rule Hit {\n  strings:\n    $a = "secret" wide noc ...|

{{% expand  "View Artifact Source" %}}


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
  - query: |
        LET office_docs = SELECT FullPath AS OfficePath,
             timestamp(epoch=Mtime.Sec) as OfficeMtime,
             Size as OfficeSize
        FROM glob(globs=searchGlob + documentGlobs)

        // A list of zip members inside the doc that have some content.
        LET document_parts = SELECT OfficePath,
             FullPath AS ZipMemberPath
        FROM glob(globs=url(
             scheme="file", path=OfficePath, fragment="/**").String,
             accessor='zip')
        WHERE not IsDir and Size > 0

        // For each document, scan all its parts for the keyword.
        SELECT OfficePath,
               OfficeMtime,
               OfficeSize,
               File.ModTime as InternalMtime,
               String.HexData as HexContext
        FROM foreach(
           row=office_docs,
           query={
              SELECT File, String, OfficePath,
                     OfficeMtime, OfficeSize
              FROM yara(
                 rules=yaraRule,
                 files=document_parts.ZipMemberPath,
                 context=200,
                 accessor='zip')
        })
```
   {{% /expand %}}

## Generic.Client.Info

Collect basic information about the client.

This artifact is collected when any new client is enrolled into the
system. Velociraptor will watch for this artifact and populate its
internal indexes from this artifact as well.

You can edit this artifact to enhance the client's interrogation
information as required.


{{% expand  "View Artifact Source" %}}


```
name: Generic.Client.Info
description: |
  Collect basic information about the client.

  This artifact is collected when any new client is enrolled into the
  system. Velociraptor will watch for this artifact and populate its
  internal indexes from this artifact as well.

  You can edit this artifact to enhance the client's interrogation
  information as required.

sources:
  - name: BasicInformation
    description: |
      This source is used internally to populate agent info. Do not
      remove this query.
    queries:
      - |
        SELECT config.Version.Name AS Name,
               config.Version.BuildTime as BuildTime,
               config.Labels AS Labels,
               Hostname, OS, Architecture,
               Platform, PlatformVersion, KernelVersion, Fqdn
        FROM info()

  - name: Users
    precondition: SELECT OS From info() where OS = 'windows'
    queries:
      - SELECT Name, Description,
               if(condition=Mtime, then=timestamp(epoch=Mtime)) AS LastLogin
        FROM Artifact.Windows.Sys.Users()

reports:
  - type: CLIENT
    template: |
      {{ $client_info := Query "SELECT * FROM clients(client_id=ClientId) LIMIT 1" }}

      {{ $flow_id := Query "SELECT timestamp(epoch=active_time / 1000000) AS Timestamp FROM flows(client_id=ClientId, flow_id=FlowId)" }}

      # {{ Get $client_info "0.os_info.fqdn" }} ( {{ Get $client_info "0.client_id" }} ) @ {{ Get $flow_id "0.Timestamp" }}

      {{ Query "SELECT * FROM source(source='BasicInformation')" | Table }}

      # Memory and CPU footprint over the past 24 hours

      {{ define "resources" }}
           SELECT Timestamp, rate(x=CPU, y=Timestamp) * 100 As CPUPercent,
                  RSS / 1000000 AS MemoryUse
           FROM source(artifact="Generic.Client.Stats",
                       client_id=ClientId,
                       mode="CLIENT_EVENT",
                       start_time=now() - 86400)
           WHERE CPUPercent >= 0
      {{ end }}

      {{ Query "resources" | LineChart "xaxis_mode" "time" "RSS.yaxis" 2 }}

      # Active Users

      {{ Query "SELECT * FROM source(source='Users')" | Table }}
```
   {{% /expand %}}

## Generic.Client.Stats

An Event artifact which generates client's CPU and memory statistics.

Arg|Default|Description
---|------|-----------
Frequency|10|Return stats every this many seconds.

{{% expand  "View Artifact Source" %}}


```
name: Generic.Client.Stats
description: An Event artifact which generates client's CPU and memory statistics.
parameters:
  - name: Frequency
    description: Return stats every this many seconds.
    default: "10"
type: CLIENT_EVENT

sources:
  - precondition: SELECT OS From info() where OS = 'windows'
    queries:
      - SELECT * from foreach(
         row={
           SELECT UnixNano FROM clock(period=atoi(string=Frequency))
         },
         query={
           SELECT UnixNano / 1000000000 as Timestamp,
                  User + System as CPU,
                  Memory.WorkingSetSize as RSS
           FROM pslist(pid=getpid())
         })

  - precondition: SELECT OS From info() where OS = 'linux'
    queries:
      - SELECT * from foreach(
         row={
           SELECT UnixNano FROM clock(period=atoi(string=Frequency))
         },
         query={
           SELECT UnixNano / 1000000000 as Timestamp,
                  Times.system + Times.user as CPU,
                  MemoryInfo.RSS as RSS
           FROM pslist(pid=getpid())
         })


reports:
  - type: SERVER_EVENT
    template: |
      {{ define "resources" }}
           SELECT Timestamp, rate(x=CPU, y=Timestamp) * 100 As CPUPercent,
                  RSS / 1000000 AS MemoryUse
           FROM source()
           WHERE CPUPercent >= 0
      {{ end }}

      {{ Query "resources" | LineChart "xaxis_mode" "time" "RSS.yaxis" 2 }}

  - type: MONITORING_DAILY
    template: |
      {{ define "resources" }}
           SELECT Timestamp, rate(x=CPU, y=Timestamp) * 100 As CPUPercent,
                  RSS / 1000000 AS MemoryUse
           FROM source()
           WHERE CPUPercent >= 0
      {{ end }}

      {{ $client_info := Query "SELECT * FROM clients(client_id=ClientId) LIMIT 1" }}

      # Client Footprint for {{ Get $client_info "0.OsInfo.Fqdn" }}

      The client has a client ID of {{ Get $client_info "0.client_id" }}.
      Clients report the Velociraptor process footprint to the
      server every 10 seconds. The data includes the total CPU
      utilization, and the resident memory size used by the client.

      The following graph shows the total utilization. Memory
      utilization is meausred in `Mb` while CPU Utilization is
      measured by `Percent of one core`.

      We would expect the client to use around 1-5% of one core when
      idle, but if a heavy hunt is running this might climb
      substantially.

      {{ Query "resources" | LineChart "xaxis_mode" "time" "RSS.yaxis" 2 }}

      ## VQL Query

      The following VQL query was used to plot the graph above.

      ```sql
      {{ template "resources" }}
      ```

      > To learn about managing end point performance with Velociraptor see
        the [blog post](https://docs.velociraptor.velocidex.com/blog/html/2019/02/10/velociraptor_performance.html).
```
   {{% /expand %}}

## Generic.Forensic.Carving.URLs

Carve URLs from files located in a glob. Note that we do not parse
any files - we simply carve anything that looks like a URL.


Arg|Default|Description
---|------|-----------
UrlGlob|["C:/Documents and Settings/*/Local Settings/Appli ...|

{{% expand  "View Artifact Source" %}}


```
name: Generic.Forensic.Carving.URLs
description: |
  Carve URLs from files located in a glob. Note that we do not parse
  any files - we simply carve anything that looks like a URL.


parameters:
  - name: UrlGlob
    default: |
      ["C:/Documents and Settings/*/Local Settings/Application Data/Google/Chrome/User Data/**",
       "C:/Users/*/AppData/Local/Google/Chrome/User Data/**",
       "C:/Documents and Settings/*/Local Settings/History/**",
       "C:/Documents and Settings/*/Local Settings/Temporary Internet Files/**",
       "C:/Users/*/AppData/Local/Microsoft/Windows/WebCache/**",
       "C:/Users/*/AppData/Local/Microsoft/Windows/INetCache/**",
       "C:/Users/*/AppData/Local/Microsoft/Windows/INetCookies/**",
       "C:/Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/**",
       "C:/Documents and Settings/*/Application Data/Mozilla/Firefox/Profiles/**"
       ]

sources:
  - queries:
      - |
        LET matching = SELECT FullPath FROM glob(
            globs=parse_json_array(data=UrlGlob))
      - |
        SELECT FullPath, URL FROM foreach(
          row=matching,
          query={
            SELECT FullPath,
                   URL FROM parse_records_with_regex(file=FullPath,
               regex="(?P<URL>https?:\\/\\/[\\w\\.-]+[\\/\\w \\.-]*)")
          })
```
   {{% /expand %}}

## Generic.Forensic.Timeline

This artifact generates a timeline of a file glob in bodyfile
format. We currently do not calculate the md5 because it is quite
expensive.


Arg|Default|Description
---|------|-----------
timelineGlob|C:\\Users\\**|
timelineAccessor|file|

{{% expand  "View Artifact Source" %}}


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
   {{% /expand %}}

## MacOS.Detection.Autoruns

Thie artifact collects evidence of autoruns. We also capture the files and upload them.

This code is based on
https://github.com/CrowdStrike/automactc/blob/master/modules/mod_autoruns_v102.py


Arg|Default|Description
---|------|-----------
sandboxed_loginitems|/var/db/com.apple.xpc.launchd/disabled.*.plist|
cronTabGlob|/private/var/at//tabs/*|
LaunchAgentsDaemonsGlob|["/System/Library/LaunchAgents/*.plist","/Library/ ...|
ScriptingAdditionsGlobs|["/System/Library/ScriptingAdditions/*.osax","/Lib ...|
StartupItemsGlobs|["/System/Library/StartupItems/*/*","/Library/Star ...|
MiscItemsGlobs|["/private/etc/periodic.conf", "/private/etc/perio ...|
LoginItemsGlobs|["/Users/*/Library/Preferences/com.apple.loginitem ...|

{{% expand  "View Artifact Source" %}}


```
name: MacOS.Detection.Autoruns
description: |
   Thie artifact collects evidence of autoruns. We also capture the files and upload them.

   This code is based on
   https://github.com/CrowdStrike/automactc/blob/master/modules/mod_autoruns_v102.py

precondition: SELECT OS FROM info() WHERE OS =~ 'darwin'

parameters:
- name: sandboxed_loginitems
  default: /var/db/com.apple.xpc.launchd/disabled.*.plist

- name: cronTabGlob
  default: /private/var/at//tabs/*

- name: LaunchAgentsDaemonsGlob
  default: |
     ["/System/Library/LaunchAgents/*.plist","/Library/LaunchAgents/*.plist",
      "/Users/*/Library/LaunchAgents/*.plist","/private/var/*/Library/LaunchAgents/*.plist",
      "/System/Library/LaunchAgents/.*.plist","/Library/LaunchAgents/.*.plist",
      "/Users/*/Library/LaunchAgents/.*.plist", "/private/var/*/Library/LaunchAgents/.*.plist",
      "/System/Library/LaunchDaemons/*.plist","/Library/LaunchDaemons/*.plist",
      "/System/Library/LaunchDaemons/.*.plist","/Library/LaunchDaemons/.*.plist"]

- name: ScriptingAdditionsGlobs
  default: |
      ["/System/Library/ScriptingAdditions/*.osax","/Library/ScriptingAdditions/*.osax",
       "/System/Library/ScriptingAdditions/.*.osax","/Library/ScriptingAdditions/.*.osax"]

- name: StartupItemsGlobs
  default: |
       ["/System/Library/StartupItems/*/*","/Library/StartupItems/*/*"]

- name: MiscItemsGlobs
  default: |
      ["/private/etc/periodic.conf", "/private/etc/periodic/*/*", "/private/etc/*.local",
       "/private/etc/rc.common",
       "/private/etc/emond.d/*","/private/etc/emond.d/*/*"]

- name: LoginItemsGlobs
  default: |
      ["/Users/*/Library/Preferences/com.apple.loginitems.plist",
       "/private/var/*/Library/Preferences/com.apple.loginitems.plist"]

sources:
- name: Sandboxed Loginitems
  queries:
  - SELECT FullPath,
           timestamp(epoch=Mtime.Sec) AS Mtime,
           plist(file=FullPath) AS Disabled,
           upload(file=FullPath) AS Upload
    FROM glob(globs=sandboxed_loginitems)

- name: crontabs
  queries:
      - LET raw = SELECT * FROM foreach(
          row={
            SELECT FullPath, Name,
                   timestamp(epoch=Mtime.Sec) AS Mtime,
                   upload(file=FullPath) AS Upload
            FROM glob(globs=split(string=cronTabGlob, sep=","))
          },
          query={
            SELECT FullPath, Name, Mtime, Upload,
              data, parse_string_with_regex(
               string=data,
               regex=[
                 /* Regex for event (Starts with @) */
                 "^(?P<Event>@[a-zA-Z]+)\\s+(?P<Command>.+)",

                 /* Regex for regular command. */
                 "^(?P<Minute>[^\\s]+)\\s+"+
                 "(?P<Hour>[^\\s]+)\\s+"+
                 "(?P<DayOfMonth>[^\\s]+)\\s+"+
                 "(?P<Month>[^\\s]+)\\s+"+
                 "(?P<DayOfWeek>[^\\s]+)\\s+"+
                 "(?P<Command>.+)$"]) as Record

            /* Read lines from the file and filter ones that start with "#" */
            FROM split_records(
               filenames=FullPath,
               regex="\n", columns=["data"]) WHERE not data =~ "^\\s*#"
            }) WHERE Record.Command

      - SELECT Record.Event AS Event,
               Mtime,
               Name AS User,
               Record.Minute AS Minute,
               Record.Hour AS Hour,
               Record.DayOfMonth AS DayOfMonth,
               Record.Month AS Month,
               Record.DayOfWeek AS DayOfWeek,
               Record.Command AS Command,
               FullPath AS Path,
               Upload
        FROM raw

- name: LaunchAgentsDaemons
  queries:
  - LET launchd_config = SELECT FullPath,
           timestamp(epoch=Mtime.Sec) AS Mtime,
           plist(file=FullPath) AS LaunchdConfig,
           upload(file=FullPath) AS Upload
    FROM glob(globs=parse_json_array(data=LaunchAgentsDaemonsGlob))

  - LET programs = SELECT FullPath, Mtime, LaunchdConfig,
           get(member="LaunchdConfig.Program",
               default=get(member="LaunchdConfig.ProgramArguments.0")) AS Program
    FROM launchd_config

  - SELECT FullPath, Mtime, LaunchdConfig,
           Program, hash(path=Program) AS Hash,
           upload(file=FullPath) AS Upload
    FROM programs

- name: ScriptingAdditions
  queries:
  - SELECT FullPath,
           timestamp(epoch=Mtime.Sec) AS Mtime,
           upload(file=FullPath) AS Upload
    FROM glob(globs=parse_json_array(data=ScriptingAdditionsGlobs))

- name: StartupItems
  queries:
  - SELECT FullPath,
           timestamp(epoch=Mtime.Sec) AS Mtime,
           upload(file=FullPath) AS Upload
    FROM glob(globs=parse_json_array(data=StartupItemsGlobs))

- name: MiscItems
  queries:
  - SELECT FullPath,
           timestamp(epoch=Mtime.Sec) AS Mtime,
           upload(file=FullPath) AS Upload
    FROM glob(globs=parse_json_array(data=MiscItemsGlobs))

- name: LoginItems
  queries:
  - SELECT FullPath,
           timestamp(epoch=Mtime.Sec) AS Mtime,
           plist(file=FullPath) AS LoginItemConfig,
           upload(file=FullPath) AS Upload
    FROM glob(globs=parse_json_array(data=LoginItemsGlobs))
```
   {{% /expand %}}

## MacOS.System.Users

This artifact collects information about the local users on the
system. The information is stored in plist files.


Arg|Default|Description
---|------|-----------
UserPlistGlob|/private/var/db/dslocal/nodes/Default/users/*.plis ...|
OnlyShowRealUsers|Y|

{{% expand  "View Artifact Source" %}}


```
name: MacOS.System.Users
description: |
  This artifact collects information about the local users on the
  system. The information is stored in plist files.

parameters:
  - name: UserPlistGlob
    default: /private/var/db/dslocal/nodes/Default/users/*.plist
  - name: OnlyShowRealUsers
    type: bool
    default: Y

sources:
  - queries:
      - LET user_plist = SELECT FullPath FROM glob(globs=UserPlistGlob)
      - LET UserDetails = SELECT * FROM foreach(
           row=plist(file=FullPath),
           query={
              SELECT get(member="name.0", default="") AS Name,
                     get(member="realname.0", default="") AS RealName,
                     get(member="shell.0", default="") AS UserShell,
                     get(member="home.0", default="") AS HomeDir,
                     plist(file=get(member="LinkedIdentity.0", default=""),
                           accessor='data') as AppleId,
                     plist(file=get(member="accountPolicyData.0", default=""),
                           accessor='data') AS AccountPolicyData
              FROM scope()
        })

      - SELECT Name, RealName, UserShell, HomeDir,
               get(item=AppleId, field="appleid.apple.com") AS AppleId,
               timestamp(epoch=AccountPolicyData.creationTime) AS CreationTime,
               AccountPolicyData.failedLoginCount AS FailedLoginCount,
               timestamp(epoch=AccountPolicyData.failedLoginTimestamp) AS FailedLoginTimestamp,
               timestamp(epoch=AccountPolicyData.passwordLastSetTime) AS PasswordLastSetTime
        FROM foreach(row=user_plist, query=UserDetails)
        WHERE OnlyShowRealUsers != 'Y' OR NOT UserShell =~ 'false'
```
   {{% /expand %}}

## Network.ExternalIpAddress

Detect the external ip address of the end point.

Arg|Default|Description
---|------|-----------
externalUrl|http://www.myexternalip.com/raw|The URL of the external IP detection site.

{{% expand  "View Artifact Source" %}}


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
      - |
        SELECT Content as IP from http_client(url=externalUrl)
```
   {{% /expand %}}

## Reporting.Hunts.Details

Report details about which client ran each hunt, how long it took
and if it has completed.


{{% expand  "View Artifact Source" %}}


```
name: Reporting.Hunts.Details
description: |
  Report details about which client ran each hunt, how long it took
  and if it has completed.

type: SERVER

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
          timestamp(epoch=Flow.create_time/1000000) as create_time,
          basename(path=Flow.session_id) as flow_id,
          (Flow.active_time - Flow.create_time) / 1000000 as Duration,
          format(format='%v', args=[Flow.state]) as State
        FROM hunt_flows(hunt_id=hunt_id) order by create_time desc
      - |
        SELECT * from foreach(row=hunts, query=flows)
```
   {{% /expand %}}

## System.Flow.Completion

An internal artifact that produces events for every flow completion
in the system.


{{% expand  "View Artifact Source" %}}


```
name: System.Flow.Completion
description: |
  An internal artifact that produces events for every flow completion
  in the system.

type: CLIENT_EVENT
```
   {{% /expand %}}

## System.Hunt.Participation

Endpoints may participate in hunts. This artifact collects which hunt
each system participated in.

Note: This is an automated system hunt. You do not need to start it.


{{% expand  "View Artifact Source" %}}


```
name: System.Hunt.Participation
description: |
     Endpoints may participate in hunts. This artifact collects which hunt
     each system participated in.

     Note: This is an automated system hunt. You do not need to start it.

type: CLIENT_EVENT

reports:
  - type: MONITORING_DAILY
    template: |
      {{ define "all_hunts" }}LET allhunts <= SELECT * FROM hunts(){{ end }}
      {{ define "hunts" }}
           SELECT * FROM foreach(
             row={ SELECT timestamp(epoch=Timestamp) AS Scheduled,
                          HuntId as ParticipatedHuntId
                   FROM source(client_id=ClientId,
                       artifact='System.Hunt.Participation') },
             query={
                SELECT Scheduled,
                       HuntId,
                       HuntDescription,
                       StartRequest.Args.Artifacts.Names
                FROM allhunts
                WHERE HuntId = ParticipatedHuntId
             })
      {{ end }}

      {{ $client_info := Query "SELECT * FROM clients(client_id=ClientId) LIMIT 1" }}

      # Hunt participation for {{ Get $client_info "0.os_info.fqdn" }}

      The client with a client ID of {{ Get $client_info "0.client_id" }} participated in some hunts today.

      {{ Query "all_hunts" "hunts" | Table }}

      ## VQL Query
      The following VQL query was used to plot the graph above.

      ```sql
      {{ template "hunts" }}
      ```
```
   {{% /expand %}}

## System.VFS.DownloadFile

This is an internal artifact used by the GUI to populate the
VFS. You may run it manually if you like, but typically it is
launched by the GUI when the user clicks the "Collect from client"
button at the file "Stats" tab.


Arg|Default|Description
---|------|-----------
Path|/|The path of the file to download.
Accessor|file|

{{% expand  "View Artifact Source" %}}


```
name: System.VFS.DownloadFile
description: |
  This is an internal artifact used by the GUI to populate the
  VFS. You may run it manually if you like, but typically it is
  launched by the GUI when the user clicks the "Collect from client"
  button at the file "Stats" tab.

parameters:
  - name: Path
    description: The path of the file to download.
    default: /
  - name: Accessor
    default: file

sources:
  - queries:
      - SELECT Path, Accessor, Size, Error, Sha256, Md5
        FROM upload(files=Path, accessor=Accessor)
```
   {{% /expand %}}

## System.VFS.ListDirectory

This is an internal artifact used by the GUI to populate the
VFS. You may run it manually if you like, but typically it is
launched by the GUI when a user clicks the "Refresh this directory"
button.


Arg|Default|Description
---|------|-----------
Path|/|The path of the file to download.
Accessor|file|
Depth|0|

{{% expand  "View Artifact Source" %}}


```
name: System.VFS.ListDirectory
description: |
  This is an internal artifact used by the GUI to populate the
  VFS. You may run it manually if you like, but typically it is
  launched by the GUI when a user clicks the "Refresh this directory"
  button.

parameters:
  - name: Path
    description: The path of the file to download.
    default: "/"

  - name: Accessor
    default: file

  - name: Depth
    default: 0

sources:
  - queries:
      - SELECT FullPath as _FullPath,
           Accessor as _Accessor,
           Data as _Data,
           Name, Size, Mode.String AS Mode,
           timestamp(epoch=Mtime.Sec) as mtime,
           timestamp(epoch=Atime.Sec) as atime,
           timestamp(epoch=Ctime.Sec) as ctime
        FROM glob(globs=Path + if(condition=atoi(string=Depth),
             then='/**' + Depth, else='/*'),
             accessor=Accessor)
```
   {{% /expand %}}

## Windows.Analysis.EvidenceOfExecution

In many investigations it is useful to find evidence of program execution.

This artifact combines the findings of several other collectors into
an overview of all program execution artifacts. The associated
report walks the user through the analysis of the findings.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Analysis.EvidenceOfExecution
description: |
  In many investigations it is useful to find evidence of program execution.

  This artifact combines the findings of several other collectors into
  an overview of all program execution artifacts. The associated
  report walks the user through the analysis of the findings.

sources:
  - name: UserAssist
    queries:
      - SELECT * FROM Artifact.Windows.Registry.UserAssist()

  - name: Timeline
    queries:
      - SELECT * FROM Artifact.Windows.Forensics.Timeline()

  - name: Recent Apps
    queries:
      - SELECT * FROM Artifact.Windows.Forensics.RecentApps()

  - name: ShimCache
    queries:
      - SELECT * FROM Artifact.Windows.Registry.AppCompatCache()

  - name: Prefetch
    queries:
      - SELECT * FROM Artifact.Windows.Forensics.Prefetch()
```
   {{% /expand %}}

## Windows.Applications.ChocolateyPackages

Chocolatey packages installed in a system.

Arg|Default|Description
---|------|-----------
ChocolateyInstall||

{{% expand  "View Artifact Source" %}}


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
      - LET files = SELECT FullPath,
              parse_xml(file=FullPath) AS Metadata
              -- Use the ChocolateyInstall parameter if it is set.

          FROM glob(globs=if(
             condition=ChocolateyInstall,
             then=ChocolateyInstall,

             -- Otherwise just use the environment.
             else=environ(var='ChocolateyInstall')) + '/lib/*/*.nuspec')

      - SELECT * FROM if(
        condition=if(condition=ChocolateyInstall,
                     then=ChocolateyInstall,
                     else=environ(var="ChocolateyInstall")),
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
   {{% /expand %}}

## Windows.Applications.Chrome.Cookies

Enumerate the users chrome cookies.

The cookies are typically encrypted by the DPAPI using the user's
credentials. Since Velociraptor is typically not running in the user
context we can not decrypt these. It may be possible to decrypt the
cookies off line.

The pertinant information from a forensic point of view is the
user's Created and LastAccess timestamp and the fact that the user
has actually visited the site and obtained a cookie.


Arg|Default|Description
---|------|-----------
cookieGlobs|\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Co ...|
cookieSQLQuery|SELECT creation_utc, host_key, name, value, path,  ...|
userRegex|.|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Applications.Chrome.Cookies
description: |
  Enumerate the users chrome cookies.

  The cookies are typically encrypted by the DPAPI using the user's
  credentials. Since Velociraptor is typically not running in the user
  context we can not decrypt these. It may be possible to decrypt the
  cookies off line.

  The pertinant information from a forensic point of view is the
  user's Created and LastAccess timestamp and the fact that the user
  has actually visited the site and obtained a cookie.

parameters:
  - name: cookieGlobs
    default: \AppData\Local\Google\Chrome\User Data\*\Cookies
  - name: cookieSQLQuery
    default: |
      SELECT creation_utc, host_key, name, value, path, expires_utc,
             last_access_utc, encrypted_value
      FROM cookies
  - name: userRegex
    default: .

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        LET cookie_files = SELECT * from foreach(
          row={
             SELECT Uid, Name AS User, Directory
             FROM Artifact.Windows.Sys.Users()
             WHERE Name =~ userRegex
          },
          query={
             SELECT User, FullPath, Mtime from glob(
               globs=Directory + cookieGlobs)
          })

      - |
        SELECT * FROM foreach(row=cookie_files,
          query={
            SELECT timestamp(winfiletime=creation_utc * 10) as Created,
                   timestamp(winfiletime=last_access_utc * 10) as LastAccess,
                   timestamp(winfiletime=expires_utc * 10) as Expires,
                   host_key, name, path, value,
                   base64encode(string=encrypted_value) as EncryptedValue
            FROM sqlite(
              file=FullPath,
              query=cookieSQLQuery)
          })
```
   {{% /expand %}}

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
extensionGlobs|\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Ex ...|
userRegex|.|

{{% expand  "View Artifact Source" %}}


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
  - name: userRegex
    default: .

sources:
  - precondition: |
      SELECT OS From info() where OS = 'windows'
    queries:
      - |
        /* For each user on the system, search for extension manifests
           in their home directory. */
        LET extension_manifests = SELECT * from foreach(
          row={
             SELECT Uid, Name AS User, Directory
             FROM Artifact.Windows.Sys.Users()
             WHERE Name =~ userRegex
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
   {{% /expand %}}

## Windows.Applications.Chrome.History

Enumerate the users chrome history.


Arg|Default|Description
---|------|-----------
historyGlobs|\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Hi ...|
urlSQLQuery|SELECT url as visited_url, title, visit_count,\n   ...|
userRegex|.|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Applications.Chrome.History
description: |
  Enumerate the users chrome history.

parameters:
  - name: historyGlobs
    default: \AppData\Local\Google\Chrome\User Data\*\History
  - name: urlSQLQuery
    default: |
      SELECT url as visited_url, title, visit_count,
             typed_count, last_visit_time
      FROM urls
  - name: userRegex
    default: .

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        LET history_files = SELECT * from foreach(
          row={
             SELECT Uid, Name AS User, Directory
             FROM Artifact.Windows.Sys.Users()
             WHERE Name =~ userRegex
          },
          query={
             SELECT User, FullPath, Mtime from glob(
               globs=Directory + historyGlobs)
          })

      - |
        SELECT * FROM foreach(row=history_files,
          query={
            SELECT User, FullPath,
                   timestamp(epoch=Mtime.Sec) as Mtime,
                   visited_url,
                   title, visit_count, typed_count,
                   timestamp(winfiletime=last_visit_time * 10) as last_visit_time
            FROM sqlite(
              file=FullPath,
              query=urlSQLQuery)
          })
```
   {{% /expand %}}

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

{{% expand  "View Artifact Source" %}}


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
   {{% /expand %}}

## Windows.Attack.ParentProcess

Maps the Mitre Att&ck framework process executions into artifacts.

### References:
* https://www.sans.org/security-resources/posters/hunt-evil/165/download
* https://github.com/teoseller/osquery-attck/blob/master/windows-incorrect_parent_process.conf


Arg|Default|Description
---|------|-----------
lookupTable|ProcessName,ParentRegex\nsmss.exe,System\nruntimeb ...|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Attack.ParentProcess
description: |
  Maps the Mitre Att&ck framework process executions into artifacts.

  ### References:
  * https://www.sans.org/security-resources/posters/hunt-evil/165/download
  * https://github.com/teoseller/osquery-attck/blob/master/windows-incorrect_parent_process.conf

precondition: SELECT OS From info() where OS = 'windows'

parameters:
  - name: lookupTable
    default: |
       ProcessName,ParentRegex
       smss.exe,System
       runtimebroker.exe,svchost.exe
       taskhostw.exe,svchost.exe
       services.exe,wininit.exe
       lsass.exe,wininit.exe
       svchost.exe,services.exe
       cmd.exe,explorer.exe
       powershell.exe,explorer.exe
       iexplore.exe,explorer.exe
       firefox.exe,explorer.exe
       chrome.exe,explorer.exe

sources:
     - queries:
       # Build up some cached queries for speed.
       - LET lookup <= SELECT * FROM parse_csv(filename=lookupTable, accessor='data')
       - LET processes <= SELECT Name, Pid, Ppid, CommandLine, CreateTime, Exe FROM pslist()
       - LET processes_lookup <= SELECT Name As ProcessName, Pid As ProcID FROM processes
       - |
         // Resolve the Ppid into a parent name using our processes_lookup
         LET resolved_parent_name = SELECT * FROM foreach(
         row={ SELECT * FROM processes},
         query={
           SELECT Name AS ActualProcessName,
                  ProcessName AS ActualParentName,
                  Pid, Ppid, CommandLine, CreateTime, Exe
           FROM processes_lookup
           WHERE ProcID = Ppid LIMIT 1
         })

       - |
         // Get the expected parent name from the table above.
         SELECT * FROM foreach(
           row=resolved_parent_name,
           query={
             SELECT ActualProcessName,
                    ActualParentName,
                    Pid, Ppid, CommandLine, CreateTime, Exe,
                    ParentRegex as ExpectedParentName
             FROM lookup
             WHERE ActualProcessName =~ ProcessName AND NOT ActualParentName =~ ParentRegex
         })
```
   {{% /expand %}}

## Windows.Attack.Prefetch

Maps the Mitre Att&ck framework process executions into
artifacts. This pack was generated from
https://github.com/teoseller/osquery-attck


{{% expand  "View Artifact Source" %}}


```
name: Windows.Attack.Prefetch
description: |
   Maps the Mitre Att&ck framework process executions into
   artifacts. This pack was generated from
   https://github.com/teoseller/osquery-attck

precondition: SELECT OS From info() where OS = 'windows'

sources:
     - queries:
       - SELECT Name, ModTime, Mtime.Sec AS modified
         FROM glob(globs="C:/Windows/Prefetch/*")

# Reports can be MONITORING_DAILY, CLIENT, SERVER_EVENT
reports:
  - type: CLIENT
    parameters:
      - name: lookupTable
        default: |
           signature,description
           attrib,Attrib Execute is usually used to modify file attributes - ATT&CK T1158
           schtasks.exe,Schtasks Execute: usaullay used to create a scheduled task - ATT&CK T1053:S0111
           taskeng.exe,taskeng Execute: usaullay used to create a scheduled task - ATT&CK T1053
           tscon.exe,tscon.exe Execute: usaullay used to Terminal Services Console - ATT&CK T1076
           mstsc.exe,mstsc.exe Execute: usaullay used to perform a RDP Session  - ATT&CK T1076
           at.exe,Schtasks Execute: usaullay used to create a scheduled task - ATT&CK T1053:S0110
           tasklist.exe,Tasklist Execute: usaullay used to list task - ATT&CK T1057:T1063:T1007:S0057
           taskkill.exe,Taskkill Execute: usaullay used to kill task
           mshta.exe,Mshta Execute: is a utility that executes Microsoft HTML Applications (HTA) - ATT&CK T1170
           whoami.exe,Whoami Execute: used to prints the effective username of the current user
           xcopy.exe,Xcopy Execute: is used for copying multiple files or entire directory trees from one directory to another and for copying files across a network.
           esentutl.exe,Esentutl Execute: is a legitimate built-in command-line program it could be used to create a exe from dump raw source.
           net.exe,Net Execute: is used in command-line operations for control of users: groups: services: and network connections - ATT&CK T1126:T1087:T1201:T1069:S0039:T1018:T1007:T1124
           vssadmin.exe,Vssadmin Execute: usaullay used to execute activity on Volume Shadow copy
           InstallUtil.exe,InstallUtil Execute: InstallUtil is a command-line utility that allows for installation and uninstallation of resources by executing specific installer components specified in .NET binaries - ATT&CK T1118
           cmstp.exe,CMSTP Execute: The Microsoft Connection Manager Profile Installer (CMSTP.exe) is a command-line program used to install Connection Manager service profiles. - ATT&CK T1191
           cmd.exe,Command-Line Interface Execute: CMD execution - ATT&CK T1059
           cscript.exe,Command-Line Interface Execute: Cscript execution starts a script so that it runs in a command-line environment. - ATT&CK T1216
           powershell.exe,POWERSHELL Execute: is a powerful interactive command-line interface and scripting environment included in the Windows operating system - ATT&CK T1086
           regsvr32.exe,POWERSHELL Execute: is a powerful interactive command-line interface and scripting environment included in the Windows operating system - ATT&CK T1117
           PsExec.exe,PsExec Execute: is a free Microsoft tool that can be used to execute a program on another computer. - ATT&CK T1035:S0029
           runas.exe,Runas Execute: Allows a user to run specific tools and programs with different permissions than the user's current logon provides. - ATT&CK T1134
           bitsadmin.exe,Bitsadmin Execute: Windows Background Intelligent Transfer Service (BITS) is a low-bandwidth: asynchronous file transfer mechanism exposed through Component Object Model (COM) - ATT&CK T1197:S0190
           certutil.exe,Certutil Execute: Certutil.exe is a legitimate built-in command-line program to manage certificates in Windows - ATT&CK T1105:T1140:T1130:S0160
           netsh.exe,Netsh Execute: Netsh.exe (also referred to as Netshell) is a command-line scripting utility used to interact with the network configuration of a system - ATT&CK T1128:T1063:S0108
           netstat.exe,Netstat Execute:  is an operating system utility that displays active TCP connections: listening ports: and network statistics. - ATT&CK T1049:S0104
           reg.exe,Reg Execute: Reg is a Windows utility used to interact with the Windows Registry.  - ATT&CK T1214:T1012:T1063:S0075
           regedit.exe,Regedit Execute: is a Windows utility used to interact with the Windows Registry. - ATT&CK T1214
           systeminfo.exe,Systeminfo Execute: Systeminfo is a Windows utility that can be used to gather detailed information about a computer. - ATT&CK T1082:S0096
           sc.exe,SC.exe Execute: Service Control - Create: Start: Stop: Query or Delete any Windows SERVICE. . - ATT&CK T1007


    template: |
      {{ .Description }}

      The below shows any prefetch files of interest and what they
      could potentially mean.

      {{ define "query" }}
         LET lookup <= SELECT * FROM parse_csv(filename=lookupTable, accessor='data')
      {{ end }}

      {{ define "data"}}
        LET data <= SELECT * FROM source()
      {{ end }}

      {{ range (Query "data" "query" "SELECT * FROM lookup") }}
          {{ $rows := Query (printf "SELECT * FROM source() WHERE Name =~ '%v'" (Get . "signature") ) }}
          {{ if $rows }}

      ## {{ Get $rows "0.Name" }}
      Modified on {{ Get $rows "0.ModTime" }}.

      {{ Get . "description" }}

          {{ end }}
      {{ end }}

      # Timeline

      {{ Query "SELECT modified * 1000, Name FROM foreach(row=lookup, query={ SELECT * FROM data WHERE Name =~ signature})" | Timeline }}
```
   {{% /expand %}}

## Windows.Collectors.File

Collects files using a set of globs. All globs must be on the same
device. The globs will be searched in one pass - so you can provide
many globs at the same time.


Arg|Default|Description
---|------|-----------
collectionSpec|Glob\nUsers\\*\\NTUser.dat\n|A CSV file with a Glob column with all the globs to collect.\nNOTE: Globs must not have a leading device since the device\nwill depend on the VSS.\n
RootDevice|C:|The device to apply all the glob on.
Accessor|lazy_ntfs|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Collectors.File
description: |
   Collects files using a set of globs. All globs must be on the same
   device. The globs will be searched in one pass - so you can provide
   many globs at the same time.

parameters:
  - name: collectionSpec
    description: |
       A CSV file with a Glob column with all the globs to collect.
       NOTE: Globs must not have a leading device since the device
       will depend on the VSS.
    default: |
       Glob
       Users\*\NTUser.dat
  - name: RootDevice
    description: The device to apply all the glob on.
    default: "C:"
  - name: Accessor
    default: lazy_ntfs

sources:
   - name: All Matches Metadata
     queries:
      # Generate the collection globs for each device
      - LET specs = SELECT "\\\\.\\" + RootDevice + "\\" + Glob AS Glob
            FROM parse_csv(filename=collectionSpec, accessor="data")
            WHERE log(message="Processing Device " + RootDevice + " With " + Accessor)

      # Join all the collection rules into a single Glob plugin. This ensure we
      # only make one pass over the filesystem. We only want LFNs.
      - |
        LET hits = SELECT FullPath AS SourceFile, Size,
               timestamp(epoch=Ctime.Sec) AS Created,
               timestamp(epoch=Mtime.Sec) AS Modified,
               timestamp(epoch=Atime.Sec) AS LastAccessed
        FROM glob(globs=specs.Glob, accessor=Accessor)
        WHERE NOT IsDir AND log(message="Found " + SourceFile)

      # Create a unique key to group by - modification time and path name.
      # Order by device name so we get C:\ above the VSS device.
      - LET all_results <= SELECT Created, LastAccessed,
              Modified, Size, SourceFile
        FROM hits

      - SELECT * FROM all_results

   - name: Uploads
     queries:
      # Upload the files
      - LET uploaded_tiles = SELECT Created, LastAccessed, Modified, SourceFile, Size,
               upload(file=SourceFile, accessor=Accessor, name=SourceFile) AS Upload
        FROM all_results

      # Seperate the hashes into their own column.
      - SELECT now() AS CopiedOnTimestamp, SourceFile, Upload.Path AS DestinationFile,
               Size AS FileSize, Upload.sha256 AS SourceFileSha256,
               Created, Modified, LastAccessed
        FROM uploaded_tiles
```
   {{% /expand %}}

## Windows.Collectors.VSS

Collects files with VSS deduplication.

Volume shadow copies is a windows feature where file system
snapshots can be made at various times. When collecting files it is
useful to go back through the VSS to see older versions of critical
files.

At the same time we dont want to collect multiple copies of the
same data.

This artifact runs the provided globs over all the VSS and collects
the unique modified time + path combinations.

If a file was modified in a previous VSS copy, this artifact will
retrieve it at multiple shadow copies.


Arg|Default|Description
---|------|-----------
collectionSpec|Glob\nUsers\\*\\NTUser.dat\n|A CSV file with a Glob column with all the globs to collect.\nNOTE: Globs must not have a leading device since the device\nwill depend on the VSS.\n
RootDevice|C:|The device to apply all the glob on.
Accessor|lazy_ntfs|
VSSDateRegex|.|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Collectors.VSS
description: |
   Collects files with VSS deduplication.

   Volume shadow copies is a windows feature where file system
   snapshots can be made at various times. When collecting files it is
   useful to go back through the VSS to see older versions of critical
   files.

   At the same time we dont want to collect multiple copies of the
   same data.

   This artifact runs the provided globs over all the VSS and collects
   the unique modified time + path combinations.

   If a file was modified in a previous VSS copy, this artifact will
   retrieve it at multiple shadow copies.

parameters:
  - name: collectionSpec
    description: |
       A CSV file with a Glob column with all the globs to collect.
       NOTE: Globs must not have a leading device since the device
       will depend on the VSS.
    default: |
       Glob
       Users\*\NTUser.dat
  - name: RootDevice
    description: The device to apply all the glob on.
    default: "C:"
  - name: Accessor
    default: lazy_ntfs
  - name: VSSDateRegex
    default: .

sources:
   - name: All Matches Metadata
     queries:
      - LET originating_machine <= SELECT Data.SystemName AS System
            FROM glob(globs="/*", accessor=Accessor)
            WHERE Name = "\\\\.\\" + RootDevice

      # Generate the collection globs for each device
      - LET specs = SELECT Device + Glob AS Glob FROM parse_csv(
            filename=collectionSpec, accessor="data")
            WHERE log(message="Processing Device " + Device + " With " + Accessor)

      # Join all the collection rules into a single Glob plugin. This ensure we
      # only make one pass over the filesystem. We only want LFNs.
      - |
        LET hits = SELECT FullPath AS SourceFile, Size,
               timestamp(epoch=Ctime.Sec) AS Created,
               timestamp(epoch=Mtime.Sec) AS Modified,
               timestamp(epoch=Atime.Sec) AS LastAccessed,
               Device, strip(string=FullPath, prefix=Device) AS Path,
               Data.mft AS MFT, Data.name_type AS NameType
        FROM glob(globs=specs.Glob, accessor=Accessor)
        WHERE NOT IsDir

      # Get all volume shadows on this system.
      - LET volume_shadows = SELECT Data.InstallDate AS InstallDate,
               Data.DeviceObject + "\\" AS Device
        FROM glob(globs='/*', accessor=Accessor)
        WHERE Device =~ 'VolumeShadowCopy' AND
              Data.OriginatingMachine = originating_machine.System[0] AND
              InstallDate =~ VSSDateRegex

      # The target devices are the root device and all the VSS
      - LET target_devices = SELECT * FROM chain(
            a={SELECT "\\\\.\\" + RootDevice + "\\" AS Device from scope()},
            b=volume_shadows)

      # Get all the paths matching the collection globs.
      - LET all_matching = SELECT * FROM foreach(row=target_devices, query=hits)

      # Create a unique key to group by - modification time and path name.
      # Order by device name so we get C:\ above the VSS device.
      - LET all_results <= SELECT Created, LastAccessed, Path, MFT, NameType,
              Modified, Size, SourceFile, Device, format(format="%s:%v", args=[Modified, MFT]) AS Key
        FROM all_matching ORDER BY Device DESC
      - SELECT * FROM all_results

   - name: Uploads
     queries:
      # Get all the unique versions of the sort key - that is unique instances of
      # mod time + path. If a path has several mod time (i.e. different times in each VSS
      # we will get them all). But if the same path has the same mod time in all VSS we only
      # take the first one which due to the sorting above will be the root device usually.
      - LET unique_mtimes = SELECT * FROM all_results GROUP BY Key

      # Upload the files using the MFT accessor.
      - LET uploaded_tiles = SELECT Created, LastAccessed, Modified, MFT, SourceFile, Size,
               upload(file=Device+MFT, name=SourceFile, accessor="mft") AS Upload
        FROM unique_mtimes

      # Seperate the hashes into their own column.
      - SELECT now() AS CopiedOnTimestamp, SourceFile, Upload.Path AS DestinationFile,
               Size AS FileSize, Upload.sha256 AS SourceFileSha256,
               Created, Modified, LastAccessed, MFT
        FROM uploaded_tiles
```
   {{% /expand %}}

## Windows.EventLogs.AlternateLogon

Logon specifying alternate credentials - if NLA enabled on
destination Current logged-on User Name Alternate User Name
Destination Host Name/IP Process Name


Arg|Default|Description
---|------|-----------
securityLogFile|C:/Windows/System32/Winevt/Logs/Security.evtx|

{{% expand  "View Artifact Source" %}}


```
name: Windows.EventLogs.AlternateLogon
description: |
  Logon specifying alternate credentials - if NLA enabled on
  destination Current logged-on User Name Alternate User Name
  Destination Host Name/IP Process Name

reference:
  - https://digital-forensics.sans.org/media/SANS_Poster_2018_Hunt_Evil_FINAL.pdf

precondition: SELECT OS From info() where OS = 'windows'

parameters:
  - name: securityLogFile
    default: C:/Windows/System32/Winevt/Logs/Security.evtx

sources:
  - queries:
      - SELECT EventData.IpAddress AS IpAddress,
               EventData.IpPort AS Port,
               EventData.ProcessName AS ProcessName,
               EventData.SubjectUserSid AS SubjectUserSid,
               EventData.SubjectUserName AS SubjectUserName,
               EventData.TargetUserName AS TargetUserName,
               EventData.TargetServerName AS TargetServerName,
               System.TimeCreated.SystemTime AS LogonTime
        FROM parse_evtx(filename=securityLogFile)
        WHERE System.EventID.Value = 4648
```
   {{% /expand %}}

## Windows.EventLogs.DHCP


This artifact parses the windows dhcp event log looking for evidence
of IP address assignments.

In some investigations it is important to be able to identify the
machine which was assigned a particular IP address at a point in
time. Usually these logs are available from the DHCP server, but in
many cases the server logs are not available (for example, if the
endpoint was visiting a different network or the DHCP server is on a
wireless router with no log retention).

On windows, there are two types of logs:

  1. The first type is the admin log
     (`Microsoft-Windows-Dhcp-Client%4Admin.evt`). These only contain
     errors such as an endpoint trying to continue its lease, but
     the lease is rejected by the server.

  2. The operational log
     (`Microsoft-Windows-Dhcp-Client%4Operational.evtx`) contains
     the full log of each lease. Unfortunately this log is disabled
     by default. If it is available we can rely on the information.


Arg|Default|Description
---|------|-----------
eventDirGlob|C:\\Windows\\system32\\winevt\\logs\\|
adminLog|Microsoft-Windows-Dhcp-Client%4Admin.evtx|
operationalLog|Microsoft-Windows-Dhcp-Client%4Operational.evtx|
accessor|file|

{{% expand  "View Artifact Source" %}}


```
name: Windows.EventLogs.DHCP
description: |

  This artifact parses the windows dhcp event log looking for evidence
  of IP address assignments.

  In some investigations it is important to be able to identify the
  machine which was assigned a particular IP address at a point in
  time. Usually these logs are available from the DHCP server, but in
  many cases the server logs are not available (for example, if the
  endpoint was visiting a different network or the DHCP server is on a
  wireless router with no log retention).

  On windows, there are two types of logs:

    1. The first type is the admin log
       (`Microsoft-Windows-Dhcp-Client%4Admin.evt`). These only contain
       errors such as an endpoint trying to continue its lease, but
       the lease is rejected by the server.

    2. The operational log
       (`Microsoft-Windows-Dhcp-Client%4Operational.evtx`) contains
       the full log of each lease. Unfortunately this log is disabled
       by default. If it is available we can rely on the information.

parameters:
  - name: eventDirGlob
    default: C:\Windows\system32\winevt\logs\
  - name: adminLog
    default: Microsoft-Windows-Dhcp-Client%4Admin.evtx

  - name: operationalLog
    default: Microsoft-Windows-Dhcp-Client%4Operational.evtx

  - name: accessor
    default: file

sources:
  - name: RejectedDHCP
    queries:
      - |
        LET files = SELECT * FROM glob(
            globs=eventDirGlob + adminLog,
            accessor=accessor)
      - |
        SELECT Time AS _Time,
               timestamp(epoch=Time) As Timestamp,
               Computer, MAC, ClientIP, DHCPServer, Type FROM foreach(
           row=files,
           query={
              SELECT System.TimeCreated.SystemTime as Time,
                     System.Computer AS Computer,
                     format(format="%x:%x:%x:%x:%x:%x", args=[EventData.HWAddress]) AS MAC,
                     ip(netaddr4_le=EventData.Address1) AS ClientIP,
                     ip(netaddr4_le=EventData.Address2) AS DHCPServer,
                     "Lease Rejected" AS Type
              FROM parse_evtx(filename=FullPath, accessor=accessor)
              WHERE System.EventID.Value = 1002
           })

  - name: AssignedDHCP
    queries:
      - |
        LET files = SELECT * FROM glob(
            globs=eventDirGlob + operationalLog,
            accessor=accessor)
      - |
        SELECT Time AS _Time,
               timestamp(epoch=Time) As Timestamp,
               Computer, MAC, ClientIP, DHCPServer, Type FROM foreach(
           row=files,
           query={
              SELECT System.TimeCreated.SystemTime as Time,
                     System.Computer AS Computer,
                     EventData.InterfaceGuid AS MAC,
                     ip(netaddr4_le=EventData.Address1) AS ClientIP,
                     ip(netaddr4_le=EventData.Address2) AS DHCPServer,
                     "Lease Assigned" AS Type
              FROM parse_evtx(filename=FullPath, accessor=accessor)
              WHERE System.EventID.Value = 60000
           })


reports:
  - type: CLIENT
    template: |
      Evidence of DHCP assigned IP addresses
      ======================================

      {{ .Description }}

      {{ define "assigned_dhcp" }}
            SELECT Computer, ClientIP,
                   count(items=Timestamp) AS Total,
                   enumerate(items=Timestamp) AS Times
            FROM source(source='AssignedDHCP')
            GROUP BY ClientIP
      {{ end }}
      {{ define "rejected_dhcp" }}
            SELECT Computer, ClientIP,
                   count(items=Timestamp) AS Total,
                   enumerate(items=Timestamp) AS Times
            FROM source(source='RejectedDHCP')
            GROUP BY ClientIP
      {{ end }}

      {{ $assigned := Query "assigned_dhcp"}}
      {{ if $assigned }}
      ## Operational logs

      This machine has DHCP operational logging enabled. We therefore
      can see complete references to all granted leases:
        {{ Table $assigned }}

      ## Timeline

      {{ Query "SELECT _Time * 1000, ClientIP FROM source(source='AssignedDHCP')" | Timeline }}

      {{ end }}

      ## Admin logs

      The admin logs show errors with DHCP lease requests. Typically
      rejected leases indicate that the machine held a least on a IP
      address in the past, but this lease is invalid for its current
      environment. For example, the machine has been moved to a
      different network.

      {{ Query "rejected_dhcp" | Table }}

      {{ Query "SELECT _Time * 1000, ClientIP FROM source(source='RejectedDHCP')" | Timeline }}
```
   {{% /expand %}}

## Windows.EventLogs.Kerbroasting

**Description**:
This Artifact will return all successful Kerberos TGS Ticket events for
Service Accounts (SPN attribute) implemented with weak encryption. These
tickets are vulnerable to brute force attack and this event is an indicator
of a Kerbroasting attack.

**ATT&CK**: [T1208 - Kerbroasting](https://attack.mitre.org/techniques/T1208/)
Typical attacker methodology is to firstly request accounts in the domain
with SPN attributes, then request an insecure TGS ticket for brute forcing.
This attack is particularly effective as any domain credentials can be used
to implement the attack and service accounts often have elevated privileges.
Kerbroasting can be used for privilege escalation or persistence by adding a
SPN attribute to an unexpected account.

**Reference**: [The Art of Detecting Kerberoast Attacks](https://www.trustedsec.com/2018/05/art_of_kerberoast/)
**Log Source**: Windows Security Event Log (Domain Controllers)
**Event ID**: 4769
**Status**: 0x0 (Audit Success)
**Ticket Encryption**: 0x17 (RC4)
**Service Name**: NOT krbtgt or NOT a system account (account name ends in $)
**TargetUserName**: NOT a system account (*$@*)


Monitor and alert on unusual events with these conditions from an unexpected
IP.
Note: There are potential false positives so whitelist normal source IPs and
manage risk of insecure ticket generation.


Arg|Default|Description
---|------|-----------
eventLog|C:\\Windows\\system32\\winevt\\logs\\Security.evtx|

{{% expand  "View Artifact Source" %}}


```
name: Windows.EventLogs.Kerbroasting
description: |
  **Description**:
  This Artifact will return all successful Kerberos TGS Ticket events for
  Service Accounts (SPN attribute) implemented with weak encryption. These
  tickets are vulnerable to brute force attack and this event is an indicator
  of a Kerbroasting attack.

  **ATT&CK**: [T1208 - Kerbroasting](https://attack.mitre.org/techniques/T1208/)
  Typical attacker methodology is to firstly request accounts in the domain
  with SPN attributes, then request an insecure TGS ticket for brute forcing.
  This attack is particularly effective as any domain credentials can be used
  to implement the attack and service accounts often have elevated privileges.
  Kerbroasting can be used for privilege escalation or persistence by adding a
  SPN attribute to an unexpected account.

  **Reference**: [The Art of Detecting Kerberoast Attacks](https://www.trustedsec.com/2018/05/art_of_kerberoast/)
  **Log Source**: Windows Security Event Log (Domain Controllers)
  **Event ID**: 4769
  **Status**: 0x0 (Audit Success)
  **Ticket Encryption**: 0x17 (RC4)
  **Service Name**: NOT krbtgt or NOT a system account (account name ends in $)
  **TargetUserName**: NOT a system account (*$@*)


  Monitor and alert on unusual events with these conditions from an unexpected
  IP.
  Note: There are potential false positives so whitelist normal source IPs and
  manage risk of insecure ticket generation.


author: Matt Green - @mgreen27

parameters:
  - name: eventLog
    default: C:\Windows\system32\winevt\logs\Security.evtx

sources:
  - name: Kerbroasting
    queries:
      - LET files = SELECT * FROM glob(globs=eventLog)

      - SELECT timestamp(epoch=System.TimeCreated.SystemTime) As EventTime,
              System.EventID.Value as EventID,
              System.Computer as Computer,
              EventData.ServiceName as ServiceName,
              EventData.ServiceSid as ServiceSid,
              EventData.TargetUserName as TargetUserName,
              "0x" + format(format="%x", args=EventData.Status) as Status,
              EventData.TargetDomainName as TargetDomainName,
              "0x" + format(format="%x", args=EventData.TicketEncryptionType) as TicketEncryptionType,
              "0x" + format(format="%x", args=EventData.TicketOptions) as TicketOptions,
              EventData.TransmittedServices as TransmittedServices,
              EventData.IpAddress as IpAddress,
              EventData.IpPort as IpPort
        FROM foreach(
          row=files,
          query={
            SELECT *
            FROM parse_evtx(filename=FullPath)
            WHERE System.EventID.Value = 4769
                AND EventData.TicketEncryptionType = 23
                AND EventData.Status = 0
                AND NOT EventData.ServiceName =~ "krbtgt|\\$$"
                AND NOT EventData.TargetUserName =~ "\\$@"
        })

reports:
  - type: CLIENT
    template: |

      Kerbroasting: TGS Ticket events.
      ===============================

      {{ .Description }}
      {{ Query "SELECT EventTime, Computer, ServiceName, TargetUserName, TargetDomainName, IpAddress FROM source(source='Kerbroasting')" | Table }}

  - type: HUNT
    template: |

      Kerbroasting: TGS Ticket events.
      ===============================

      {{ .Description }}
      {{ Query "SELECT EventTime, Computer, ServiceName, TargetUserName, TargetDomainName, IpAddress FROM source(source='Kerbroasting')" | Table }}
```
   {{% /expand %}}

## Windows.EventLogs.PowershellScriptblock

This Artifact will search and extract ScriptBlock events (Event ID 4104) from 
Powershell-Operational Event Logs.

Powershell is commonly used by attackers accross all stages of the attack 
lifecycle. A valuable hunt is to search Scriptblock logs for signs of 
malicious content.

There are several parameter's availible for search leveraging regex. 
  - dateAfter enables search for events after this date.  
  - dateBefore enables search for events before this date.   
  - SearchStrings enables regex search over scriptblock text field.  
  - stringWhiteList enables a regex whitelist for scriptblock text field.  
  - pathWhitelist enables a regex whitelist for path of scriptblock. 
  - LogLevel enables searching on type of log. Default is Warning level 
    which is logged even if ScriptBlock logging is turned off when 
    suspicious keywords detected in Powershell interpreter.   


Arg|Default|Description
---|------|-----------
eventLog|C:\\Windows\\system32\\winevt\\logs\\Microsoft-Win ...|
dateAfter||search for events after this date. YYYY-MM-DDTmm:hh:ss Z
dateBefore||search for events before this date. YYYY-MM-DDTmm:hh:ss Z
searchStrings||regex search over scriptblock text field.
stringWhitelist||Regex of string to witelist
pathWhitelist||Regex of path to whitelist.
LogLevel|Warning|Log level. Warning is Powershell default bad keyword list.

{{% expand  "View Artifact Source" %}}


```
name: Windows.EventLogs.PowershellScriptblock
description: |
  This Artifact will search and extract ScriptBlock events (Event ID 4104) from 
  Powershell-Operational Event Logs.
  
  Powershell is commonly used by attackers accross all stages of the attack 
  lifecycle. A valuable hunt is to search Scriptblock logs for signs of 
  malicious content.
  
  There are several parameter's availible for search leveraging regex. 
    - dateAfter enables search for events after this date.  
    - dateBefore enables search for events before this date.   
    - SearchStrings enables regex search over scriptblock text field.  
    - stringWhiteList enables a regex whitelist for scriptblock text field.  
    - pathWhitelist enables a regex whitelist for path of scriptblock. 
    - LogLevel enables searching on type of log. Default is Warning level 
      which is logged even if ScriptBlock logging is turned off when 
      suspicious keywords detected in Powershell interpreter.   
  

author: Matt Green - @mgreen27

parameters:
  - name: eventLog
    default: C:\Windows\system32\winevt\logs\Microsoft-Windows-PowerShell%4Operational.evtx
  - name: dateAfter
    description: "search for events after this date. YYYY-MM-DDTmm:hh:ss Z"
    type: timestamp
  - name: dateBefore
    description: "search for events before this date. YYYY-MM-DDTmm:hh:ss Z"
    type: timestamp
  - name: searchStrings
    description: "regex search over scriptblock text field."
  - name: stringWhitelist
    description: "Regex of string to witelist"
  - name: pathWhitelist
    description: "Regex of path to whitelist."
    
  - name: LogLevel
    description: "Log level. Warning is Powershell default bad keyword list."
    type: choices
    default: Warning
    choices:
       - All
       - Warning
       - Verbose
  - name: LogLevelMap
    type: hidden
    default: |
      Choice,Regex
      All,"."
      Warning,"3"
      Verbose,"5"
      
      
sources:
  - name: PowershellScriptBlock
    queries:
      - LET time <= SELECT format(format="%v", args=Regex) as value
            FROM parse_csv(filename=LogLevelMap, accessor="data")
            WHERE Choice=LogLevel LIMIT 1
      - LET LogLevelRegex <= SELECT format(format="%v", args=Regex) as value
            FROM parse_csv(filename=LogLevelMap, accessor="data")
            WHERE Choice=LogLevel LIMIT 1
      - LET files = SELECT * FROM glob(
            globs=eventLog)
      - SELECT *
        FROM foreach(
          row=files,
          query={
            SELECT timestamp(epoch=System.TimeCreated.SystemTime) As EventTime,
              System.Computer as Computer,
              System.Security.UserID as SecurityID,
              EventData.Path as Path,
              EventData.ScriptBlockId as ScriptBlockId,
              EventData.ScriptBlockText as ScriptBlockText,
              System.EventRecordID as EventRecordID,
              System.Level as Level,
              System.Opcode as Opcode,
              System.Task as Task
            FROM parse_evtx(filename=FullPath)
            WHERE System.EventID.Value = 4104 and
                if(condition=dateAfter, then=EventTime > timestamp(string=dateAfter),
                 else=TRUE) and
                if(condition=dateBefore, then=EventTime < timestamp(string=dateBefore),
                 else=TRUE) and
                format(format="%d", args=System.Level) =~ LogLevelRegex.value[0] and
                if(condition=searchStrings, then=ScriptBlockText =~ searchStrings,
                 else=TRUE) and
                if(condition=stringWhitelist, then=not ScriptBlockText =~ stringWhitelist,
                 else=TRUE) and
                if(condition=pathWhitelist, then=not Path =~ pathWhitelist,
                 else=TRUE)
        })

reports:
  - type: HUNT
    template: |
      Powershell: Scriptblock
      =======================
      Powershell is commonly used by attackers accross all stages of the attack 
      lifecycle.  
      A valuable hunt is to search Scriptblock logs for signs of malicious 
      content. Stack ranking these events can provide valuable leads from which 
      to start an investigation.
      
      {{ Query "SELECT count(items=ScriptBlockText) as Count, ScriptBlockText FROM source(source='PowershellScriptBlock') GROUP BY ScriptBlockText ORDER BY Count"  | Table }}
      
```
   {{% /expand %}}

## Windows.EventLogs.ServiceCreationComspec


This Detection hts on the string "COMSPEC" (nocase) in Windows Service
Creation events. That is: EventID 7045 from the System event log. 

This detects many hack tools that leverage SCM based lateral movement 
including smbexec.


Arg|Default|Description
---|------|-----------
eventLog|C:\\Windows\\system32\\winevt\\logs\\System.evtx|
accessor|ntfs|

{{% expand  "View Artifact Source" %}}


```
name: Windows.EventLogs.ServiceCreationComspec
description: |

  This Detection hts on the string "COMSPEC" (nocase) in Windows Service
  Creation events. That is: EventID 7045 from the System event log. 

  This detects many hack tools that leverage SCM based lateral movement 
  including smbexec.

author: Matt Green - @mgreen27

parameters:
  - name: eventLog
    default: C:\Windows\system32\winevt\logs\System.evtx
  - name: accessor
    default: ntfs

sources:
  - name: ServiceCreation
    queries:
      - |
        LET files = SELECT * FROM glob(
            globs=eventLog,
            accessor=accessor)
      - |
        SELECT *
        FROM foreach(
          row=files,
          query={
            SELECT timestamp(epoch=System.TimeCreated.SystemTime) As EventTime,
              System.EventID.Value as EventID,
              System.Computer as Computer,
              System.Security.UserID as SecurityID,
              EventData.AccountName as ServiceAccount,
              EventData.ServiceName as ServiceName,
              EventData.ImagePath as ImagePath,
              EventData.ServiceType as ServiceType,
              EventData.StartType as StartType,
              System.EventRecordID as EventRecordID,
              System.Level as Level,
              System.Opcode as Opcode,
              System.Task as Task
            FROM parse_evtx(filename=FullPath, accessor=accessor)
            WHERE System.EventID.Value = 7045 and 
              EventData.ImagePath =~ "(?i)COMSPEC"
        })
```
   {{% /expand %}}

## Windows.Memory.Acquisition

Acquires a full memory image. We download winpmem and use it to
acquire a full memory image.

NOTE: This artifact usually takes a long time. You should increase
the default timeout to allow it to complete.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Memory.Acquisition
description: |
  Acquires a full memory image. We download winpmem and use it to
  acquire a full memory image.

  NOTE: This artifact usually takes a long time. You should increase
  the default timeout to allow it to complete.

sources:
  - queries:
      - SELECT * FROM foreach(
          row={
            SELECT FullPath, tempfile(data="X", extension=".aff4") AS Tempfile
            FROM Artifact.Windows.Utils.FetchBinary(
                ToolName="WinPmem",
                binaryURL=binaryURL)
          },
          query={
            SELECT Stdout, Stderr,
                   if(condition=Complete,
                      then=upload(file=Tempfile)) As Upload
            FROM execve(
               argv=[FullPath, "-dd", "-o", Tempfile, "-t", "-c", "snappy"],
               sep="\r\n")
        })
```
   {{% /expand %}}

## Windows.NTFS.I30

Carve the $I30 index stream for a directory.

This can reveal previously deleted files. Optionally upload the I30
stream to the server as well.


Arg|Default|Description
---|------|-----------
DirectoryGlobs|C:\\Users\\|

{{% expand  "View Artifact Source" %}}


```
name: Windows.NTFS.I30
description: |
  Carve the $I30 index stream for a directory.

  This can reveal previously deleted files. Optionally upload the I30
  stream to the server as well.

parameters:
 - name: DirectoryGlobs
   default: C:\Users\

precondition:
  SELECT * FROM info() where OS = 'windows'

sources:
  - name: UploadI30Streams
    queries:
       - LET inodes = SELECT FullPath, Data.mft AS MFT,
             parse_ntfs(device=FullPath, inode=Data.mft) AS MFTInfo
         FROM glob(globs=DirectoryGlobs, accessor="ntfs")
         WHERE IsDir

       - LET upload_streams = SELECT * FROM foreach(
            row=MFTInfo.Attributes,
            query={
              SELECT Type, TypeId, Id, Inode, Size, Name, FullPath,
                     upload(accessor="mft", file=MFTInfo.Device + Inode,
                            name=FullPath + "/" + Inode) AS IndexUpload
              FROM scope()
              WHERE Type =~ "INDEX_"
            })

       - SELECT * FROM foreach(row=inodes, query=upload_streams)

  - name: AnalyzeI30
    queries:
       - SELECT * FROM foreach(
           row=inodes,
           query={
             SELECT FullPath, Name, NameType, Size, AllocatedSize,
                    IsSlack, SlackOffset, Mtime, Atime, Ctime, Btime, MFTId
             FROM parse_ntfs_i30(device=MFTInfo.Device, inode=MFT)
           })
```
   {{% /expand %}}

## Windows.NTFS.MFT

This artifact scans the $MFT file on the host showing all files
within the MFT.  This is useful in order to try and recover deleted
files. Take the MFT ID of a file of interest and provide it to the
Windows.NTFS.Recover artifact.


Arg|Default|Description
---|------|-----------
MFTFilename|C:/$MFT|
Accessor|ntfs|
FilenameRegex|.|

{{% expand  "View Artifact Source" %}}


```
name: Windows.NTFS.MFT
description: |
  This artifact scans the $MFT file on the host showing all files
  within the MFT.  This is useful in order to try and recover deleted
  files. Take the MFT ID of a file of interest and provide it to the
  Windows.NTFS.Recover artifact.

parameters:
  - name: MFTFilename
    default: "C:/$MFT"

  - name: Accessor
    default: ntfs

  - name: FilenameRegex
    default: .

sources:
  - queries:
      - SELECT * FROM parse_mft(filename=MFTFilename, accessor=Accessor)
        WHERE FileName =~ FilenameRegex
```
   {{% /expand %}}

## Windows.NTFS.Recover

Attempt to recover deleted files.

This artifact uploads all streams from an MFTId. If the MFT entry is
not allocated there is a chance that the cluster that contain the
actual data of the file will be intact still on the disk. Therefore
this artifact can be used to attempt to recover a deleted file.

A common use is to recover deleted directory entries using the
Windows.NTFS.I30 artifact and identify MFT entries of interest. This
is artifact can be used to attempt to recover some data.


Arg|Default|Description
---|------|-----------
MFTId|81978|
Drive|\\\\.\\C:|

{{% expand  "View Artifact Source" %}}


```
name: Windows.NTFS.Recover
description: |
  Attempt to recover deleted files.

  This artifact uploads all streams from an MFTId. If the MFT entry is
  not allocated there is a chance that the cluster that contain the
  actual data of the file will be intact still on the disk. Therefore
  this artifact can be used to attempt to recover a deleted file.

  A common use is to recover deleted directory entries using the
  Windows.NTFS.I30 artifact and identify MFT entries of interest. This
  is artifact can be used to attempt to recover some data.

parameters:
 - name: MFTId
   default: 81978
 - name: Drive
   default: '\\.\C:'

precondition:
  SELECT * FROM info() where OS = 'windows'

sources:
  - name: Upload
    queries:
       - SELECT * FROM foreach(
            row=parse_ntfs(device=Drive, inode=MFTId).Attributes,
            query={
              SELECT Type, TypeId, Id, Inode, Size, Name, FullPath,
                     upload(accessor="mft", file=Drive + Inode,
                            name=FullPath + "/" + Inode) AS IndexUpload
              FROM scope()
            })
```
   {{% /expand %}}

## Windows.Network.ArpCache

Address resolution cache, both static and dynamic (from ARP, NDP).

Arg|Default|Description
---|------|-----------
wmiQuery|SELECT AddressFamily, Store, State, InterfaceIndex ...|
wmiNamespace|ROOT\\StandardCimv2|
kMapOfState|{\n "0": "Unreachable",\n "1": "Incomplete",\n "2" ...|

{{% expand  "View Artifact Source" %}}


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
   {{% /expand %}}

## Windows.Network.InterfaceAddresses

Network interfaces and relevant metadata.

{{% expand  "View Artifact Source" %}}


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
        SELECT Index, MTU, Name, HardwareAddr.String As HardwareAddr,
           Flags, Addrs.IP as IP, Addrs.Mask.String as Mask
        FROM flatten(query=interface_address)
```
   {{% /expand %}}

## Windows.Network.ListeningPorts

Processes with listening (bound) network sockets/ports.

{{% expand  "View Artifact Source" %}}


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
   {{% /expand %}}

## Windows.Network.Netstat

Show information about open sockets. On windows the time when the
socket was first bound is also shown.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Network.Netstat
description: |
  Show information about open sockets. On windows the time when the
  socket was first bound is also shown.

sources:
- precondition: SELECT OS From info() where OS = 'windows'
  queries:
  - LET processes <= SELECT Name, Pid AS ProcPid FROM pslist()
  - SELECT Pid, {
        SELECT Name from processes
        WHERE Pid = ProcPid
      } AS Name, FamilyString as Family,
      TypeString as Type,
      Status,
      Laddr.IP, Laddr.Port,
      Raddr.IP, Raddr.Port,
      Timestamp
    FROM netstat()
```
   {{% /expand %}}

## Windows.Network.NetstatEnriched

NetstatEnhanced adds addtional data points to the Netstat artifact and
enables verbose search options.

Examples include: Process name and path, authenticode information or
network connection details.


Arg|Default|Description
---|------|-----------
IPRegex|.*|regex search over IP address fields.
PortRegex|.*|regex search over port fields.
Family|ALL|IP version family selection
Type|ALL|Transport protocol type selection
Status|ALL|TCP status selection
ProcessNameRegex|.*|regex search over source process name
ProcessPathRegex|.*|regex search over source process path
CommandLineRegex|.*|regex search over source process commandline
HashRegex|.*|regex search over source process hash
UsernameRegex|.*|regex search over source process user context
AuthenticodeSubjectRegex|.*|regex search over source Authenticode Subject
AuthenticodeIssuerRegex|.*|regex search over source Authenticode Issuer
AuthenticodeVerified|ALL|Authenticode signiture selection

{{% expand  "View Artifact Source" %}}


```
name: Windows.Network.NetstatEnriched
description: |
  NetstatEnhanced adds addtional data points to the Netstat artifact and
  enables verbose search options.

  Examples include: Process name and path, authenticode information or
  network connection details.

author: "Matthew Green - @mgreen27"

precondition: SELECT OS From info() where OS = 'windows'

parameters:
  - name: IPRegex
    description: "regex search over IP address fields."
    default:  ".*"
  - name: PortRegex
    description: "regex search over port fields."
    default: ".*"

  - name: Family
    description: "IP version family selection"
    type: choices
    default: ALL
    choices:
       - ALL
       - IPv4
       - IPv6
  - name: FamilyMap
    type: hidden
    default: |
      Choice,Regex
      ALL,".*"
      IPv4,"^IPv4$"
      IPv6,"^IPv6$"

  - name: Type
    description: "Transport protocol type selection"
    type: choices
    default: ALL
    choices:
       - ALL
       - TCP
       - UDP
  - name: TypeMap
    type: hidden
    default: |
      Choice,Regex
      ALL,".*"
      TCP,"^TCP$"
      UDP,"^UDP$"

  - name: Status
    description: "TCP status selection"
    type: choices
    default: ALL
    choices:
       - ALL
       - ESTABLISHED
       - LISTENING
       - OTHER
  - name: StatusMap
    type: hidden
    default: |
      Choice,Regex
      ALL,".*"
      ESTABLISHED,"^ESTAB$"
      LISTENING,"^LISTEN$"
      OTHER,"CLOS|SENT|RCVD|LAST|WAIT|DELETE"

  - name: ProcessNameRegex
    description: "regex search over source process name"
    default: ".*"
  - name: ProcessPathRegex
    description: "regex search over source process path"
    default: ".*"
  - name: CommandLineRegex
    description: "regex search over source process commandline"
    default: ".*"
  - name: HashRegex
    description: "regex search over source process hash"
    default: ".*"
  - name: UsernameRegex
    description: "regex search over source process user context"
    default: ".*"
  - name: AuthenticodeSubjectRegex
    description: "regex search over source Authenticode Subject"
    default: ".*"
  - name: AuthenticodeIssuerRegex
    description: "regex search over source Authenticode Issuer"
    default: ".*"
  - name: AuthenticodeVerified
    description: "Authenticode signiture selection"
    type: choices
    default: ALL
    choices:
       - ALL
       - TRUSTED
       - UNSIGNED
       - NOT TRUSTED
  - name: AuthenticodeVerifiedMap
    type: hidden
    default: |
      Choice,Regex
      ALL,".*"
      TRUSTED,"^trusted$"
      UNSIGNED,"^unsigned$"
      NOT TRUSTED,"unsigned|disallowed|untrusted|error"

sources:
  - name: Netstat
    queries:
      - LET VerifiedRegex <= SELECT Regex
            FROM parse_csv(filename=AuthenticodeVerifiedMap, accessor="data")
            WHERE Choice=AuthenticodeVerified LIMIT 1
      - LET StatusRegex <= SELECT Regex
            FROM parse_csv(filename=StatusMap, accessor="data")
            WHERE Choice=Status LIMIT 1
      - LET FamilyRegex <= SELECT Regex
            FROM parse_csv(filename=FamilyMap, accessor="data")
            WHERE Choice=Family LIMIT 1
      - LET TypeRegex <= SELECT Regex
            FROM parse_csv(filename=TypeMap, accessor="data")
            WHERE Choice=Type LIMIT 1

      - LET process <= SELECT Pid as PsId,
            Ppid,
            Name,
            CommandLine,
            Exe,
            Hash,
            Authenticode,
            Username
        FROM Artifact.Windows.System.Pslist()
        WHERE Name =~ ProcessNameRegex

      - SELECT Pid,
            { SELECT Ppid FROM process WHERE PsId = Pid } as Ppid,
            { SELECT Name FROM process WHERE PsId = Pid } as Name,
            { SELECT Exe FROM process WHERE PsId = Pid } as Path,
            { SELECT CommandLine FROM process WHERE PsId = Pid } as CommandLine,
            { SELECT Hash FROM process WHERE PsId = Pid } as Hash,
            { SELECT Username FROM process WHERE PsId = Pid } as Username,
            { SELECT Authenticode FROM process WHERE PsId = Pid } as Authenticode,
            FamilyString as Family,
            TypeString as Type,
            Status,
            Laddr.IP, Laddr.Port,
            Raddr.IP, Raddr.Port,
            Timestamp
        FROM netstat()
        WHERE Path =~ ProcessPathRegex
            and CommandLine =~ CommandLineRegex
            and Username =~ UsernameRegex
            and ( Hash.MD5 =~ HashRegex
              or Hash.SHA1 =~ HashRegex
              or Hash.SHA256 =~ HashRegex
              or not Hash )
            and ( Authenticode.IssuerName =~ AuthenticodeIssuerRegex or not Authenticode )
            and ( Authenticode.SubjectName =~ AuthenticodeSubjectRegex or not Authenticode )
            and ( Authenticode.Trusted =~ VerifiedRegex.Regex[0] or not Authenticode )
            and Status =~ StatusRegex.Regex[0]
            and Family =~ FamilyRegex.Regex[0]
            and Type =~ TypeRegex.Regex[0]
            and ( format(format="%v", args=Laddr.IP) =~ IPRegex
                or format(format="%v", args=Raddr.IP) =~ IPRegex )
            and ( format(format="%v", args=Laddr.Port) =~ PortRegex
                or format(format="%v", args=Raddr.Port) =~ PortRegex )
```
   {{% /expand %}}

## Windows.Packs.Autoexec

Aggregate of executables that will automatically execute on the
target machine. This is an amalgamation of other tables like
services, scheduled_tasks, startup_items and more.


{{% expand  "View Artifact Source" %}}


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
   {{% /expand %}}

## Windows.Packs.LateralMovement

Detect evidence of lateral movement.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Packs.LateralMovement
description: |
  Detect evidence of lateral movement.

precondition: SELECT OS From info() where OS = 'windows'

reference:
  - https://digital-forensics.sans.org/media/SANS_Poster_2018_Hunt_Evil_FINAL.pdf

sources:
  - name: AlternateLogon
    queries:
      - SELECT * FROM Artifact.Windows.EventLogs.AlternateLogon()
  - name: WMIC
    queries:
      - SELECT * FROM Artifact.Windows.Forensics.Prefetch()
        WHERE Executable =~ "wmic.exe"
  - name: ShimCache
    queries:
      - SELECT * FROM Artifact.Windows.Registry.AppCompatCache()
        WHERE Name =~ "wmic.exe"
  - name: BAM
    queries:
      - SELECT * FROM Artifact.Windows.Forensics.Bam()
        WHERE Binary =~ "wmic.exe"
  - name: AmCache
    queries:
      - SELECT * FROM Artifact.Windows.System.Amcache()
        WHERE Binary =~ "wmic.exe"
```
   {{% /expand %}}

## Windows.Packs.Persistence

This artifact pack collects various persistence mechanisms in Windows.


{{% expand  "View Artifact Source" %}}


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
      - |
        SELECT * FROM Artifact.Windows.Persistence.PermanentWMIEvents()

  - name: Startup Items
    description: |
      {{ DocFrom "Windows.Sys.StartupItems" }}

    queries:
      - |
        SELECT * FROM Artifact.Windows.Sys.StartupItems()

  - name: Debug Bootstraping
    description: |
      {{ DocFrom "Windows.Persistence.Debug" }}

      If there are any rows in the table below then executing the
      program will also launch the program listed under the Debugger
      column.

    queries:
      - SELECT * FROM Artifact.Windows.Persistence.Debug()
```
   {{% /expand %}}

## Windows.Registry.AppCompatCache

Parses the system's app compatibility cache.


Arg|Default|Description
---|------|-----------
AppCompatCacheKey|HKEY_LOCAL_MACHINE/System/ControlSet*/Control/Sess ...|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Registry.AppCompatCache
description: |
  Parses the system's app compatibility cache.

parameters:
  - name: AppCompatCacheKey
    default: HKEY_LOCAL_MACHINE/System/ControlSet*/Control/Session Manager/AppCompatCache/AppCompatCache

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - LET AppCompatKeys = SELECT * FROM glob(globs=AppCompatCacheKey, accessor='reg')
      - SELECT * FROM foreach(
          row={
              SELECT Filename, Data FROM read_file(
                  filenames=AppCompatKeys.FullPath, accessor='reg')
          }, query={
              SELECT Filename AS Key, name as Name, epoch, time
              FROM appcompatcache(value=Data)
        }) WHERE epoch < 2000000000
```
   {{% /expand %}}

## Windows.Registry.EnableUnsafeClientMailRules

Checks for Outlook EnableUnsafeClientMailRules = 1 (turned on).
This registry key enables execution from Outlook inbox rules which can be used as a persistence mechanism.
Microsoft has released a patch to disable execution but attackers can reenable by changing this value to 1.

HKEY_USERS\*\Software\Microsoft\Office\*\Outlook\Security\EnableUnsafeClientMailRules = 0 (expected)
https://support.microsoft.com/en-us/help/3191893/how-to-control-the-rule-actions-to-start-an-application-or-run-a-macro


Arg|Default|Description
---|------|-----------
KeyGlob|Software\\Microsoft\\Office\\*\\Outlook\\Security\ ...|
userRegex|.|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Registry.EnableUnsafeClientMailRules
description: |
  Checks for Outlook EnableUnsafeClientMailRules = 1 (turned on).
  This registry key enables execution from Outlook inbox rules which can be used as a persistence mechanism.
  Microsoft has released a patch to disable execution but attackers can reenable by changing this value to 1.

  HKEY_USERS\*\Software\Microsoft\Office\*\Outlook\Security\EnableUnsafeClientMailRules = 0 (expected)
  https://support.microsoft.com/en-us/help/3191893/how-to-control-the-rule-actions-to-start-an-application-or-run-a-macro

author: "@mgreen27"

precondition: SELECT OS From info() where OS = 'windows'

parameters:
   - name: KeyGlob
     default: Software\Microsoft\Office\*\Outlook\Security\
   - name: userRegex
     default: .

sources:
  - queries:
      - |
        LET UserProfiles = Select Name as Username,
            {
                SELECT FullPath FROM glob(globs=expand(path=Directory) + "//NTUSER.DAT", accessor="file")
            } as NTUser,
            expand(path=Directory) as Directory
        FROM Artifact.Windows.Sys.Users()
        WHERE Directory and NTUser and Name =~ userRegex
      - |
         SELECT * FROM foreach(
           row={
              SELECT Username, NTUser FROM UserProfiles
           },
           query={
              SELECT Username,
                NTUser as Userhive,
                url(parse=key.FullPath).fragment as Key,
                timestamp(epoch=key.Mtime.Sec) AS LastModified,
                EnableUnsafeClientMailRules,
                OutlookSecureTempFolder
              FROM read_reg_key(
                 globs=url(scheme="ntfs",
                    path=FullPath,
                    fragment=KeyGlob).String,
                 accessor="raw_reg")
              WHERE EnableUnsafeClientMailRules = 1
           })
```
   {{% /expand %}}

## Windows.Registry.EnabledMacro

Checks for Registry key indicating macro was enabled by user.

HKEY_USERS\*\Software\Microsoft\Office\*\Security\Trusted Documents\TrustRecords reg keys for values ending in FFFFFF7F
http://az4n6.blogspot.com/2016/02/more-on-trust-records-macros-and.html


Arg|Default|Description
---|------|-----------
KeyGlob|Software\\Microsoft\\Office\\*\\*\\Security\\Trust ...|
userRegex|.|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Registry.EnabledMacro
description: |
  Checks for Registry key indicating macro was enabled by user.

  HKEY_USERS\*\Software\Microsoft\Office\*\Security\Trusted Documents\TrustRecords reg keys for values ending in FFFFFF7F
  http://az4n6.blogspot.com/2016/02/more-on-trust-records-macros-and.html

author: "@mgreen27"

precondition: SELECT OS From info() where OS = 'windows'

parameters:
 - name: KeyGlob
   default: Software\Microsoft\Office\*\*\Security\Trusted Documents\TrustRecords\*
 - name: userRegex
   default: .

sources:
 - queries:
      - |
        LET UserProfiles = Select Name as Username,
            {
                SELECT FullPath FROM glob(globs=expand(path=Directory) + "//NTUSER.DAT", accessor="file")
            } as NTUser,
            expand(path=Directory) as Directory
        FROM Artifact.Windows.Sys.Users()
        WHERE Directory and NTUser and Name =~ userRegex
      - |
        SELECT * FROM foreach(
          row={
            SELECT Username,NTUser FROM UserProfiles
          },
          query={
            SELECT Name as Document,
              Username,
              NTUser as Userhive,
              dirname(path=url(parse=FullPath).fragment) as Key,
              timestamp(epoch=Mtime.Sec) AS LastModified
            FROM glob(
              globs=url(scheme="ntfs",
                path=NTUser,
                fragment=KeyGlob).String,
              accessor="raw_reg")
            WHERE Data.type = "REG_BINARY" and encode(string=Data.value, type="hex") =~ "ffffff7f$"
          })
```
   {{% /expand %}}

## Windows.Registry.MountPoints2

This detection will collect any items in the MountPoints2 registry key.
With a "$" in the share path. This key will store all remotely mapped
drives unless removed so is a great hunt for simple admin $ mapping based
lateral movement.


Arg|Default|Description
---|------|-----------
KeyGlob|Software\\Microsoft\\Windows\\CurrentVersion\\Expl ...|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Registry.MountPoints2
description: |
    This detection will collect any items in the MountPoints2 registry key.
    With a "$" in the share path. This key will store all remotely mapped
    drives unless removed so is a great hunt for simple admin $ mapping based
    lateral movement.
    
author: Matt Green - @mgreen27

precondition: SELECT OS From info() where OS = 'windows'

parameters:
 - name: KeyGlob
   default: Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\*

sources:
 - queries:
     - |
        SELECT regex_replace(source=basename(path=url(parse=FullPath).Fragment), 
          re="#", replace="\\") as MountPoint,
          timestamp(epoch=Mtime) as ModifiedTime,
          Username,
          url(parse=FullPath).Path as Hive,
          url(parse=FullPath).Fragment as Key
        FROM Artifact.Windows.Registry.NTUser(KeyGlob=KeyGlob)
        WHERE FullPath =~ "\\$"
```
   {{% /expand %}}

## Windows.Registry.NTUser

This artifact searches for keys or values within the user's
NTUser.dat registry hives.

When a user logs into a windows machine the system creates their own
"profile" which consists of a registry hive mapped into the
HKEY_USERS hive. This hive file is locked as long as the user is
logged in. If the user is not logged in, the file is not mapped at
all.

This artifact bypasses the locking mechanism by parsing the raw NTFS
filesystem to recover the registry hives. We then parse the registry
hives to search for the glob provided.

This artifact is designed to be reused by other artifacts that need
to access user data.

{{% notice note %}}

  Any artifacts that look into the HKEY_USERS registry hive should
  be using the `Windows.Registry.NTUser` artifact instead of
  accessing the hive via the API. The API only makes the currently
  logged in users available in that hive and so if we rely on the
  windows API we will likely miss any settings for users not
  currently logged on.

{{% /notice %}}


Arg|Default|Description
---|------|-----------
KeyGlob|Software\\Microsoft\\Windows\\CurrentVersion\\Expl ...|
userRegex|.|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Registry.NTUser
description: |
  This artifact searches for keys or values within the user's
  NTUser.dat registry hives.

  When a user logs into a windows machine the system creates their own
  "profile" which consists of a registry hive mapped into the
  HKEY_USERS hive. This hive file is locked as long as the user is
  logged in. If the user is not logged in, the file is not mapped at
  all.

  This artifact bypasses the locking mechanism by parsing the raw NTFS
  filesystem to recover the registry hives. We then parse the registry
  hives to search for the glob provided.

  This artifact is designed to be reused by other artifacts that need
  to access user data.

  {{% notice note %}}

    Any artifacts that look into the HKEY_USERS registry hive should
    be using the `Windows.Registry.NTUser` artifact instead of
    accessing the hive via the API. The API only makes the currently
    logged in users available in that hive and so if we rely on the
    windows API we will likely miss any settings for users not
    currently logged on.

  {{% /notice %}}

precondition: SELECT OS From info() where OS = 'windows'

parameters:
 - name: KeyGlob
   default: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\**
 - name: userRegex
   default: .

sources:
 - queries:
     - |
        LET UserProfiles = SELECT Uid,
            Gid,
            Name as Username,
            Description,
            UUID,
            {
                SELECT FullPath FROM glob(globs=expand(path=Directory) + "//NTUSER.DAT", accessor="file")
            } as FullPath,
            expand(path=Directory) as Directory
        FROM Artifact.Windows.Sys.Users()
        WHERE Directory and FullPath AND Name =~ userRegex
     - |
       SELECT * FROM foreach(
            row={
                SELECT * FROM UserProfiles
            },
            query={
                SELECT FullPath, Data, Mtime.Sec AS Mtime, Username, Description, Uid, Gid, UUID, Directory
                FROM glob(
                    globs=url(scheme="ntfs",
                    path=FullPath,
                    fragment=KeyGlob).String,
                    accessor="raw_reg")
            })
```
   {{% /expand %}}

## Windows.Registry.NTUser.Upload

This artifact collects all the user's NTUser.dat registry hives.

When a user logs into a windows machine the system creates their own
"profile" which consists of a registry hive mapped into the
HKEY_USERS hive. This hive file is locked as long as the user is
logged in.

This artifact bypasses the locking mechanism by extracting the
registry hives using raw NTFS parsing. We then just upload all hives
to the server.


Arg|Default|Description
---|------|-----------
userRegex|.|

{{% expand  "View Artifact Source" %}}


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

parameters:
  - name: userRegex
    default: .

sources:
  - precondition: |
      SELECT OS From info() where OS = 'windows'
    queries:
      - |
        LET users = SELECT Name, Directory as HomeDir
            FROM Artifact.Windows.Sys.Users()
            WHERE Directory AND Name =~ userRegex

      - |
        SELECT upload(file=expand(path=HomeDir) + "\\ntuser.dat",
                      accessor="ntfs") as Upload
        FROM users
```
   {{% /expand %}}

## Windows.Registry.PortProxy

**Description**: 
This artifact will return any items in the Windows PortProxy service 
registry path. The most common configuration of this service is via the
lolbin netsh.exe; Metaspoit and other common attack tools also have 
configuration modules.

**Reference**: [Port Proxy detection]
(http://www.dfirnotes.net/portproxy_detection/)  

**ATT&CK**: [T1090 - Connection Proxy](https://attack.mitre.org/techniques/T1090/)  
Adversaries may use a connection proxy to direct network traffic between
systems or act as an intermediary for network communications to a command 
and control server to avoid direct connections to their infrastructure.


Arg|Default|Description
---|------|-----------
KeyGlob|HKEY_LOCAL_MACHINE\\SYSTEM\\*ControlSet*\\services ...|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Registry.PortProxy
description: |
    **Description**: 
    This artifact will return any items in the Windows PortProxy service 
    registry path. The most common configuration of this service is via the
    lolbin netsh.exe; Metaspoit and other common attack tools also have 
    configuration modules.

    **Reference**: [Port Proxy detection]
    (http://www.dfirnotes.net/portproxy_detection/)  

    **ATT&CK**: [T1090 - Connection Proxy](https://attack.mitre.org/techniques/T1090/)  
    Adversaries may use a connection proxy to direct network traffic between
    systems or act as an intermediary for network communications to a command 
    and control server to avoid direct connections to their infrastructure.
    
author: Matt Green - @mgreen27

precondition: SELECT OS From info() where OS = 'windows'

parameters:
 - name: KeyGlob
   default: HKEY_LOCAL_MACHINE\SYSTEM\*ControlSet*\services\PortProxy\**

sources:
 - name: PortProxy
   queries:
     - SELECT FullPath,
         basename(path=dirname(path=dirname(path=FullPath))) as ProxyType,
         basename(path=dirname(path=FullPath)) as Protocol,
         regex_replace(source=basename(path=FullPath),re="/",replace=":") as Listening,
         regex_replace(source=Data.value,re="/",replace=":") as Destination,
         timestamp(epoch=Mtime.sec) as ModifiedTime,
         Type
       FROM glob(globs=KeyGlob, accessor="reg")
       WHERE Type


reports:
  - type: CLIENT
    template: |

      Port Forwarding: PortProxy
      ==========================
      {{ .Description }}
      
      {{ define "report" }}
         LET report = SELECT Protocol, 
            ProxyType, 
            Listening, 
            Destination, 
            ModifiedTime,
            ProxyType + Protocol + Listening + Destination as ServiceKey
         FROM source(source='PortProxy')
         GROUP BY ServiceKey
      {{ end }}
      
      {{ Query "report"  "SELECT ProxyType, Protocol, Listening, Destination, ModifiedTime FROM report" | Table }}
      
  - type: HUNT
    template: |

      Port Forwarding: PortProxy
      ==========================
      {{ .Description }}
      
      {{ define "report" }}
         LET report = SELECT Fqdn,
            Protocol, 
            ProxyType, 
            Listening, 
            Destination, 
            ModifiedTime,
            ProxyType + Protocol + Listening + Destination as ServiceKey
         FROM source(source='PortProxy')
         GROUP BY ServiceKey
      {{ end }}
      
      {{ Query "report"  "SELECT Fqdn, ProxyType, Protocol, Listening, Destination, ModifiedTime FROM report" | Table }}
```
   {{% /expand %}}

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
userRegex|.|

{{% expand  "View Artifact Source" %}}


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
   - name: userRegex
     default: .

sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'

    queries:
    - |
      LET users <= SELECT Name, UUID
          FROM Artifact.Windows.Sys.Users()
          WHERE Name =~ userRegex
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
   {{% /expand %}}

## Windows.Registry.UserAssist

Windows systems maintain a set of keys in the registry database
(UserAssist keys) to keep track of programs that executed. The
number of executions and last execution date and time are available
in these keys.

The information within the binary UserAssist values contains only
statistical data on the applications launched by the user via
Windows Explorer. Programs launched via the command­line (cmd.exe)
do not appear in these registry keys.

From a forensics perspective, being able to decode this information
can be very useful.


Arg|Default|Description
---|------|-----------
UserFilter||If specified we filter by this user ID.
ExecutionTimeAfter||If specified only show executions after this time.
UserAssistKey|Software\\Microsoft\\Windows\\CurrentVersion\\Expl ...|
userAssistProfile|{\n  "Win10": [0, {\n    "NumberOfExecutions": [4, ...|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Registry.UserAssist
description: |
  Windows systems maintain a set of keys in the registry database
  (UserAssist keys) to keep track of programs that executed. The
  number of executions and last execution date and time are available
  in these keys.

  The information within the binary UserAssist values contains only
  statistical data on the applications launched by the user via
  Windows Explorer. Programs launched via the command­line (cmd.exe)
  do not appear in these registry keys.

  From a forensics perspective, being able to decode this information
  can be very useful.

reference:
  - https://www.aldeid.com/wiki/Windows-userassist-keys

precondition: SELECT OS From info() where OS = 'windows'

parameters:
  - name: UserFilter
    default: ""
    description: If specified we filter by this user ID.

  - name: ExecutionTimeAfter
    default: ""
    type: timestamp
    description: If specified only show executions after this time.

  - name: UserAssistKey
    default: Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*\Count\*

  - name: userAssistProfile
    default: |
      {
        "Win10": [0, {
          "NumberOfExecutions": [4, ["unsigned int"]],
          "LastExecution": [60, ["unsigned long long"]]
        }]
      }

sources:
  - queries:
      - LET TMP = SELECT rot13(string=regex_replace(
             source=url(parse=FullPath).Fragment,
             re="^.+/Count/",
             replace="")) AS Name,
             binary_parse(
               string=Data.value,
               profile=userAssistProfile,
               target="Win10"
             ) As UserAssist,
             parse_string_with_regex(
               string=FullPath,
               regex="Users/(?P<User>[^/]+)/NTUSER").User AS User
        FROM Artifact.Windows.Registry.NTUser(KeyGlob=UserAssistKey)
      - LET UserAssist = SELECT Name,
               User,
               timestamp(
                  winfiletime=UserAssist.LastExecution.AsInteger) As LastExecution,
               timestamp(
                  winfiletime=UserAssist.LastExecution.AsInteger).Unix AS LastExecutionTS,
               UserAssist.NumberOfExecutions.AsInteger AS NumberOfExecutions
        FROM TMP
      - LET A1 = SELECT * FROM if(
          condition=UserFilter,
          then={
            SELECT * FROM UserAssist WHERE User =~ UserFilter
          }, else=UserAssist)
      - SELECT * FROM if(
          condition=ExecutionTimeAfter,
          then={
            SELECT * FROM A1 WHERE LastExecutionTS > ExecutionTimeAfter
          }, else=A1)
```
   {{% /expand %}}

## Windows.Remediation.ScheduledTasks

Remove malicious task from the Windows scheduled task list.

Danger: You need to make sure to test this before running.


Arg|Default|Description
---|------|-----------
script|Unregister-ScheduledTask -TaskName "%s" -Confirm:$ ...|
TasksPath|c:/Windows/System32/Tasks/**|
ArgumentRegex|ThisIsAUniqueName|
CommandRegEx|ThisIsAUniqueName|
ReallyDoIt|N|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Remediation.ScheduledTasks
description: |
   Remove malicious task from the Windows scheduled task list.

   Danger: You need to make sure to test this before running.

type: CLIENT

parameters:
 - name: script
   default: |
     Unregister-ScheduledTask -TaskName "%s" -Confirm:$false
 - name: TasksPath
   default: c:/Windows/System32/Tasks/**
 - name: ArgumentRegex
   default: ThisIsAUniqueName
 - name: CommandRegEx
   default: ThisIsAUniqueName
 - name: ReallyDoIt
   type: bool
   default: N

sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'

    queries:
    - LET task_paths = SELECT Name, FullPath
        FROM glob(globs=TasksPath)
        WHERE NOT IsDir

    - LET parse_task = select FullPath, Name, parse_xml(
               accessor='data',
               file=regex_replace(
                    source=utf16(string=Data),
                    re='<[?].+?>',
                    replace='')) AS XML
       FROM read_file(filenames=FullPath)

    - LET tasks = SELECT FullPath, Name,
            XML.Task.Actions.Exec.Command as Command,
            XML.Task.Actions.Exec.Arguments as Arguments,
            XML.Task.Actions.ComHandler.ClassId as ComHandler,
            XML.Task.Principals.Principal.UserId as UserId,
            XML as _XML
      FROM foreach(row=task_paths, query=parse_task)
      WHERE (Arguments =~ ArgumentRegex AND Command =~ CommandRegEx)  AND
      log(message="Removing task " + Name)

    - SELECT * FROM foreach(row=tasks,
        query={
          SELECT * FROM if(condition= ReallyDoIt='Y',
            then={
              SELECT FullPath, Name, Command, Arguments, ComHandler, UserId, _XML
              FROM execve(argv=["powershell",
                 "-ExecutionPolicy", "Unrestricted", "-encodedCommand",
                    base64encode(string=utf16_encode(
                    string=format(format=script, args=[Name])))
              ])
            }, else={
              SELECT FullPath, Name, Command, Arguments, ComHandler, UserId, _XML
              FROM scope()
            })
        })
```
   {{% /expand %}}

## Windows.Search.FileFinder

Find files on the filesystem using the filename or content.


## Performance Note

This artifact can be quite expensive, especially if we search file
content. It will require opening each file and reading its entire
content. To minimize the impact on the endpoint we recommend this
artifact is collected with a rate limited way (about 20-50 ops per
second).

This artifact is useful in the following scenarios:

  * We need to locate all the places on our network where customer
    data has been copied.

  * We’ve identified malware in a data breach, named using short
    random strings in specific folders and need to search for other
    instances across the network.

  * We believe our user account credentials have been dumped and
    need to locate them.

  * We need to search for exposed credit card data to satisfy PCI
    requirements.

  * We have a sample of data that has been disclosed and need to
    locate other similar files


Arg|Default|Description
---|------|-----------
SearchFilesGlob|C:\\Users\\**|Use a glob to define the files that will be searched.
Keywords|None|A comma delimited list of strings to search for.
Use_Raw_NTFS|N|
Upload_File|N|
Calculate_Hash|N|
MoreRecentThan||
ModifiedBefore||

{{% expand  "View Artifact Source" %}}


```
name: Windows.Search.FileFinder
description: |
  Find files on the filesystem using the filename or content.


  ## Performance Note

  This artifact can be quite expensive, especially if we search file
  content. It will require opening each file and reading its entire
  content. To minimize the impact on the endpoint we recommend this
  artifact is collected with a rate limited way (about 20-50 ops per
  second).

  This artifact is useful in the following scenarios:

    * We need to locate all the places on our network where customer
      data has been copied.

    * We’ve identified malware in a data breach, named using short
      random strings in specific folders and need to search for other
      instances across the network.

    * We believe our user account credentials have been dumped and
      need to locate them.

    * We need to search for exposed credit card data to satisfy PCI
      requirements.

    * We have a sample of data that has been disclosed and need to
      locate other similar files


precondition:
  SELECT * FROM info() where OS = 'windows'

parameters:
  - name: SearchFilesGlob
    default: C:\Users\**
    description: Use a glob to define the files that will be searched.

  - name: Keywords
    default:
    description: A comma delimited list of strings to search for.

  - name: Use_Raw_NTFS
    default: N
    type: bool

  - name: Upload_File
    default: N
    type: bool

  - name: Calculate_Hash
    default: N
    type: bool

  - name: MoreRecentThan
    default: ""
    type: timestamp

  - name: ModifiedBefore
    default: ""
    type: timestamp


sources:
  - queries:
    - |
      LET file_search = SELECT FullPath,
               Sys.mft as Inode,
               Mode.String AS Mode, Size,
               Mtime.Sec AS Modified,
               timestamp(epoch=Atime.Sec) AS ATime,
               timestamp(epoch=Mtime.Sec) AS MTime,
               timestamp(epoch=Ctime.Sec) AS CTime, IsDir
        FROM glob(globs=SearchFilesGlob,
                  accessor=if(condition=Use_Raw_NTFS = "Y",
                              then="ntfs", else="file"))

    - |
      LET more_recent = SELECT * FROM if(
        condition=MoreRecentThan,
        then={
          SELECT * FROM file_search
          WHERE Modified > parse_float(string=MoreRecentThan)
        }, else=file_search)

    - |
      LET modified_before = SELECT * FROM if(
        condition=ModifiedBefore,
        then={
          SELECT * FROM more_recent
          WHERE Modified < parse_float(string=ModifiedBefore)
        }, else=more_recent)

    - |
      LET keyword_search = SELECT * FROM if(
        condition=Keywords,
        then={
          SELECT * FROM foreach(
            row={
               SELECT * FROM modified_before
               WHERE NOT IsDir
            },
            query={
               SELECT FullPath, Inode, Mode,
                      Size, Modified, ATime, MTime, CTime,
                      str(str=String.Data) As Keywords, IsDir

               FROM yara(files=FullPath,
                         key=Keywords,
                         rules="wide nocase ascii:"+Keywords,
                         accessor=if(condition=Use_Raw_NTFS = "Y",
                                          then="ntfs", else="file"))
            })
        }, else=modified_before)

    - |
      SELECT FullPath, Inode, Mode, Size, Modified, ATime,
             MTime, CTime, Keywords, IsDir,
               if(condition=(Upload_File = "Y" and NOT IsDir ),
                  then=upload(file=FullPath,
                              accessor=if(condition=Use_Raw_NTFS = "Y",
                                          then="ntfs", else="file"))) AS Upload,
               if(condition=(Calculate_Hash = "Y" and NOT IsDir ),
                  then=hash(path=FullPath,
                            accessor=if(condition=Use_Raw_NTFS = "Y",
                                        then="ntfs", else="file"))) AS Hash
      FROM keyword_search
```
   {{% /expand %}}

## Windows.Timeline.Prefetch

Windows keeps a cache of prefetch files. When an executable is run,
the system records properties about the executable to make it faster
to run next time. By parsing this information we are able to
determine when binaries are run in the past. On Windows10 we can see
the last 8 execution times and creation time (9 potential executions).  
  
This artifact is a timelined output version of the standard Prefetch 
artifact. There are several parameter's availible.  
  - dateAfter enables search for prefetch evidence after this date.  
  - dateBefore enables search for prefetch evidence before this date.   
  - binaryRegex enables to filter on binary name, e.g evil.exe.  
  - hashRegex enables to filter on prefetch hash.     


Arg|Default|Description
---|------|-----------
prefetchGlobs|C:\\Windows\\Prefetch\\*.pf|
dateAfter||search for events after this date. YYYY-MM-DDTmm:hh:ssZ
dateBefore||search for events before this date. YYYY-MM-DDTmm:hh:ssZ
binaryRegex||Regex of executable name.
hashRegex||Regex of prefetch hash.

{{% expand  "View Artifact Source" %}}


```
name: Windows.Timeline.Prefetch
description: |
  Windows keeps a cache of prefetch files. When an executable is run,
  the system records properties about the executable to make it faster
  to run next time. By parsing this information we are able to
  determine when binaries are run in the past. On Windows10 we can see
  the last 8 execution times and creation time (9 potential executions).  
    
  This artifact is a timelined output version of the standard Prefetch 
  artifact. There are several parameter's availible.  
    - dateAfter enables search for prefetch evidence after this date.  
    - dateBefore enables search for prefetch evidence before this date.   
    - binaryRegex enables to filter on binary name, e.g evil.exe.  
    - hashRegex enables to filter on prefetch hash.     

reference:
  - https://www.forensicswiki.org/wiki/Prefetch

author: matthew.green@cybereason.com

parameters:
    - name: prefetchGlobs
      default: C:\Windows\Prefetch\*.pf
    - name: dateAfter
      description: "search for events after this date. YYYY-MM-DDTmm:hh:ssZ"
      type: timestamp
    - name: dateBefore
      description: "search for events before this date. YYYY-MM-DDTmm:hh:ssZ"
      type: timestamp
    - name: binaryRegex
      description: "Regex of executable name."
    - name: hashRegex
      description: "Regex of prefetch hash."
      
precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - LET hostname <= SELECT Fqdn FROM info()
      - |
        // Parse prefetch files and apply non time filters
        LET pf <= SELECT * FROM foreach(
              row={
                 SELECT * FROM glob(globs=prefetchGlobs)
              },
              query={
                SELECT
                    Executable,
                    FileSize,
                    Hash,
                    Version,
                    LastRunTimes,
                    RunCount,
                    // FilesAccessed, 
                    FullPath, 
                    Name AS PrefetchFileName,
                    timestamp(epoch=Ctime.sec) as CreationTime,
                    timestamp(epoch=Mtime.sec) as ModificationTime
                 FROM prefetch(filename=FullPath)
                 WHERE  
                    if(condition=binaryRegex, then= Executable =~ binaryRegex,
                    else=TRUE) AND
                    if(condition=hashRegex, then= Hash =~ hashRegex,
                    else=TRUE)
              })
      - |
        // Flattern and filter on time. 
        LET executionTimes = SELECT * FROM flatten(
                query = { 
                    SELECT *,
                        FullPath as FilteredPath,
                        LastRunTimes as ExecutionTime
                    FROM pf 
                })
            WHERE 
                if(condition=dateAfter, then=ExecutionTime > timestamp(string=dateAfter),
                    else=TRUE) AND
                if(condition=dateBefore, then=ExecutionTime < timestamp(string=dateBefore),
                    else=TRUE)
      - |
        LET creationTimes = SELECT * FROM flatten(
                query = { 
                    SELECT *,
                        FullPath as FilteredPath,
                        CreationTime as ExecutionTime
                    FROM pf 
                    WHERE RunCount > 8
                })
            WHERE
                if(condition=dateAfter, then=ExecutionTime > timestamp(string=dateAfter),
                    else=TRUE) AND
                if(condition=dateBefore, then=ExecutionTime < timestamp(string=dateBefore),
                        else=TRUE)
            GROUP BY ExecutionTime
                        
      - |
        // Output results ready for timeline
        LET flatOutput = SELECT 
                    ExecutionTime as event_time,
                    hostname.Fqdn[0] as hostname,
                    "Prefetch" as parser,
                    "Evidence of Execution: " + Executable + format(format=" Prefetch run count %v", args=RunCount) as message,
                    FilteredPath as source,
                    Executable as file_name,
                    CreationTime as prefetch_ctime,
                    ModificationTime as prefetch_mtime,
                    FileSize as prefetch_size,
                    Hash as prefetch_hash,
                    Version as prefetch_version, 
                    PrefetchFileName as prefetch_file,
                    RunCount as prefetch_count 
            FROM chain(
                    a = { SELECT * FROM executionTimes },
                    b = { SELECT * FROM creationTimes  })
      - SELECT * FROM flatOutput
              
```
   {{% /expand %}}

## Windows.Utils.DownloadBinaries

This server side artifact downloads the external binary blobs we
require into the server's public directory. We also update the
inventory and the hashes.

You need to run this artifact at least once after installation to
populate the third party binary store. Many client side artifacts
depend on this.


Arg|Default|Description
---|------|-----------
binaryList|Tool,Type,URL,Filename\nAutorun,amd64,https://live ...|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Utils.DownloadBinaries
description: |
  This server side artifact downloads the external binary blobs we
  require into the server's public directory. We also update the
  inventory and the hashes.

  You need to run this artifact at least once after installation to
  populate the third party binary store. Many client side artifacts
  depend on this.

type: SERVER

parameters:
  - name: binaryList
    default: |
      Tool,Type,URL,Filename
      Autorun,amd64,https://live.sysinternals.com/tools/autorunsc64.exe,autorunsc_x64.exe
      Autorun,x86,https://live.sysinternals.com/tools/autorunsc.exe,autorunsc_x86.exe
      WinPmem,.,https://github.com/Velocidex/c-aff4/releases/download/v3.3.rc3/winpmem_v3.3.rc3.exe,winpmem_v3.3.rc3.exe
      Sysmon,amd64,https://live.sysinternals.com/tools/sysmon64.exe,sysmon_x64.exe
      Sysmon,x86,https://live.sysinternals.com/tools/sysmon.exe,sysmon_x86.exe
      SysmonConfig,.,https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/z-AlphaVersion.xml,sysmon_config.xml

sources:
  - queries:
      - LET binpath <= SELECT server_config.Frontend.public_path AS Path FROM scope()
      - LET spec = SELECT * FROM parse_csv(filename=binaryList, accessor="data")

      - LET download = SELECT Tool, Type, Filename,
            hash(path=Content) as Hash,
            copy(filename=Content, dest=path_join(components=[
                (binpath[0]).Path, Filename]))
        FROM http_client(url=URL, tempfile_extension=".exe")

      # Write the inventory file.
      - SELECT * FROM write_csv(
          filename=path_join(components=[
              (binpath[0]).Path, "inventory.csv"]),
          query={
            SELECT Tool, Type,
                   Filename, Hash.SHA256 AS ExpectedHash
            FROM foreach(
                   row=spec,
                   query=download)
          })
```
   {{% /expand %}}

## Windows.Utils.FetchBinary

A utility artifact which fetches a binary from a URL and caches it on disk. We verify the hash of the binary on disk and if it does not match we fetch it again from the source URL.
This artifact is designed to be called from other artifacts. The binary path will be emitted in the FullPath column.

Arg|Default|Description
---|------|-----------
binaryURL||Specify this as the base of the binary store (if empty we use\nthe server's public directory).\n
ToolName|Autorun|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Utils.FetchBinary
description: A utility artifact which fetches a binary from a URL and caches it on disk.
   We verify the hash of the binary on disk and if it does not match we fetch it again
   from the source URL.

   This artifact is designed to be called from other artifacts. The binary path will be
   emitted in the FullPath column.

parameters:
  - name: binaryURL
    description: |
      Specify this as the base of the binary store (if empty we use
      the server's public directory).
  - name: ToolName
    default: Autorun

sources:
  - queries:
      - LET info_cache <= SELECT * FROM info()

      # Figure out our binary cache path based on arch. Fallback to
      # the temp directory.
      - LET binpath <= SELECT dirname(path=expand(path=Path)) AS Path FROM switch(
          a={SELECT config.WritebackWindows AS Path FROM info_cache
             WHERE OS="windows" AND Path},
          b={SELECT config.WritebacLinux AS Path FROM info_cache
             WHERE OS="linux" AND Path},
          c={SELECT config.WritebackDarwin AS Path FROM info_cache
             WHERE OS="darwin" AND Path},
          d={SELECT expand(path="$Temp") AS Path FROM scope() WHERE Path},
          e={SELECT "/tmp/XXX" AS Path FROM info_cache WHERE OS = "linux"}
        )

      # Where should we download binaries from? Allow this to be
      # overriden by the user.
      - LET inventory_url <= SELECT URL from switch(
         a={SELECT binaryURL AS URL FROM scope() WHERE URL},
         b={SELECT config.ServerUrls[0] + "public/" AS URL FROM scope() WHERE URL},
         c={SELECT log(message="binaryURL not set and no server config."),
            NULL AS URL FROM info_cache})

      # Fetch the inventory from the repository.
      - LET inventory_data = SELECT * FROM http_client(
           chunk_size=1000000,
           url=(inventory_url[0]).URL + "inventory.csv")
           WHERE inventory_url

      # Parse the inventory: Tool,Type,Filename,ExpectedHash
      - LET inventory = SELECT * FROM parse_csv(
           filename=inventory_data.Content, accessor="data")

      # Figure out which tool we need based on the Architecture and
      # the required tool.
      - LET required_tool = SELECT * FROM foreach(
         row=inventory,
         query={
           SELECT Tool, ExpectedHash, Filename FROM info_cache
           WHERE Architecture =~ Type AND Tool = ToolName
         }) LIMIT 1

      # Download the file from the binary URL and store in the local
      # binary cache.
      - LET download = SELECT hash(path=Content) as Hash,
            "Downloaded" AS DownloadStatus,
            copy(filename=Content,
                 dest=path_join(components=[(binpath[0]).Path, Filename])) AS FullPath
        FROM http_client(
            url=(inventory_url[0]).URL + Filename,
            tempfile_extension=".exe")
        WHERE Hash.SHA256 = ExpectedHash

      # Check if the existing file in the binary file cache matches
      # the hash.
      - LET existing = SELECT FullPath, hash(path=FullPath) AS Hash,
                    "Cached" AS DownloadStatus
        FROM stat(filename=path_join(components=[(binpath[0]).Path, Filename]))
        WHERE Hash.SHA256 = ExpectedHash

      # Find the required_tool either if in the local cache or
      # download it (and put it in the cache for next time). If we
      # have to download the file we sleep for a random time to
      # stagger server bandwidth load.
      - SELECT * from foreach(row=required_tool, query={
          SELECT * FROM switch(
            a=existing,
            b={
               SELECT rand(range=20) AS timeout
               FROM scope()
               WHERE log(message=format(format='Sleeping %v Seconds',
                   args=[timeout])) AND sleep(time=timeout) AND FALSE
            },
            c=download)
        })
```
   {{% /expand %}}

## Windows.Utils.UpdatePublicHashes

The server maintains a public directory which can be served to all
endpoints. The public directory should be initially populated by
running the Windows.Utils.DownloadBinaries artifact. It is possible
to manually edit the content of this directory but you will need to
update the hashes.

Clients maintain their local cache of the files and they use the
hash to tell if their local copy is out of date.

This artifact will regenerate the inventory file by re-calculating
the hashes of all files in the public directory.

You need to run this artifact on the server if you manually edit the
content of the public directory.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Utils.UpdatePublicHashes
description: |
  The server maintains a public directory which can be served to all
  endpoints. The public directory should be initially populated by
  running the Windows.Utils.DownloadBinaries artifact. It is possible
  to manually edit the content of this directory but you will need to
  update the hashes.

  Clients maintain their local cache of the files and they use the
  hash to tell if their local copy is out of date.

  This artifact will regenerate the inventory file by re-calculating
  the hashes of all files in the public directory.

  You need to run this artifact on the server if you manually edit the
  content of the public directory.

type: SERVER

sources:
  - queries:
      - LET binpath <= SELECT server_config.Frontend.public_path AS Path
        FROM scope()

      # Get the old inventory.
      - LET inventory <= SELECT * FROM parse_csv(
            filename=path_join(components=[
                (binpath[0]).Path, "inventory.csv"]))

      # Calculate all the hashes of the files on disk and update the
      # hash in the new inventory.
      - LET hashes = SELECT Name,
           hash(path=FullPath) as Hash,
           { SELECT * FROM inventory
             WHERE Filename = Name LIMIT 1 } AS OldData
        FROM glob(globs=(binpath[0]).Path + "/*")
        WHERE OldData.Tool

      # Reconstruct a new inventory file.
      - LET new_inventory = SELECT OldData.Tool AS Tool,
               OldData.Type AS Type, Name AS Filename,
               Hash.SHA256 AS ExpectedHash
        FROM hashes

      # Write the new inventory file.
      - SELECT * FROM write_csv(
          filename=path_join(components=[
                (binpath[0]).Path, "inventory.csv"]),
          query=new_inventory)
```
   {{% /expand %}}

