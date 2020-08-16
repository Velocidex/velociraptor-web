---
description: Various Artifacts which do not fit into other categories.
linktitle: Miscelaneous
title: Miscelaneous Artifacts
toc: true
weight: 70

---
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


```text
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


```text
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


```text
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


```text
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


```text
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


```text
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
    query: |
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

## Generic.Client.Profile

This artifact collects profiling information about the running
client. This is useful when you notice a high CPU load in the client
and want to know why.

The following options are most useful:

1. Goroutines: This shows the backtraces of all currently running
   goroutines. It will generally show most of the code working in the
   current running set of queries.

2. Heap: This shows all allocations currently in use and where they
   are allocated from. This is useful if the client is taking too
   much memory.

3. Profile: This takes a CPU profile of the running process for the
   number of seconds specified in the Duration parameter. You can
   read profiles using:

```
go tool pprof -callgrind -output=profile.grind profile.bin
kcachegrind profile.grind
```

Note that this really only makes sense when another query is running
at the same time since this artifacts itself will not be doing very
much other than just measuring the state of the process.


Arg|Default|Description
---|------|-----------
Allocs||A sampling of all past memory allocations
Block||Stack traces that led to blocking on synchronization primitives
Goroutine||Stack traces of all current goroutines
Heap||A sampling of memory allocations of live objects
Mutex||Stack traces of holders of contended mutexes
Profile||CPU profile
Trace||CPU trace
Verbose||Print more detail
Duration|30|Duration of sampling for Profile and Trace.

{{% expand  "View Artifact Source" %}}


```text
name: Generic.Client.Profile
description: |
  This artifact collects profiling information about the running
  client. This is useful when you notice a high CPU load in the client
  and want to know why.

  The following options are most useful:

  1. Goroutines: This shows the backtraces of all currently running
     goroutines. It will generally show most of the code working in the
     current running set of queries.

  2. Heap: This shows all allocations currently in use and where they
     are allocated from. This is useful if the client is taking too
     much memory.

  3. Profile: This takes a CPU profile of the running process for the
     number of seconds specified in the Duration parameter. You can
     read profiles using:

  ```
  go tool pprof -callgrind -output=profile.grind profile.bin
  kcachegrind profile.grind
  ```

  Note that this really only makes sense when another query is running
  at the same time since this artifacts itself will not be doing very
  much other than just measuring the state of the process.


parameters:
  - name: Allocs
    description: A sampling of all past memory allocations
    type: bool
  - name: Block
    description: Stack traces that led to blocking on synchronization primitives
    type: bool
  - name: Goroutine
    description: Stack traces of all current goroutines
    type: bool
  - name: Heap
    description: A sampling of memory allocations of live objects
    type: bool
  - name: Mutex
    description: Stack traces of holders of contended mutexes
    type: bool
  - name: Profile
    description: CPU profile
    type: bool
  - name: Trace
    description: CPU trace
    type: bool
  - name: Verbose
    description: Print more detail
    type: bool
  - name: Duration
    description: Duration of sampling for Profile and Trace.
    default: "30"

sources:
  - query: |
      SELECT Type, upload(name=Type + ".bin", file=FullPath) AS File
      FROM profile(allocs=Allocs, block=Block, goroutine=Goroutine,
                   heap=Heap, mutex=Mutex, profile=Profile, trace=Trace,
                   debug=if(condition=Verbose, then=2, else=1),
                   duration=atoi(string=Duration))
```
   {{% /expand %}}

## Generic.Client.Stats

An Event artifact which generates client's CPU and memory statistics.

Arg|Default|Description
---|------|-----------
Frequency|10|Return stats every this many seconds.

{{% expand  "View Artifact Source" %}}


```text
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

  - precondition: SELECT OS From info() where OS != 'windows'
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


```text
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


```text
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

## Generic.Utils.FetchBinary

A utility artifact which fetches a binary from a URL and caches it on disk.
We verify the hash of the binary on disk and if it does not match we fetch it again
from the source URL.

This artifact is designed to be called from other artifacts. The
binary path will be emitted in the FullPath column.

As a result of launching an artifact with declared "required_tools"
field, the server will populate the following environment
variables.

Tool_<ToolName>_HASH     - The hash of the binary
Tool_<ToolName>_FILENAME - The filename to store it.
Tool_<ToolName>_URL      - The URL.


Arg|Default|Description
---|------|-----------
ToolName|Autorun_amd64|
SleepDuration|20|A time to sleep before fetching the binary.

{{% expand  "View Artifact Source" %}}


```text
name: Generic.Utils.FetchBinary
description: |
   A utility artifact which fetches a binary from a URL and caches it on disk.
   We verify the hash of the binary on disk and if it does not match we fetch it again
   from the source URL.

   This artifact is designed to be called from other artifacts. The
   binary path will be emitted in the FullPath column.

   As a result of launching an artifact with declared "required_tools"
   field, the server will populate the following environment
   variables.

   Tool_<ToolName>_HASH     - The hash of the binary
   Tool_<ToolName>_FILENAME - The filename to store it.
   Tool_<ToolName>_URL      - The URL.

parameters:
  - name: ToolName
    default: Autorun_amd64

  - name: SleepDuration
    default: "20"
    description: A time to sleep before fetching the binary.

  - name: ToolInfo
    type: hidden
    description: A dict containing the tool information.

sources:
  - query: |
      -- The following VQL is particularly ancient because it is
      -- running on the client and it needs to be compatibile with
      -- clients at least back to 0.3.9

      LET info_cache <= SELECT * FROM info()
      LET inventory_item <= SELECT inventory_get(tool=ToolName) AS Item FROM scope()

      LET args <= SELECT * FROM switch(
        // Try to get info from the ToolInfo parameter.
        a={SELECT get(field="Tool_" + ToolName + "_HASH", item=ToolInfo) AS ToolHash,
                  get(field="Tool_" + ToolName + "_FILENAME", item=ToolInfo) AS ToolFilename,
                  get(field="Tool_" + ToolName + "_URL", item=ToolInfo) AS ToolURL
           FROM scope()  WHERE ToolFilename},

        // Failing this - get it from the scope()
        b={SELECT get(field="Tool_" + ToolName + "_HASH", item=scope()) AS ToolHash,
                  get(field="Tool_" + ToolName + "_FILENAME", item=scope()) AS ToolFilename,
                  get(field="Tool_" + ToolName + "_URL", item=scope()) AS ToolURL
           FROM scope()  WHERE ToolFilename},

        // Failing this - try to get it from the inventory service directly.
        c={SELECT get(field="Tool_" + ToolName + "_HASH", item=(inventory_item[0]).Item) AS ToolHash,
                  get(field="Tool_" + ToolName + "_FILENAME", item=(inventory_item[0]).Item) AS ToolFilename,
                  get(field="Tool_" + ToolName + "_URL", item=(inventory_item[0]).Item) AS ToolURL
           FROM scope()  WHERE ToolFilename}
      )

      // Keep the binaries cached in the temp directory. We verify the
      // hashes all the time so this should be safe.
      LET binpath <= SELECT Path FROM switch(
          a={SELECT dirname(path=tempfile()) AS Path FROM scope() WHERE Path},
          e={SELECT "/tmp" AS Path FROM info_cache WHERE OS = "linux"}
        )

      // Where we should save the file.
      LET ToolPath <= SELECT path_join(components=[(binpath[0]).Path, (args[0]).ToolFilename]) AS Path FROM scope()

      // Download the file from the binary URL and store in the local
      // binary cache.
      LET download = SELECT * FROM if(condition=log(
             message="URL for " + (args[0]).ToolFilename +
                " is at " + (args[0]).ToolURL + " and has hash of " + (args[0]).ToolHash)
             AND binpath AND (args[0]).ToolHash AND (args[0]).ToolURL,
        then={
          SELECT hash(path=Content) as Hash,
              (args[0]).ToolFilename AS Name,
              "Downloaded" AS DownloadStatus,
              copy(filename=Content, dest=(ToolPath[0]).Path) AS FullPath
          FROM http_client(url=(args[0]).ToolURL, tempfile_extension=".exe")
          WHERE log(message=format(format="downloaded hash of %v: %v, expected %v", args=[
                    Content, Hash.SHA256, (args[0]).ToolHash]))
                AND Hash.SHA256 = (args[0]).ToolHash
        }, else={
           SELECT * FROM scope()
           WHERE NOT log(message="No valid setup - is tool " + ToolName +
                        " configured in the server inventory?")
        })

      // Check if the existing file in the binary file cache matches
      // the hash.
      LET existing = SELECT FullPath, hash(path=FullPath) AS Hash, Name,
                    "Cached" AS DownloadStatus
        FROM stat(filename=(ToolPath[0]).Path)
        WHERE Hash.SHA256 = (args[0]).ToolHash AND log(
            message=format(format="hash of %v: %v, expected %v", args=[
            FullPath, Hash.SHA256, (args[0]).ToolHash]))

      // Find the required_tool either in the local cache or
      // download it (and put it in the cache for next time). If we
      // have to download the file we sleep for a random time to
      // stagger server bandwidth load.
      SELECT * FROM switch(
        a=existing,
        b={
           SELECT rand(range=atoi(string=SleepDuration)) AS timeout
           FROM scope()
           WHERE args AND (args[0]).ToolURL AND
              log(message=format(format='Sleeping %v Seconds',
                 args=[timeout])) AND sleep(time=timeout) AND FALSE
        },
        c=download)
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


```text
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


```text
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


```text
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

## Reporting.Default

A default template for HTML export.  This template will be used to
host html exports such as the notebook and the reporting
templates. Velociraptor will evaluate this template on the following
dict:

  - key main: contains a string with all the results of rendering
              the notebook inside.

## Notes

1. All html elements are allowed in a html template.

2. It is possible to run arbitrary VQL (and therefore arbitrary
   code) inside HTML templates. Therefore to modify this you will
   need the SERVER_ARTIFACT_WRITER permission.


{{% expand  "View Artifact Source" %}}


```text
name: Reporting.Default

type: SERVER

description: |
  A default template for HTML export.  This template will be used to
  host html exports such as the notebook and the reporting
  templates. Velociraptor will evaluate this template on the following
  dict:

    - key main: contains a string with all the results of rendering
                the notebook inside.

  ## Notes

  1. All html elements are allowed in a html template.

  2. It is possible to run arbitrary VQL (and therefore arbitrary
     code) inside HTML templates. Therefore to modify this you will
     need the SERVER_ARTIFACT_WRITER permission.

reports:
  - type: HTML
    template: |
          <html>
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
              <title>Velociraptor Report</title>

              <!-- Bootstrap core CSS -->
              <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/css/bootstrap.min.css" integrity="sha384-Vkoo8x4CGsO3+Hhxv8T/Q5PaXtkKtu6ug5TOeNV6gBiFeWPGFN9MuhOf23Q9Ifjh" crossorigin="anonymous">
              <script src="https://code.jquery.com/jquery-3.4.1.slim.min.js" integrity="sha384-J6qa4849blE2+poT4WnyKhv5vZF5SrPo0iEjwBvKU7imGFAV0wwj1yYfoRSJoZ+n" crossorigin="anonymous"></script>
              <script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.0/dist/umd/popper.min.js" integrity="sha384-Q6E9RHvbIyZFJoft+2mJbHaEWldlvI9IOYy5n3zV9zzTtmI3UksdQRVvoxMfooAo" crossorigin="anonymous"></script>
              <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/js/bootstrap.min.js" integrity="sha384-wfSDF2E50Y2D1uUdj0O3uMBJnjuUD4Ih7YwaYd1iqfktj0Uod8GCExl3Og8ifwB6" crossorigin="anonymous"></script>

              <style>
          pre {
              display: block;
              padding: 8px;
              margin: 0 0 8.5px;
              font-size: 12px;
              line-height: 1.31;
              word-break: break-all;
              word-wrap: break-word;
              color: #333333;
              background-color: #f5f5f5;
              border: 1px solid #ccc;
              border-radius: 4px;
          }

          .notebook-cell {
              border-color: transparent;
              display: flex;
              flex-direction: column;
              align-items: stretch;
              border-radius: 20px;
              border-width: 3px;
              border-style: none;
              border-color: #ababab;
              padding: 20px;
              margin: 0px;
              position: relative;
              overflow: auto;
          }

          /* Error */  .chromaerr { color: #a61717; background-color: #e3d2d2 }
          /* LineTableTD */  .chromalntd { vertical-align: top; padding: 0; margin: 0; border: 0; }
          /* LineTable */  .chromalntable { border-spacing: 0; padding: 0; margin: 0; border: 0; width: auto; overflow: auto; display: block; }
          /* LineHighlight */  .chromahl { display: block; width: 100%%; }
          /* LineNumbersTable */  .chromalnt { margin-right: 0.4em; padding: 0 0.4em 0 0.4em; }
          /* LineNumbers */  .chromaln { margin-right: 0.4em; padding: 0 0.4em 0 0.4em; }
          /* Keyword */  .chromak { color: #000000; font-weight: bold }
          /* KeywordConstant */  .chromakc { color: #000000; font-weight: bold }
          /* KeywordDeclaration */  .chromakd { color: #000000; font-weight: bold }
          /* KeywordNamespace */  .chromakn { color: #000000; font-weight: bold }
          /* KeywordPseudo */  .chromakp { color: #000000; font-weight: bold }
          /* KeywordReserved */  .chromakr { color: #000000; font-weight: bold }
          /* KeywordType */  .chromakt { color: #445588; font-weight: bold }
          /* NameAttribute */  .chromana { color: #008080 }
          /* NameBuiltin */  .chromanb { color: #0086b3 }
          /* NameBuiltinPseudo */  .chromabp { color: #999999 }
          /* NameClass */  .chromanc { color: #445588; font-weight: bold }
          /* NameConstant */  .chromano { color: #008080 }
          /* NameDecorator */  .chromand { color: #3c5d5d; font-weight: bold }
          /* NameEntity */  .chromani { color: #800080 }
          /* NameException */  .chromane { color: #990000; font-weight: bold }
          /* NameFunction */  .chromanf { color: #990000; font-weight: bold }
          /* NameLabel */  .chromanl { color: #990000; font-weight: bold }
          /* NameNamespace */  .chromann { color: #555555 }
          /* NameTag */  .chromant { color: #000080 }
          /* NameVariable */  .chromanv { color: #008080 }
          /* NameVariableClass */  .chromavc { color: #008080 }
          /* NameVariableGlobal */  .chromavg { color: #008080 }
          /* NameVariableInstance */  .chromavi { color: #008080 }
          /* LiteralString */  .chromas { color: #dd1144 }
          /* LiteralStringAffix */  .chromasa { color: #dd1144 }
          /* LiteralStringBacktick */  .chromasb { color: #dd1144 }
          /* LiteralStringChar */  .chromasc { color: #dd1144 }
          /* LiteralStringDelimiter */  .chromadl { color: #dd1144 }
          /* LiteralStringDoc */  .chromasd { color: #dd1144 }
          /* LiteralStringDouble */  .chromas2 { color: #dd1144 }
          /* LiteralStringEscape */  .chromase { color: #dd1144 }
          /* LiteralStringHeredoc */  .chromash { color: #dd1144 }
          /* LiteralStringInterpol */  .chromasi { color: #dd1144 }
          /* LiteralStringOther */  .chromasx { color: #dd1144 }
          /* LiteralStringRegex */  .chromasr { color: #009926 }
          /* LiteralStringSingle */  .chromas1 { color: #dd1144 }
          /* LiteralStringSymbol */  .chromass { color: #990073 }
          /* LiteralNumber */  .chromam { color: #009999 }
          /* LiteralNumberBin */  .chromamb { color: #009999 }
          /* LiteralNumberFloat */  .chromamf { color: #009999 }
          /* LiteralNumberHex */  .chromamh { color: #009999 }
          /* LiteralNumberInteger */  .chromami { color: #009999 }
          /* LiteralNumberIntegerLong */  .chromail { color: #009999 }
          /* LiteralNumberOct */  .chromamo { color: #009999 }
          /* Operator */  .chromao { color: #000000; font-weight: bold }
          /* OperatorWord */  .chromaow { color: #000000; font-weight: bold }
          /* Comment */  .chromac { color: #999988; font-style: italic }
          /* CommentHashbang */  .chromach { color: #999988; font-style: italic }
          /* CommentMultiline */  .chromacm { color: #999988; font-style: italic }
          /* CommentSingle */  .chromac1 { color: #999988; font-style: italic }
          /* CommentSpecial */  .chromacs { color: #999999; font-weight: bold; font-style: italic }
          /* CommentPreproc */  .chromacp { color: #999999; font-weight: bold; font-style: italic }
          /* CommentPreprocFile */  .chromacpf { color: #999999; font-weight: bold; font-style: italic }
          /* GenericDeleted */  .chromagd { color: #000000; background-color: #ffdddd }
          /* GenericEmph */  .chromage { color: #000000; font-style: italic }
          /* GenericError */  .chromagr { color: #aa0000 }
          /* GenericHeading */  .chromagh { color: #999999 }
          /* GenericInserted */  .chromagi { color: #000000; background-color: #ddffdd }
          /* GenericOutput */  .chromago { color: #888888 }
          /* GenericPrompt */  .chromagp { color: #555555 }
          /* GenericStrong */  .chromags { font-weight: bold }
          /* GenericSubheading */  .chromagu { color: #aaaaaa }
          /* GenericTraceback */  .chromagt { color: #aa0000 }
          /* TextWhitespace */  .chromaw { color: #bbbbbb }
          </style>
            </head>
            <body>
              <main role="main" class="container">

              <h1> Collection report. </h1>

              {{ $data := Query "SELECT timestamp(epoch=now()).String AS Time, \
                     OS, Fqdn \
                 FROM info()" | Expand }}
              This report was generated at {{ Get $data "0.Time" }} on host {{ Get $data "0.Fqdn" }}.

              {{ .main }}

              </main>
             </body>
          </html>
```
   {{% /expand %}}

## Reporting.Hunts.Details

Report details about which client ran each hunt, how long it took
and if it has completed.


{{% expand  "View Artifact Source" %}}


```text
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

## Windows.Analysis.EvidenceOfExecution

In many investigations it is useful to find evidence of program execution.

This artifact combines the findings of several other collectors into
an overview of all program execution artifacts. The associated
report walks the user through the analysis of the findings.


{{% expand  "View Artifact Source" %}}


```text
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

## Windows.Application.TeamViewer.Incoming

Parses the TeamViewer Connections_incoming.txt log file.

When inbound logging enabled, this file will show all inbound TeamViewer
connections.


Arg|Default|Description
---|------|-----------
FileGlob|C:\\Program Files (x86)\\TeamViewer\\Connections_i ...|
DateAfter||search for events after this date. YYYY-MM-DDTmm:hh:ss Z
DateBefore||search for events before this date. YYYY-MM-DDTmm:hh:ss Z
TeamViewerIDRegex|.|Regex of TeamViewer ID
SourceHostRegex|.|Regex of source host
UserRegex|.|Regex of user
SearchVSS||Add VSS into query.

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Application.TeamViewer.Incoming
description: |
   Parses the TeamViewer Connections_incoming.txt log file.

   When inbound logging enabled, this file will show all inbound TeamViewer
   connections.

author: Matt Green - @mgreen27

reference:
  - https://attack.mitre.org/techniques/T1219/
  - https://www.systoolsgroup.com/forensics/teamviewer/


type: CLIENT
parameters:
  - name: FileGlob
    default: C:\Program Files (x86)\TeamViewer\Connections_incoming.txt
  - name: DateAfter
    description: "search for events after this date. YYYY-MM-DDTmm:hh:ss Z"
    type: timestamp
  - name: DateBefore
    description: "search for events before this date. YYYY-MM-DDTmm:hh:ss Z"
    type: timestamp
  - name: TeamViewerIDRegex
    description: "Regex of TeamViewer ID"
    default: .
  - name: SourceHostRegex
    description: "Regex of source host"
    default: .
  - name: UserRegex
    description: "Regex of user"
    default: .
  - name: SearchVSS
    description: "Add VSS into query."
    type: bool

sources:
  - query: |
        -- Target hostname
        LET hostname <= SELECT Fqdn FROM info()

        -- Build time bounds
        LET DateAfterTime <= if(condition=DateAfter,
            then=timestamp(epoch=DateAfter), else=timestamp(epoch="1600-01-01"))
        LET DateBeforeTime <= if(condition=DateBefore,
            then=timestamp(epoch=DateBefore), else=timestamp(epoch="2200-01-01"))

        -- Determine target files
        LET files = SELECT *,
                if(condition=Source,
                    then=Source,
                    else=FullPath
                        ) as Source
          FROM if(condition=SearchVSS,
            then= {
              SELECT *
              FROM Artifact.Windows.Search.VSS(SearchFilesGlob=FileGlob)
              WHERE not IsDir and Size > 0
            },
            else= {
              SELECT *, FullPath AS Source
              FROM glob(globs=FileGlob) WHERE not IsDir and Size > 0
            })
        LET Items = SELECT * FROM foreach(
                row=files,
                query={
                    SELECT parse_string_with_regex(
                        string=Line,
                        regex=[
                            "^(?P<TeamViewerID>[^\\s]+)\\s+"+
                            "(?P<SourceHost>[^\\s]+)\\s+"+
                            "(?P<StartTime>[^\\s]+\\s[^\\s]+)\\s+"+
                            "(?P<EndTime>[^\\s]+\\s[^\\s]+)\\s+"+
                            "(?P<User>[^\\s]+)\\s+"+
                            "(?P<ConnectionType>[^\\s]+)\\s+"+
                            "(?P<ConnectionID>.+)$"
                        ]) as Record,
                        Source
                    FROM parse_lines(filename=FullPath)
                    WHERE Line
                })
                ORDER BY Source DESC

        -- Group and filter results for deduplication
        LET grouped = SELECT
                timestamp(string=Record.StartTime) as StartTime,
                timestamp(string=Record.EndTime) as EndTime,
                Record.TeamViewerID as TeamViewerID,
                hostname.Fqdn[0] as TargetHost,
                Record.SourceHost as SourceHost,
                Record.User as User,
                Record.ConnectionType as ConnectionType,
                Record.ConnectionID as ConnectionID,
                Source
            FROM Items
            GROUP BY ConnectionID

        -- Output results
        SELECT * FROM grouped
        WHERE
            (( StartTime < DateBeforeTime AND StartTime > DateAfterTime ) OR
                    ( EndTime < DateBeforeTime AND EndTime > DateAfterTime ))
            AND TeamViewerID =~ TeamViewerIDRegex
            AND SourceHost =~ SourceHostRegex
            AND User =~ UserRegex
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


```text
name: Windows.Attack.ParentProcess
description: |
  Maps the Mitre Att&ck framework process executions into artifacts.

  ### References:
  * https://www.sans.org/security-resources/posters/hunt-evil/165/download
  * https://github.com/teoseller/osquery-attck/blob/master/windows-incorrect_parent_process.conf

precondition: SELECT OS From info() where OS = 'windows'

parameters:
  - name: lookupTable
    type: csv
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


```text
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
        type: csv
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

## Windows.Memory.Acquisition

Acquires a full memory image. We download winpmem and use it to
acquire a full memory image.

NOTE: This artifact usually takes a long time. You should increase
the default timeout to allow it to complete.


{{% expand  "View Artifact Source" %}}


```text
name: Windows.Memory.Acquisition
description: |
  Acquires a full memory image. We download winpmem and use it to
  acquire a full memory image.

  NOTE: This artifact usually takes a long time. You should increase
  the default timeout to allow it to complete.

tools:
  - name: WinPmem
    url: https://github.com/Velocidex/c-aff4/releases/download/v3.3.rc3/winpmem_v3.3.rc3.exe

sources:
  - queries:
      - SELECT * FROM foreach(
          row={
            SELECT FullPath, tempfile(data="X", extension=".aff4") AS Tempfile
            FROM Artifact.Generic.Utils.FetchBinary(ToolName="WinPmem")
          },
          query={
            SELECT Stdout, Stderr,
                   if(condition=Complete,
                      then=upload(file=Tempfile, name="PhysicalMemory.aff4")) As Upload
            FROM execve(
               argv=[FullPath, "-dd", "-o", Tempfile, "-t", "-c", "snappy"],
               sep="\r\n")
        })
```
   {{% /expand %}}

## Windows.Packs.Autoexec

Aggregate of executables that will automatically execute on the
target machine. This is an amalgamation of other tables like
services, scheduled_tasks, startup_items and more.


{{% expand  "View Artifact Source" %}}


```text
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


```text
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


```text
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
Accessor|auto|The accessor to use
YaraRule|None|A yara rule to search for matching files.
Upload_File|N|
Calculate_Hash|N|
MoreRecentThan||
ModifiedBefore||

{{% expand  "View Artifact Source" %}}


```text
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

  - name: Accessor
    default: auto
    description: The accessor to use

  - name: YaraRule
    default:
    description: A yara rule to search for matching files.

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
  - query: |
      LET file_search = SELECT FullPath,
               Sys.mft as Inode,
               Mode.String AS Mode, Size,
               Mtime.Sec AS Modified,
               timestamp(epoch=Atime.Sec) AS ATime,
               timestamp(epoch=Mtime.Sec) AS MTime, "" AS Keywords,
               timestamp(epoch=Ctime.Sec) AS CTime, IsDir
        FROM glob(globs=SearchFilesGlob, accessor=Accessor)

      LET more_recent = SELECT * FROM if(
        condition=MoreRecentThan,
        then={
          SELECT * FROM file_search
          WHERE Modified > parse_float(string=MoreRecentThan)
        }, else=file_search)

      LET modified_before = SELECT * FROM if(
        condition=ModifiedBefore,
        then={
          SELECT * FROM more_recent
          WHERE Modified < parse_float(string=ModifiedBefore)
        }, else=more_recent)

      LET keyword_search = SELECT * FROM if(
        condition=YaraRule,
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
                         key="A",
                         rules=YaraRule,
                         accessor=Accessor)
            })
        }, else=modified_before)

      SELECT FullPath, Inode, Mode, Size, Modified, ATime,
             MTime, CTime, Keywords, IsDir,
               if(condition=(Upload_File = "Y" and NOT IsDir ),
                  then=upload(file=FullPath, accessor=Accessor)) AS Upload,
               if(condition=(Calculate_Hash = "Y" and NOT IsDir ),
                  then=hash(path=FullPath, accessor=Accessor)) AS Hash
      FROM keyword_search
```
   {{% /expand %}}

## Windows.Search.VSS

This artifact will find all relevant files in the VSS. Typically used to
out deduplicated paths for processing by other artifacts.

Input either search Glob or FullPath.
Output is standard Glob results with additional fields:
SHA1 hash for deduplication,
Type for prioritisation, and
Deduped to indicate if FullPath has been deduped with another row.


Arg|Default|Description
---|------|-----------
SearchFilesGlob|C:\\Windows\\System32\\winevt\\Logs\\Security.evtx|Use a glob to define the files that will be searched.

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Search.VSS
description: |
  This artifact will find all relevant files in the VSS. Typically used to
  out deduplicated paths for processing by other artifacts.

  Input either search Glob or FullPath.
  Output is standard Glob results with additional fields:
  SHA1 hash for deduplication,
  Type for prioritisation, and
  Deduped to indicate if FullPath has been deduped with another row.

author: Matt Green - @mgreen27

precondition: SELECT * FROM info() where OS = 'windows'

parameters:
  - name: SearchFilesGlob
    default: C:\Windows\System32\winevt\Logs\Security.evtx
    description: Use a glob to define the files that will be searched.

sources:
  - query: |
      -- Given a path in either device notation or drive notation,
      -- break it into a drive and path
      LET extract_path(FullPath) = parse_string_with_regex(string=FullPath,
         regex="^(?P<Device>\\\\\\\\.\\\\GLOBALROOT\\\\Device\\\\HarddiskVolumeShadowCopy[^\\\\]+\\\\|\\\\\\\\.\\\\.:\\\\|.:\\\\)(?P<Path>.+)$")

      LET extract_vss(FullPath) = parse_string_with_regex(string=FullPath,
         regex="^(?P<Device>(\\\\\\\\.\\\\GLOBALROOT\\\\Device\\\\HarddiskVolumeShadowCopy[^\\\\]+\\\\|\\\\\\\\.\\\\.:\\\\))")

      -- Build a SearchGlob for all logical disks and VSS
      LET globs = SELECT
            FullPath + '/' + extract_path(FullPath=SearchFilesGlob).Path as SearchGlob
        FROM glob(globs='/*', accessor='ntfs')
        ORDER BY FullPath  DESC

      -- Glob for all files in SearchGlob and calculate their hash.
      LET globvss(SearchGlob) = SELECT *,
            extract_path(FullPath=FullPath).Path AS Path,
            basename(path=extract_vss(FullPath=FullPath).Device) AS Source,
            hash(path=FullPath,accessor='ntfs').SHA1 as SHA1
         FROM glob(globs=SearchGlob, accessor='ntfs')
         WHERE NOT IsDIr

      -- For each full glob (including VSS device) extract all files
      -- and hashes.
      LET results = SELECT * FROM foreach(row=globs,
      query={
        -- Prepend VSS with _ to make them sort last.
        SELECT *, if(condition=Source =~ '^HarddiskVolumeShadowCopy',
                     then='_' + Source,
                     else=Source) AS Source
        FROM globvss(SearchGlob=SearchGlob)
      })

      -- We want to see natural drives after VSS because group by
      -- shows the last in the group. VSS Sources look like
      -- HarddiskVolumeShadowCopy1 and disk sources look like C:
      ORDER BY Source DESC

      -- Dedup and show results
      SELECT *, count() > 1 AS Deduped, SHA1 + Path AS Key
      FROM results
      GROUP BY Key
```
   {{% /expand %}}

## Windows.Search.Yara

Searches for a specific malicious file or set of files by a Yara rule.

You will need to upload your yara file using:

```
velociraptor tools upload --name YaraRules my_yara_file.yara
```


Arg|Default|Description
---|------|-----------
nameRegex|(exe|txt|dll|php)$|Only file names that match this regular expression will be scanned.

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Search.Yara
description: |
  Searches for a specific malicious file or set of files by a Yara rule.

  You will need to upload your yara file using:

  ```
  velociraptor tools upload --name YaraRules my_yara_file.yara
  ```

tools:
  - name: YaraRules

parameters:
    - name: nameRegex
      description: Only file names that match this regular expression will be scanned.
      default: "(exe|txt|dll|php)$"

precondition:
  SELECT * FROM info() WHERE OS =~ "windows"

sources:
  - query: |
        LET yara_rules <= SELECT read_file(filename=FullPath) AS Rule
        FROM Artifact.Generic.Utils.FetchBinary(ToolName="YaraRules")

        LET fileList = SELECT FullPath
        FROM parse_mft(
            accessor="ntfs",
            filename="C:\\$MFT")
        WHERE InUse
          AND FileName =~ nameRegex
          AND NOT FullPath =~ "WinSXS"

        -- These files are typically short - only report a single hit.
        LET search = SELECT Rule, String.Offset AS HitOffset,
             str(str=String.Data) AS HitContext,
             FileName,
             File.Size AS Size,
             File.ModTime AS ModTime
        FROM yara(
            rules=yara_rules[0].Rule, key="A",
            files="C:/" + FullPath)
        LIMIT 1

        -- Only do something when yara rules are available.
        SELECT * FROM if(condition=yara_rules,
        then={
          SELECT *, upload(file=FileName) AS Upload
          FROM foreach(row=fileList, query=search)
        })
```
   {{% /expand %}}

## Windows.Timeline.MFT

# Output all filtered MFT records.

This Artifact enables querying the MFT with advanced filters 
such as time, path or other ntfs attributes.

Output is to Timeline field format to enable simple review accross Timeline
queries. The TimeOutput paramater enables configuring which NTFS attribute 
timestamps are in focus as event_time. for example: 
  STANDARD_INFORMATION (4), FILE_NAME (4) or ALL (8)

This artifact also has the same anomaly logic as AnalyzeMFT added to 
each row to assist analysis.


Arg|Default|Description
---|------|-----------
MFTFilename|C:/$MFT|
Accessor|ntfs|
PathRegex|.|regex search over FullPath.
NameRegex|.|regex search over File Name
Inode||search for inode
DateAfter||search for events after this date. YYYY-MM-DDTmm:hh:ssZ
DateBefore||search for events before this date. YYYY-MM-DDTmm:hh:ssZ
SizeMax||Entries in the MFT over this size in bytes.
SizeMin||Entries in the MFT under this size in bytes.
EntryType|Both|Type of entry. File, Directory or Both.\n
AllocatedType|Both|Type of entry. Allocated, Unallocated or Both.\n
TimeOutput|STANDARD_INFORMATION|Timestamps to output as event_time. SI, FN or both. \nNOTE: both will output 8 rows per MFT entry.\n

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Timeline.MFT
description: |
  # Output all filtered MFT records.

  This Artifact enables querying the MFT with advanced filters 
  such as time, path or other ntfs attributes.

  Output is to Timeline field format to enable simple review accross Timeline
  queries. The TimeOutput paramater enables configuring which NTFS attribute 
  timestamps are in focus as event_time. for example: 
    STANDARD_INFORMATION (4), FILE_NAME (4) or ALL (8)

  This artifact also has the same anomaly logic as AnalyzeMFT added to 
  each row to assist analysis.
  
author: Matt Green - @mgreen27

precondition: SELECT OS From info() where OS = 'windows'

parameters:
  - name: MFTFilename
    default: "C:/$MFT"
  - name: Accessor
    default: ntfs
  - name: PathRegex
    description: "regex search over FullPath."
    default: .
  - name: NameRegex
    default: .
    description: "regex search over File Name"
  - name: Inode
    type: int64
    description: "search for inode"
  - name: DateAfter
    type: timestamp
    description: "search for events after this date. YYYY-MM-DDTmm:hh:ssZ"
  - name: DateBefore
    type: timestamp
    description: "search for events before this date. YYYY-MM-DDTmm:hh:ssZ"
  - name: SizeMax
    type: int64
    description: "Entries in the MFT over this size in bytes."
  - name: SizeMin
    type: int64
    description: "Entries in the MFT under this size in bytes."
  - name: EntryType
    description: |
        Type of entry. File, Directory or Both.
    type: choices
    default: Both
    choices:
       - File
       - Directory
       - Both
  - name: AllocatedType
    description: |
        Type of entry. Allocated, Unallocated or Both.
    type: choices
    default: Both
    choices:
       - Allocated
       - Unallocated
       - Both
  - name: TimeOutput
    description: |
        Timestamps to output as event_time. SI, FN or both. 
        NOTE: both will output 8 rows per MFT entry.
    type: choices
    default: STANDARD_INFORMATION
    choices:
       - STANDARD_INFORMATION
       - FILE_NAME
       - ALL
    
sources:
  - queries:
        - LET hostname <= SELECT Fqdn FROM info()
        - LET DateAfterTime <= if(condition=DateAfter, then=timestamp(epoch=DateAfter), else=timestamp(epoch="1600-01-01"))
        - LET DateBeforeTime <= if(condition=DateBefore, then=timestamp(epoch=DateBefore), else=timestamp(epoch="2200-01-01")) 
        - LET records = SELECT *,
                if(condition=Created0x10.Unix < Created0x30.Unix, 
                    then=True, else=False) as FNCreatedShift,
                if(condition=Created0x10.Unix * 1000000000 = Created0x10.UnixNano, 
                    then=True, else=False) as USecZero,
                if(condition=Created0x10.Unix > LastModified0x10.Unix, 
                    then=True, else=False) as PossibleCopy,
                if(condition=LastAccess0x10.Unix > LastModified0x10.Unix AND LastAccess0x10.Unix > Created0x10.Unix, 
                    then=True, else=False) as VolumeCopy
            FROM parse_mft(filename=MFTFilename, accessor=Accessor)
            WHERE 
                FullPath =~ PathRegex AND 
                FileName =~ NameRegex AND
                if(condition=Inode, then= EntryNumber=atoi(string=Inode)
                    OR ParentEntryNumber=atoi(string=Inode), 
                    else=TRUE) AND                     
                if(condition=SizeMax, then=FileSize < atoi(string=SizeMax),
                    else=TRUE) AND 
                if(condition=SizeMin, then=FileSize > atoi(string=SizeMin),
                    else=TRUE) AND
                if(condition= EntryType="Both", then=TRUE,
                    else= if(condition= EntryType="File", 
                        then= IsDir=False,
                    else= if(condition= EntryType="Directory",
                        then= IsDir=True))) AND
                if(condition= AllocatedType="Both", then=TRUE,
                    else= if(condition= AllocatedType="Allocated", 
                        then= InUse=True,
                    else= if(condition= AllocatedType="Unallocated",
                        then= InUse=False))) AND
                (((Created0x10 > DateAfterTime) AND (Created0x10 < DateBeforeTime)) OR
                ((Created0x30 > DateAfterTime) AND (Created0x30 < DateBeforeTime)) OR
                ((LastModified0x10 > DateAfterTime) AND (LastModified0x10 < DateBeforeTime)) OR
                ((LastModified0x30 > DateAfterTime) AND (LastModified0x30 < DateBeforeTime)) OR
                ((LastRecordChange0x10 > DateAfterTime) AND (LastRecordChange0x10 < DateBeforeTime)) OR
                ((LastRecordChange0x30 > DateAfterTime) AND (LastRecordChange0x30 < DateBeforeTime)) OR
                ((LastAccess0x10 > DateAfterTime) AND (LastAccess0x10 < DateBeforeTime)) OR
                ((LastAccess0x30 > DateAfterTime) AND (LastAccess0x30 < DateBeforeTime)))

        - LET common_fields = SELECT EntryNumber, ParentEntryNumber,
                FullPath, FileName, FileSize, IsDir,InUse,
                Created0x10, Created0x30, 
                LastModified0x10, LastModified0x30,
                LastRecordChange0x10, LastRecordChange0x30,
                LastAccess0x10, LastAccess0x30,
                FNCreatedShift, USecZero, PossibleCopy, VolumeCopy
            FROM scope()

        - LET standard_information_rows = SELECT * FROM chain(
            si_modified = { 
                SELECT *,
                    LastModified0x10 as event_time,
                    format(format="MFTEntry:%v $STANDARD_INFORMATION (0x10) LastModified time", 
                      args=EntryNumber) as message
                FROM common_fields
            },
            si_access = { 
                SELECT *,
                    LastAccess0x10 as event_time,
                    format(format="MFTEntry:%v $STANDARD_INFORMATION (0x10) LastAccess time", 
                      args=EntryNumber) as message
                FROM common_fields
            },
            si_created = { 
                SELECT *,
                    LastRecordChange0x10 as event_time,
                    format(format="MFTEntry:%v $STANDARD_INFORMATION (0x10) LastRecordChange time", 
                      args=EntryNumber) as message
                FROM common_fields
            },
            si_born = { 
                SELECT *,
                    Created0x10 as event_time,
                    format(format="MFTEntry:%v $STANDARD_INFORMATION (0x10) Created time", 
                      args=EntryNumber) as message
                FROM common_fields
            })
        - LET file_name_rows = SELECT * FROM chain(
            fn_modified = { 
                SELECT *,
                    LastModified0x30 as event_time,
                    format(format="MFTEntry:%v $FILE_NAME (0x30) LastModified time", 
                      args=EntryNumber) as message
                FROM common_fields
            },
            fn_access = { 
                SELECT *,
                    LastAccess0x30 as event_time,
                    format(format="MFTEntry:%v $FILE_NAME (0x30) LastAccess time", 
                      args=EntryNumber) as message
                FROM common_fields
            },
            fn_created = { 
                SELECT *,
                    LastRecordChange0x30 as event_time,
                    format(format="MFTEntry:%v $FILE_NAME (0x30) LastRecordChange time", 
                      args=EntryNumber) as message
                FROM common_fields
            },
            fn_born = { 
                SELECT *,
                    Created0x30 as event_time,
                      format(format="MFTEntry:%v $FILE_NAME (0x30) Created time", 
                        args=EntryNumber) as message
                FROM common_fields
            })
        - SELECT
            event_time,
            hostname.Fqdn[0] as hostname,
            "MFT" as parser,
            MFTFilename as source,
            message,
            FullPath as path,
            { SELECT EntryNumber,ParentEntryNumber,FileSize, IsDir, InUse FROM scope() } as optional_1,
            { SELECT FNCreatedShift, USecZero, PossibleCopy, VolumeCopy FROM scope() } as optional_2,
            { SELECT LastModified0x10,LastAccess0x10,LastRecordChange0x10,Created0x10 FROM scope() } as optional_3,
            { SELECT LastModified0x30,LastAccess0x30,LastRecordChange0x30,Created0x30 FROM scope() } as optional_4
          FROM foreach(
            row=records,
            query={
                SELECT * FROM chain(
                    standard_information={
                        SELECT * FROM if(
                            condition=TimeOutput="STANDARD_INFORMATION" OR TimeOutput="ALL",
                            then=standard_information_rows)
                    },
                    file_name={
                        SELECT * FROM if(
                            condition=TimeOutput="FILE_NAME" OR TimeOutput="ALL",
                            then=file_name_rows)
                    })
            }) 
            
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


```text
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
            GROUP BY ExecutionTime
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

## Windows.Timeline.Registry.RunMRU

# Output all available RunMRU registry keys in timeline format.

RunMRU is when a user enters a command into the START > Run prompt.  
Entries will be logged in the user hive under:    Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU

The artifact numbers all entries with the most recent at 
reg_mtime starting at 0. Second recent 1, Third recent 2 etc. 
  
Default output enables a line per MRU entry.  
A tickbox enables Grouped results with order in a single line.

Note: This artifact will collect RunMRU from ntuser.dat files and 
may exclude very recent entries in transaction (HKCU).  Future 
versions of this content will address this gap.


Arg|Default|Description
---|------|-----------
dateAfter||search for events after this date. YYYY-MM-DDTmm:hh:ss Z
dateBefore||search for events before this date. YYYY-MM-DDTmm:hh:ss Z
targetUser||target user regex
regexValue||regex search over RunMRU values.
groupResults||groups MRU entries to one message line

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Timeline.Registry.RunMRU
description: |
    # Output all available RunMRU registry keys in timeline format.
    
    RunMRU is when a user enters a command into the START > Run prompt.  
    Entries will be logged in the user hive under:    Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
    
    The artifact numbers all entries with the most recent at 
    reg_mtime starting at 0. Second recent 1, Third recent 2 etc. 
      
    Default output enables a line per MRU entry.  
    A tickbox enables Grouped results with order in a single line.
    
    Note: This artifact will collect RunMRU from ntuser.dat files and 
    may exclude very recent entries in transaction (HKCU).  Future 
    versions of this content will address this gap.
    
author: Matt Green - @mgreen27

precondition: SELECT OS From info() where OS = 'windows'

parameters:
  - name: KeyGlob
    type: hidden
    default: Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\MRUList     
  - name: dateAfter
    description: "search for events after this date. YYYY-MM-DDTmm:hh:ss Z"
    type: timestamp
  - name: dateBefore
    description: "search for events before this date. YYYY-MM-DDTmm:hh:ss Z"
    type: timestamp
  - name: targetUser
    description: "target user regex"
  - name: regexValue
    description: "regex search over RunMRU values."
  - name: groupResults
    description: "groups MRU entries to one message line"
    type: bool
    
sources:
 - query: |
        LET hostname <= SELECT Fqdn FROM info()
        
        // First we need to extract populated RunMRU
        LET runmru <= SELECT basename(path=FullPath),
                url(path=url(parse=FullPath).Path,
                    fragment=dirname(path=url(parse=FullPath).Fragment) 
                        + "/*").string as mruKeyGlob,
                FullPath,
                url(parse=FullPath),
                Data.value as RunMruOrder,
                len(list=Data.value) as RunMruLength,
                Username,
                UUID
        FROM Artifact.Windows.Registry.NTUser(KeyGlob=KeyGlob)
        
        // Now extract RunMRU entries and order
        LET results <= SELECT * FROM foreach(
             row=runmru, 
             query={
                SELECT 
                    url(parse=FullPath).Path as source,
                    Username,
                    "HKEY_USERS\\" + UUID + dirname(path=url(parse="ntfs://" + 
                        FullPath).Fragment) as reg_key,
                    timestamp(epoch=Mtime.sec) as reg_mtime,
                    basename(path=url(parse=FullPath).Fragment) as reg_name,
                    split(string=Data.value, sep="\\\\1$")[0] as reg_value,
                    Data.type as reg_type,
                    RunMruLength - 1 - len(list=regex_replace(
                        source=RunMruOrder, 
                        re="^.*" + basename(path=url(parse=FullPath).Fragment), 
                            replace="")) as mru_order,
                    RunMruOrder
                FROM glob(globs=mruKeyGlob, accessor="raw_reg")
                WHERE not reg_name = "MRUList" AND
                    if(condition=targetUser, then=Username =~ targetUser,
                        else=TRUE) AND
                    if(condition=dateAfter, then=reg_mtime > timestamp(string=dateAfter),
                        else=TRUE) AND
                    if(condition=dateBefore, then=reg_mtime < timestamp(string=dateBefore),
                        else=TRUE)  
                ORDER BY mru_order
              })

        // join mru values and order for presentation
        LET usercommands <= SELECT Username as user, mru_order, 
                format(format="MRU%v: %v", args=[mru_order,reg_value]) as mru_grouped
        FROM results
        
        // Prepare join use case
        LET joinOut = SELECT 
                reg_mtime as event_time,
                hostname.Fqdn[0] as hostname,
                "RunMRU" as parser,
                "RunMRU evidence user: " + Username + ", " + 
                  join(array=mru_grouped, sep=" | ")  + "'" as message,
                source,
                Username as user
        FROM foreach(row=usercommands,
            query={
                SELECT *, Username,
                    {
                        SELECT mru_grouped
                        FROM usercommands
                        WHERE user = Username
                        ORDER BY mru_order
                    } as mru_grouped
                FROM results
                ORDER BY mru_grouped
            })
        GROUP BY source

        // Prepare split use case
        LET splitOut = SELECT 
                    reg_mtime as event_time,
                    hostname.Fqdn[0] as hostname,
                    "RunMRU" as parser,
                    "RunMRU evidence user: " + Username + 
                        format(format=", order: %v, command: %v", args=[mru_order,reg_value]) 
                            + "'" as message,
                    source,
                    Username as user,
                    reg_key,
                    reg_mtime,
                    reg_name,
                    reg_value,
                    reg_type
            FROM results

        // Print out chosen usecase
        SELECT *
        FROM if(condition=groupResults,
            then=joinOut, else=splitOut)
        WHERE if(condition=regexValue, then=reg_runmru =~ regexValue, else=TRUE)
```
   {{% /expand %}}

