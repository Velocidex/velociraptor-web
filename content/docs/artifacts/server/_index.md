---
description: These artifacts are intended to run on the server.
linktitle: Server Artifacts
title: Server Artifacts
weight: 30

---
## Server.Alerts.PsExec

Send an email if execution of the psexec service was detected on
any client. This is a server side artifact.

Note this requires that the Windows.Event.ProcessCreation
monitoring artifact be collected from clients.


Arg|Default|Description
---|------|-----------
EmailAddress|admin@example.com|
MessageTemplate|PsExec execution detected at %v: %v for client %v\ ...|

{{% expand  "View Artifact Source" %}}


```text
name: Server.Alerts.PsExec
description: |
   Send an email if execution of the psexec service was detected on
   any client. This is a server side artifact.

   Note this requires that the Windows.Event.ProcessCreation
   monitoring artifact be collected from clients.

type: SERVER_EVENT

parameters:
  - name: EmailAddress
    default: admin@example.com
  - name: MessageTemplate
    default: |
      PsExec execution detected at %v: %v for client %v

sources:
  - queries:
      - |
        SELECT * FROM foreach(
          row={
            SELECT * from watch_monitoring(
              artifact='Windows.Events.ProcessCreation')
            WHERE Name =~ '(?i)psexesvc'
          },
          query={
            SELECT * FROM mail(
              to=EmailAddress,
              subject='PsExec launched on host',
              period=60,
              body=format(
              format=MessageTemplate,
              args=[Timestamp, CommandLine, ClientId])
          )
        })
```
   {{% /expand %}}

## Server.Alerts.WinPmem

Send an email if the pmem service has been installed on any of the
endpoints.

Note this requires that the Windows.Event.ServiceCreation
monitoring artifact be collected from clients.


Arg|Default|Description
---|------|-----------
EmailAddress|admin@example.com|

{{% expand  "View Artifact Source" %}}


```text
name: Server.Alerts.WinPmem
description: |
   Send an email if the pmem service has been installed on any of the
   endpoints.

   Note this requires that the Windows.Event.ServiceCreation
   monitoring artifact be collected from clients.

type: SERVER_EVENT

parameters:
  - name: EmailAddress
    default: admin@example.com

sources:
  - queries:
      - |
        SELECT * FROM foreach(
          row={
            SELECT * from watch_monitoring(
              artifact='Windows.Events.ServiceCreation')
            WHERE ServiceName =~ 'pmem'
          },
          query={
            SELECT * FROM mail(
              to=EmailAddress,
              subject='Pmem launched on host',
              period=60,
              body=format(
                 format="WinPmem execution detected at %s for client %v",
                 args=[Timestamp, ClientId]
              )
          )
        })
```
   {{% /expand %}}

## Server.Hunts.List

List Hunts currently scheduled on the server.


{{% expand  "View Artifact Source" %}}


```text
name: Server.Hunts.List
description: |
  List Hunts currently scheduled on the server.

type: SERVER

sources:
  - precondition:
      SELECT * from server_config

    query: |
      SELECT HuntId, timestamp(epoch=create_time/1000000) as Created,
             join(array=start_request.artifacts, sep=",") as Artifact,
             State
      FROM hunts()
```
   {{% /expand %}}

## Server.Hunts.Results

Show the results from each artifact collection hunt.


Arg|Default|Description
---|------|-----------
huntId|H.d05b2482|
ArtifactName|Linux.Mounts|

{{% expand  "View Artifact Source" %}}


```text
name: Server.Hunts.Results
description: |
  Show the results from each artifact collection hunt.
parameters:
  - name: huntId
    default: H.d05b2482
  - name: ArtifactName
    default: Linux.Mounts

type: SERVER

sources:
  - precondition:
      SELECT * from server_config

    queries:
      - |
        SELECT * FROM hunt_results(hunt_id=huntId, artifact=ArtifactName)
```
   {{% /expand %}}

## Server.Information.Clients

This artifact returns the total list of clients, their hostnames and
the last times they were seen.

We also include a list of usernames on this machine, as gathered by
the last Windows.Sys.Users artifact that was collected. Note that
the list of usernames may be outdated if that artifact was not
collected recently.


{{% expand  "View Artifact Source" %}}


```text
name: Server.Information.Clients
description: |
  This artifact returns the total list of clients, their hostnames and
  the last times they were seen.

  We also include a list of usernames on this machine, as gathered by
  the last Windows.Sys.Users artifact that was collected. Note that
  the list of usernames may be outdated if that artifact was not
  collected recently.

type: SERVER

sources:
  - queries:
      - |
        /* Collect information about each client. */
        LET client_info = SELECT client_id,
               os_info.fqdn as HostName,
               os_info.system as OS,
               os_info.release as Release,
               timestamp(epoch=last_seen_at/ 1000000).String as LastSeenAt,
               last_ip AS LastIP,
               last_seen_at AS _LastSeenAt
        FROM clients()
        ORDER BY _LastSeenAt DESC

      - |
        LET names = SELECT Name FROM Artifact.Server.Information.Users(
               ClientId=client_id)

      - |
        /* For each client, also list its users. */
        SELECT client_id,
               HostName, OS, Release, LastSeenAt, LastIP,
               join(array=names.Name, sep=",") AS Users
        FROM client_info
```
   {{% /expand %}}

## Server.Information.Users

List the user names and SIDs on each machine. We get this
information from the last time we collected Windows.Sys.Users. If we
never collected it for this machine, there will be no results.


Arg|Default|Description
---|------|-----------
ClientId|C.56a8dfd31eb1fa6f|
StandardUserAccounts|(-5..$|S-1-5-18|S-1-5-19|S-1-5-20)|Well known SIDs to hide from the output.

{{% expand  "View Artifact Source" %}}


```text
name: Server.Information.Users
description: |
  List the user names and SIDs on each machine. We get this
  information from the last time we collected Windows.Sys.Users. If we
  never collected it for this machine, there will be no results.

type: SERVER

parameters:
  - name: ClientId
    default: C.56a8dfd31eb1fa6f

  - name: StandardUserAccounts
    description: Well known SIDs to hide from the output.
    default: "(-5..$|S-1-5-18|S-1-5-19|S-1-5-20)"

sources:
  - query: |
        // Get the most recent collection of our user listing.
        LET last_user_listing = SELECT session_id AS flow_id
           FROM flows(client_id=ClientId)
           WHERE artifacts_with_results =~'Windows.Sys.Users'
           ORDER BY LastActive
           DESC LIMIT 1

        /* For each Windows.Sys.Users collection, extract the user
           names, but hide standard SIDs.
        */
        SELECT * FROM foreach(
            row=last_user_listing,
            query={
              SELECT Name, UUID from source(
                 flow_id=flow_id,
                 artifact='Windows.Sys.Users',
                 client_id=ClientId)
              WHERE NOT UUID =~ StandardUserAccounts
            })
```
   {{% /expand %}}

## Server.Internal.ArtifactDescription



{{% expand  "View Artifact Source" %}}


```text
name: Server.Internal.ArtifactDescription

type: INTERNAL

reports:
  - type: INTERNAL
    template: |
      {{ $artifact := Scope "artifact" }}

      ## {{ $artifact.Name }}

      #### Type: {{ $artifact.Type }}

      {{ if $artifact.Author }}
      ##### by {{ $artifact.Author }}
      {{end}}

      {{ $artifact.Description }}

      {{ if $artifact.Parameters }}

      ### Parameters

      <table class="table table-striped table-hover">
      <thead>
         <tr>
           <th>Name</th>
           <th>Type</th>
           <th>Default</th>
         </tr>
      </thead>
      <tbody>
      {{- range $item := $artifact.Parameters -}}
         {{- if not (eq $item.Type "hidden") -}}
           <tr>
               <td> {{ $item.Name }}</td>
               <td>{{ $item.Type }}</td>
               <td><pre>{{ $item.Default }}</pre></td>
           </tr>
         {{- end -}}
      {{- end -}}
      </tbody></table>

      {{ end }}

      {{ range $source := $artifact.Sources }}

      ### Source {{ $source.Name }}
      {{ if $source.Query }}

      ```vql
      {{ $source.Query }}
      ```

      {{- else -}}

      ```vql
      {{ range $query := $source.Queries -}}
      {{- $query -}}
      {{ end }}
      ```
      {{ end }}

      {{ end }}
```
   {{% /expand %}}

## Server.Internal.ArtifactModification

This event artifact is an internal event stream over which
notifications of artifact modifications are sent. Interested parties
can watch for new artifact modification events and rebuild caches
etc.

Note: This is an automated system artifact. You do not need to start it.


{{% expand  "View Artifact Source" %}}


```text
name: Server.Internal.ArtifactModification
description: |
  This event artifact is an internal event stream over which
  notifications of artifact modifications are sent. Interested parties
  can watch for new artifact modification events and rebuild caches
  etc.

  Note: This is an automated system artifact. You do not need to start it.

type: SERVER_EVENT
```
   {{% /expand %}}

## Server.Internal.Enrollment

This event artifact is an internal event stream over which client
enrollments are sent. You can watch this event queue to be notified
on any new clients enrolling for the first time.

Note: This is an automated system artifact. You do not need to start it.


{{% expand  "View Artifact Source" %}}


```text
name: Server.Internal.Enrollment
description: |
  This event artifact is an internal event stream over which client
  enrollments are sent. You can watch this event queue to be notified
  on any new clients enrolling for the first time.

  Note: This is an automated system artifact. You do not need to start it.

type: SERVER_EVENT
```
   {{% /expand %}}

## Server.Internal.Interrogate

An internal artifact used track new client interrogations by the
Interrogation service.


{{% expand  "View Artifact Source" %}}


```text
name: Server.Internal.Interrogate
description: |
  An internal artifact used track new client interrogations by the
  Interrogation service.

type: SERVER_EVENT

sources:
  - queries:
      - SELECT * FROM foreach(
          row={
             SELECT ClientId, Flow, FlowId
             FROM watch_monitoring(artifact='System.Flow.Completion')
             WHERE Flow.artifacts_with_results =~ 'Generic.Client.Info'
          },
          query={
            SELECT * FROM switch(
              a={
                  SELECT ClientId,
                    FlowId,
                    Architecture,
                    BuildTime,
                    Fqdn,
                    Hostname,
                    KernelVersion,
                    Labels,
                    Name,
                    OS,
                    Platform,
                    PlatformVersion
                 FROM source(
                    client_id=ClientId,
                    flow_id=FlowId,
                    source="BasicInformation",
                    artifact="Custom.Generic.Client.Info",
                    mode="CLIENT")
               },
            b={
                SELECT ClientId,
                  FlowId,
                  Architecture,
                  BuildTime,
                  Fqdn,
                  Hostname,
                  KernelVersion,
                  Labels,
                  Name,
                  OS,
                  Platform,
                  PlatformVersion
               FROM source(
                  client_id=ClientId,
                  flow_id=FlowId,
                  source="BasicInformation",
                  artifact="Generic.Client.Info",
                  mode="CLIENT")
            })
          })
```
   {{% /expand %}}

## Server.Internal.Label

An internal artifact used to track new labeling events.


{{% expand  "View Artifact Source" %}}


```text
name: Server.Internal.Label
description: |
  An internal artifact used to track new labeling events.

type: SERVER_EVENT
```
   {{% /expand %}}

## Server.Internal.Notifications

This event artifact is an internal event stream over which client
notifications are sent. A frontend will watch for events over this
stream and if a client is actively connected to this frontend, the
client will be notified that new work is available to it.

Note: This is an automated system artifact. You do not need to start it.


{{% expand  "View Artifact Source" %}}


```text
name: Server.Internal.Notifications
description: |
  This event artifact is an internal event stream over which client
  notifications are sent. A frontend will watch for events over this
  stream and if a client is actively connected to this frontend, the
  client will be notified that new work is available to it.

  Note: This is an automated system artifact. You do not need to start it.

type: SERVER_EVENT
```
   {{% /expand %}}

## Server.Monitor.Health

This is the main server health dashboard. It is shown on the
homescreen and enabled by default on all new installs.


{{% expand  "View Artifact Source" %}}


```text
name: Server.Monitor.Health
description: |
  This is the main server health dashboard. It is shown on the
  homescreen and enabled by default on all new installs.

type: SERVER_EVENT

sources:
  - name: Prometheus

    # This artifact is populated by the frontend service using the
    # total of all frontend metrics.
    query: SELECT * FROM info() WHERE FALSE

reports:
  - type: SERVER_EVENT
    # Only allow the report to run for 10 seconds - this is plenty for
    # the GUI.
    timeout: 10
    parameters:
      - name: Sample
        default: "4"

    template: |
      {{ define "CPU" }}
          SELECT _ts as Timestamp,
              CPUPercent,
              MemoryUse / 1048576 AS MemoryUse
          FROM source(source="Prometheus",
                      artifact="Server.Monitor.Health")
      {{ end }}

      {{ define "CurrentConnections" }}
           SELECT * FROM sample(
             n=atoi(string=Sample),
             query={
               SELECT _ts as Timestamp,
                  client_comms_current_connections
               FROM source(source="Prometheus",
                           artifact="Server.Monitor.Health")
            })
      {{ end }}

      ## Server status

      The following are total across all frontends.

      <span class="container">
        <span class="row">
          <span class="col-sm panel">
           CPU and Memory Utilization
           {{ Query "CPU" | LineChart "xaxis_mode" "time" "RSS.yaxis" 2 }}
          </span>
          <span class="col-sm panel">
           Currently Connected Clients
           {{ Query "CurrentConnections" | LineChart "xaxis_mode" "time" "RSS.yaxis" 2 }}
          </span>
        </span>
      </span>


      ## Users

      {{ Query "SELECT Name, Permissions FROM gui_users()" | Table }}

      ## Server version

      {{ Query "SELECT Version FROM server_config" | Table }}
```
   {{% /expand %}}

## Server.Monitor.Profile

This artifact collects profiling information from the running
server. This is useful when you notice a high CPU load in the server
and want to know why.

The following options are most useful:

1. Goroutines: This shows the backtraces of all currently running
   goroutines. It will generally show most of the code working in the
   current running set of queries.

2. Heap: This shows all allocations currently in use and where they
   are allocated from. This is useful if the server is taking too
   much memory.

3. Profile: This takes a CPU profile of the running process for the
   number of seconds specified in the Duration parameter. You can
   read profiles using:

```
go tool pprof -callgrind -output=profile.grind profile.bin
kcachegrind profile.grind
```


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
name: Server.Monitor.Profile
description: |
  This artifact collects profiling information from the running
  server. This is useful when you notice a high CPU load in the server
  and want to know why.

  The following options are most useful:

  1. Goroutines: This shows the backtraces of all currently running
     goroutines. It will generally show most of the code working in the
     current running set of queries.

  2. Heap: This shows all allocations currently in use and where they
     are allocated from. This is useful if the server is taking too
     much memory.

  3. Profile: This takes a CPU profile of the running process for the
     number of seconds specified in the Duration parameter. You can
     read profiles using:

  ```
  go tool pprof -callgrind -output=profile.grind profile.bin
  kcachegrind profile.grind
  ```

type: SERVER

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

## Server.Monitor.Shell

Velociraptor can get an interactive shell on the endpoint by using
the shell command. In order to use it, the user must be directly
logged on the server.

Obviously being able to run arbitrary commands on the end point is
a powerful feature and should be used sparingly. There is an audit
trail for shell commands executed and their output available by
streaming all shell commands to the "Shell" client evnt monitoring
artifact.

This server event artifact centralizes all shell access from all
clients into the same log file.


{{% expand  "View Artifact Source" %}}


```text
name: Server.Monitor.Shell
description: |
   Velociraptor can get an interactive shell on the endpoint by using
   the shell command. In order to use it, the user must be directly
   logged on the server.

   Obviously being able to run arbitrary commands on the end point is
   a powerful feature and should be used sparingly. There is an audit
   trail for shell commands executed and their output available by
   streaming all shell commands to the "Shell" client evnt monitoring
   artifact.

   This server event artifact centralizes all shell access from all
   clients into the same log file.

# Can be CLIENT, EVENT, SERVER, SERVER_EVENT
type: SERVER_EVENT

sources:
  - query: |
      -- Watch for shell flow completions.
      LET collections = SELECT Flow
         FROM watch_monitoring(artifact="System.Flow.Completion")
         WHERE Flow.artifacts_with_results =~ "Windows.System.PowerShell|Windows.System.CmdShell"

      -- Dump the command and the results.
      SELECT * FROM foreach(row=collections,
      query={
         SELECT Flow.session_id AS FlowId,
             Flow.client_id AS ClientId,
             client_info(client_id=Flow.client_id).os_info.fqdn AS Hostname,
             timestamp(epoch=Flow.create_time / 1000000) AS Created,
             timestamp(epoch=Flow.active_time / 1000000) AS LastActive,
             Flow.request.parameters.env[0].value AS Command,
             Stdout, Stderr FROM source(
                 client_id=Flow.client_id,
                 flow_id=Flow.session_id,
                 artifact=Flow.artifacts_with_results[0])
      })


# Reports can be MONITORING_DAILY, CLIENT
reports:
  - type: SERVER_EVENT
    template: |
      {{ .Description }}

      {{ $rows := Query "SELECT ClientId, Hostname, \
           timestamp(epoch=LastActive) AS Timestamp, Command, Stdout FROM source()" }}

      {{ range $row := $rows }}

      * On {{ Get $row "Timestamp" }} we ran {{ Get $row "Command" }} on {{ Get $row "Hostname" }}

      ```text
      {{ Get $row "Stdout" }}
      ```

      {{end}}
```
   {{% /expand %}}

## Server.Monitor.VeloMetrics

Get Velociraptor server metrics.


Arg|Default|Description
---|------|-----------
MetricsURL|http://localhost:8003/metrics|

{{% expand  "View Artifact Source" %}}


```text
name: Server.Monitor.VeloMetrics
description: |
  Get Velociraptor server metrics.

type: SERVER

parameters:
  - name: MetricsURL
    default: http://localhost:8003/metrics

sources:
  - queries:
      - |
        LET stats = SELECT parse_string_with_regex(string=Content,
           regex=[
             'client_comms_concurrency (?P<client_comms_concurrency>[^\\s]+)',
             'client_comms_current_connections (?P<client_comms_current_connections>[^\\s]+)',
             'flow_completion (?P<flow_completion>[^\\s]+)',
             'process_open_fds (?P<process_open_fds>[^\\s]+)',
             'uploaded_bytes (?P<uploaded_bytes>[^\\s]+)',
             'uploaded_files (?P<uploaded_files>[^\\s]+)',
             'stats_client_one_day_actives{version="[^"]+"} (?P<one_day_active>[^\\s]+)',
             'stats_client_seven_day_actives{version="[^"]+"} (?P<seven_day_active>[^\\s]+)'
           ]) AS Stat, {
              // On Windows Prometheus does not provide these so we get our own.
              SELECT Times.user + Times.system as CPU,
                     MemoryInfo.RSS as RSS
              FROM pslist(pid=getpid())
           } AS PslistStats
        FROM  http_client(url=MetricsURL, chunk_size=50000)

      - |
        SELECT now() AS Timestamp,
               PslistStats.RSS AS process_resident_memory_bytes,
               parse_float(string=Stat.client_comms_concurrency)
                      AS client_comms_concurrency,
               parse_float(string=Stat.client_comms_current_connections)
                      AS client_comms_current_connections,
               parse_float(string=Stat.flow_completion) AS flow_completion,
               parse_float(string=Stat.uploaded_bytes) AS uploaded_bytes,
               parse_float(string=Stat.uploaded_files) AS uploaded_files,
               parse_float(string=Stat.process_open_fds)
                     AS process_open_fds,
               PslistStats.CPU AS process_cpu_seconds_total,
               parse_float(string=Stat.one_day_active)
                     AS one_day_active,
               parse_float(string=Stat.seven_day_active)
                     AS seven_day_active
        FROM stats
```
   {{% /expand %}}

## Server.Monitoring.ClientCount

An artifact that sends an email every hour of the current state of
the deployment.


Arg|Default|Description
---|------|-----------
EmailAddress|admin@example.com|
CCAddress|None|
Subject|Deployment statistics for Velociraptor|
Period|3600|

{{% expand  "View Artifact Source" %}}


```text
name: Server.Monitoring.ClientCount

description: |
   An artifact that sends an email every hour of the current state of
   the deployment.

type: SERVER_EVENT

parameters:
   - name: EmailAddress
     default: admin@example.com
   - name: CCAddress
     default:
   - name: Subject
     default: "Deployment statistics for Velociraptor"
   - name: Period
     default: "3600"

sources:
  - queries:
    - |
      LET metrics = SELECT * FROM Artifact.Server.Monitor.VeloMetrics()

    - |
      SELECT * FROM foreach(
        row={
            SELECT * FROM clock(period=atoi(string=Period))
        },
        query={
             SELECT * FROM mail(
                to=EmailAddress,
                cc=CCAddress,
                subject=Subject,
                period=60,
                body=format(format='Total clients currently connected %v',
                     args=[metrics.client_comms_current_connections])
            )
        })
```
   {{% /expand %}}

## Server.Powershell.EncodedCommand

It is possible to pass powershell an encoded script. This artifact
decodes the scripts.

NOTE: The client must be running the Windows.Events.ProcessCreation
event artifact to retrieve process execution logs.


{{% expand  "View Artifact Source" %}}


```text
name: Server.Powershell.EncodedCommand
description: |
  It is possible to pass powershell an encoded script. This artifact
  decodes the scripts.

  NOTE: The client must be running the Windows.Events.ProcessCreation
  event artifact to retrieve process execution logs.

type: SERVER_EVENT

sources:
  - queries:
     - |
       SELECT ClientId, ParentInfo, CommandLine, Timestamp, utf16(
          string=base64decode(
             string=parse_string_with_regex(
                string=CommandLine,
                regex='-((?i)(en|enc|encode|encodedCommand)) (?P<Encoded>[^ ]+)'
             ).Encoded)) AS Script
        FROM watch_monitoring(artifact='Windows.Events.ProcessCreation')
        WHERE CommandLine =~ '-(en|enc|encode|encodedCommand)'

reports:
  - type: SERVER_EVENT
    template: |

      Encoded Powershell
      ==================

      {{ .Description }}

      ## Decoded Powershell commands.

      {{ Query "SELECT ClientId, { SELECT os_info.Fqdn from clients(client_id=ClientId) } AS FQDN, Script FROM source()" | Table }}
```
   {{% /expand %}}

## Server.Utils.CreateCollector

A utility artifact to create a stand alone collector.

This artifact is actually invoked by the Offline collector GUI and
that is the recommended way to launch it. You can find the Offline
collector builder in the `Server Artifacts` section of the GUI.


Arg|Default|Description
---|------|-----------
OS|Windows|
artifacts|["Generic.Client.Info"]\n|A list of artifacts to collect
template|Reporting.Default|The HTML report template to use.
Password||If set we encrypt collected zip files with this password.
parameters|{}\n|A dict containing the parameters to set.
target|ZIP|Output type
target_args|{}|Type Dependent args
FetchBinaryOverride|LET temp_binary <= tempfile(extension=".exe",\n    ...|A replacement for Generic.Utils.FetchBinary which\ngrabs files from the local archive.\n

{{% expand  "View Artifact Source" %}}


```text
name: Server.Utils.CreateCollector
description: |
  A utility artifact to create a stand alone collector.

  This artifact is actually invoked by the Offline collector GUI and
  that is the recommended way to launch it. You can find the Offline
  collector builder in the `Server Artifacts` section of the GUI.

type: SERVER

tools:
  - name: VelociraptorWindows
    github_project: Velocidex/velociraptor
    github_asset_regex: windows-amd64.exe
    serve_locally: true

  - name: VelociraptorWindows_x86
    github_project: Velocidex/velociraptor
    github_asset_regex: windows-386.exe
    serve_locally: true

  - name: VelociraptorLinux
    github_project: Velocidex/velociraptor
    github_asset_regex: linux-amd64
    serve_locally: true

  - name: VelociraptorDarwin
    github_project: Velocidex/velociraptor
    github_asset_regex: darwin-amd64
    serve_locally: true

parameters:
  - name: OS
    default: Windows
    type: choices
    choices:
      - Windows
      - Linux
      - MacOS

  - name: artifacts
    description: A list of artifacts to collect
    type: json_array
    default: |
      ["Generic.Client.Info"]

  - name: template
    default: Reporting.Default
    description: The HTML report template to use.

  - name: Password
    description: If set we encrypt collected zip files with this password.

  - name: parameters
    description: A dict containing the parameters to set.
    type: json
    default: |
      {}

  - name: target
    description: Output type
    type: choices
    default: ZIP
    choices:
      - ZIP
      - GCS
      - S3

  - name: target_args
    description: Type Dependent args
    type: json
    default: "{}"

  - name: StandardCollection
    type: hidden
    default: |
      LET Artifacts <= parse_json_array(data=Artifacts)
      LET Parameters <= parse_json(data=Parameters)
      LET baseline <= SELECT Fqdn FROM info()

      // Make the filename safe on windows.
      LET filename <= regex_replace(
          source=format(format="Collection-%s-%s",
                        args=[baseline[0].Fqdn, timestamp(epoch=now())]),
          re="[^0-9A-Za-z\\-.]", replace="_")

      LET _ <= log(message="Will collect package " + filename)

      SELECT * FROM collect(artifacts=Artifacts, report=filename + ".html",
          args=Parameters, output=filename + ".zip", template=Template,
          password=Password)

  - name: S3Collection
    type: hidden
    default: |
      LET Artifacts <= parse_json_array(data=Artifacts)
      LET Parameters <= parse_json(data=Parameters)
      LET baseline <= SELECT Fqdn FROM info()
      LET TargetArgs <= parse_json(data=target_args)

      // Make the filename safe on windows.
      LET filename <= regex_replace(
          source=format(format="Collection-%s-%s",
                        args=[baseline[0].Fqdn, timestamp(epoch=now())]),
          re="[^0-9A-Za-z\\-.]", replace="_")

      LET _ <= log(message="Will collect package " + filename +
         " and upload to s3 bucket " + TargetArgs.bucket)

      SELECT upload_s3(file=Container,
          bucket=TargetArgs.bucket,
          name=filename + ".zip",
          credentialskey=TargetArgs.credentialsKey,
          credentialssecret=TargetArgs.credentialsSecret,
          region=TargetArgs.region) AS Upload,
       upload_s3(file=Report,
          bucket=TargetArgs.bucket,
          name=filename + ".html",
          credentialskey=TargetArgs.credentialsKey,
          credentialssecret=TargetArgs.credentialsSecret,
          region=TargetArgs.region) AS ReportUpload
      FROM collect(artifacts=Artifacts, report=tempfile(extension=".html"),
          args=Parameters, output=tempfile(extension=".zip"), template=Template,
          password=Password)

  - name: GCSCollection
    type: hidden
    default: |
      LET Artifacts <= parse_json_array(data=Artifacts)
      LET Parameters <= parse_json(data=Parameters)
      LET baseline <= SELECT Fqdn FROM info()
      LET TargetArgs <= parse_json(data=target_args)
      LET GCSBlob <= parse_json(data=TargetArgs.GCSKey)

      // Make the filename safe on windows.
      LET filename <= regex_replace(
          source=format(format="Collection-%s-%s",
                        args=[baseline[0].Fqdn, timestamp(epoch=now())]),
          re="[^0-9A-Za-z\\-.]", replace="_")

      LET _ <= log(message="Will collect package " + filename +
         " and upload to GCS bucket " + TargetArgs.bucket)

      SELECT upload_gcs(file=Container,
          bucket=TargetArgs.bucket,
          project=GCSBlob.project_id,
          name=filename + ".zip",
          credentials=TargetArgs.GCSKey
      ) AS Upload,
      upload_gcs(file=Report,
          bucket=TargetArgs.bucket,
          project=GCSBlob.project_id,
          name=filename + ".html",
          credentials=TargetArgs.GCSKey
      ) AS ReportUpload
      FROM collect(artifacts=Artifacts, report=tempfile(extension=".html"),
          args=Parameters, output=tempfile(extension=".zip"), template=Template,
          password=Password)

  - name: PackageToolsArtifact
    description: Collects and uploads third party binaries.
    type: hidden
    default: |
      name: PackageToolsArtifact
      parameters:
       - name: Binaries
      sources:
       - query: |
          LET temp <= tempfile()

          LET uploader = SELECT ToolName,
                                Upload.Path AS Filename,
                                Upload.sha256 AS ExpectedHash,
                                Upload.Size AS Size
          FROM foreach(row=Binaries,
            query={
              SELECT _value AS ToolName, upload(file=FullPath, name=Name) AS Upload
              FROM Artifact.Generic.Utils.FetchBinary(
                   ToolName=_value, SleepDuration='0',
                   ToolInfo=inventory_get(tool=_value))
            })

          // Flush the entire query into the inventory file.
          LET _ <= SELECT * FROM write_csv(filename=temp, query=uploader)

          // Now upload it.
          SELECT upload(file=temp, name="inventory.csv") FROM scope()

  - name: FetchBinaryOverride
    description: |
       A replacement for Generic.Utils.FetchBinary which
       grabs files from the local archive.

    default: |
       LET temp_binary <= tempfile(extension=".exe",
                remove_last=TRUE, permissions="x")

       LET matching_tools = SELECT ToolName AS ArchiveTool, Filename
       FROM parse_csv(filename="/inventory.csv", accessor="me")

       SELECT * FROM foreach(row=matching_tools, query={
         SELECT copy(filename=Filename, accessor="me", dest=temp_binary) AS FullPath,
                     Filename AS Name
         FROM scope()
         WHERE ToolName = ArchiveTool
       })

sources:
  - query: |
      LET Payload <= tempfile(extension=".zip")
      LET Artifacts <= parse_json_array(data=artifacts)

      LET Binaries <= SELECT * FROM foreach(
          row={
             SELECT tools FROM artifact_definitions(names=Artifacts)
          }, query={
             SELECT * FROM foreach(row=tools,
             query={
              SELECT name AS Binary FROM scope()
             })
          }) GROUP BY Binary

      // Create a zip file with the binaries in it.
      LET _ <= SELECT * FROM collect(artifacts="PackageToolsArtifact",
         output=Payload, args=dict(Binaries=Binaries.Binary),
         artifact_definitions=PackageToolsArtifact)

      LET CollectionArtifact <= SELECT Value FROM switch(
        a = { SELECT StandardCollection AS Value FROM scope() WHERE target = "ZIP" },
        b = { SELECT S3Collection AS Value  FROM scope() WHERE target = "S3" },
        c = { SELECT GCSCollection AS Value  FROM scope() WHERE target = "GCS" },
        d = { SELECT "" AS Value  FROM scope() WHERE log(message="Unknown collection type " + target) }
      )

      LET definitions <= SELECT * FROM chain(
      a = { SELECT name, description, parameters, sources, reports
            FROM artifact_definitions(names=Artifacts + template)
            WHERE name =~ "^(Custom|Packs)\\." AND
              log(message="Adding artifact_definition for " + name) },

      b = { SELECT "Collector" AS name, (
                    dict(name="Artifacts", default=artifacts),
                    dict(name="Parameters", default=parameters),
                    dict(name="Template", default=template),
                    dict(name="Password", default=Password),
                    dict(name="target_args", default=target_args),
                ) AS parameters,
                (
                  dict(query=CollectionArtifact[0].Value),
                ) AS sources
            FROM scope() },
      c = { SELECT "Generic.Utils.FetchBinary" AS name,
            (
               dict(name="SleepDuration"),
               dict(name="ToolName"),
            ) AS parameters,
            (
               dict(query=FetchBinaryOverride),
            ) AS sources FROM scope()  }
      )

      // Build the autoexec config file depending on the user's
      // collection type choices.
      LET autoexec <= dict(autoexec=dict(
          argv=["artifacts", "collect", "-v", "Collector"],
          artifact_definitions=definitions)
      )

      // Get some tempfiles to work with.
      LET Config <= tempfile()
      LET Destination <= tempfile()

      // Choose the right target binary depending on the target OS
      LET tool_name = SELECT * FROM switch(
       a={ SELECT "VelociraptorWindows" AS Type FROM scope() WHERE OS = "Windows"},
       b={ SELECT "VelociraptorWindows_x86" AS Type FROM scope() WHERE OS = "Windows_x86"},
       c={ SELECT "VelociraptorLinux" AS Type FROM scope() WHERE OS = "Linux"},
       d={ SELECT "VelociraptorDarwin" AS Type FROM scope() WHERE OS = "MacOS"},
       e={ SELECT "" AS Type FROM scope()
           WHERE NOT log(message="Unknown target type " + OS) }
      )

      // Repack this binary.
      LET target_binary <= SELECT FullPath, Name
         FROM Artifact.Generic.Utils.FetchBinary(
            ToolName=tool_name[0].Type, SleepDuration="0",
            ToolInfo=inventory_get(tool=tool_name[0].Type))
         WHERE log(message="Target binary " + Name + " is at " + FullPath)

      LET me <= SELECT Exe FROM info()

      // Copy the configuration to a temp file and shell out to our
      // binary to repack it.
      LET repack_step = SELECT upload(
           file=Destination,
           accessor="file",
           name=format(format='Collector_%v', args=[target_binary[0].Name, ])) AS Binary,
           timestamp(epoch=now()) As CreationTime
      FROM execve(argv=[
        me[0].Exe, "config", "repack",
        "--exe", target_binary[0].FullPath,
        "--append", Payload,
        copy(dest=Config,
             accessor='data',
             filename=serialize(format='json', item=autoexec)),
        Destination ], length=1000000)
      WHERE log(message="Creating config on " + Config) AND log(message=Stderr)

      // Only actually run stuff if everything looks right.
      SELECT * FROM if(condition=autoexec AND target_binary AND me[0].Exe,
         then=repack_step)
```
   {{% /expand %}}

## System.Flow.Archive

An internal artifact that produces events for every flow completion
in the system.


{{% expand  "View Artifact Source" %}}


```text
name: System.Flow.Archive
description: |
  An internal artifact that produces events for every flow completion
  in the system.

type: CLIENT_EVENT
```
   {{% /expand %}}

## System.Flow.Completion

An internal artifact that produces events for every flow completion
in the system.


{{% expand  "View Artifact Source" %}}


```text
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

Note: This is an automated system artifact. You do not need to start it.


{{% expand  "View Artifact Source" %}}


```text
name: System.Hunt.Participation
description: |
     Endpoints may participate in hunts. This artifact collects which hunt
     each system participated in.

     Note: This is an automated system artifact. You do not need to start it.

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
                       hunt_id,
                       hunt_description,
                       start_request.artifacts
                FROM allhunts
                WHERE hunt_id = ParticipatedHuntId
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

## System.Upload.Completion

An internal artifact that produces events for every file that is
uploaded to the system.


{{% expand  "View Artifact Source" %}}


```text
name: System.Upload.Completion
description: |
  An internal artifact that produces events for every file that is
  uploaded to the system.

type: CLIENT_EVENT
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


```text
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
      - SELECT Path, Accessor, Size, StoredSize, Error, Sha256, Md5
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


```text
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
  - query: |
      // Old versions do not have the root parameter to glob()
      // Fixes https://github.com/Velocidex/velociraptor/issues/322
      LET LegacyQuery = SELECT FullPath as _FullPath,
           Accessor as _Accessor,
           Data as _Data,
           Name, Size, Mode.String AS Mode,
           Mtime as mtime,
           Atime as atime,
           Ctime as ctime
        FROM glob(globs=Path + if(condition=atoi(string=Depth),
             then='/**' + Depth, else='/*'),
             accessor=Accessor)

      LET NewQuery = SELECT FullPath as _FullPath,
           Accessor as _Accessor,
           Data as _Data,
           Name, Size, Mode.String AS Mode,
           Mtime as mtime,
           Atime as atime,
           Ctime as ctime
        FROM glob(globs=if(condition=atoi(string=Depth),
             then='/**' + Depth, else='/*'),
             root=Path,
             accessor=Accessor)

      SELECT * FROM if(
       condition=version(plugin="glob") >= 1,
       then=NewQuery,
       else=LegacyQuery)
```
   {{% /expand %}}

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


```text
name: Admin.Client.Upgrade
description: |
  Remotely push new client updates.

  NOTE: The updates can be pulled from any web server. You need to
  ensure they are properly secured with SSL and at least a random
  nonce in their path. You may configure the Velociraptor server to
  serve these through the public directory. Simply place the MSI in
  the public directory within the data store and set the URL below.

required_permissions:
  - EXECVE

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


```text
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

required_permissions:
  - EXECVE

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


```text
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

