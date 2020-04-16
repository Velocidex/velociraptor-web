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

    queries:
      - |
        SELECT HuntId, timestamp(epoch=create_time/1000000) as Created,
               start_request.Args.artifacts.names  as Artifact,
               State
        FROM hunts()
        WHERE start_request.flow_name = 'ArtifactCollector'
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
ClientId|None|
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
    default:
  - name: StandardUserAccounts
    description: Well known SIDs to hide from the output.
    default: "(-5..$|S-1-5-18|S-1-5-19|S-1-5-20)"

sources:
  - queries:
      - |
        // Get the most recent collection of our user listing.
        LET last_user_listing = SELECT flow_id
           FROM flows(client_id=ClientId)
           WHERE context.artifacts =~'Windows.Sys.Users'
           ORDER BY LastActive DESC LIMIT 1

      - |
        /* For each Windows.Sys.Users collection, extract the user
           names. Hide standard SIDs.
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
      {{ range $item := $artifact.Parameters }}
         {{ if not (eq $item.Type "hidden") }}
           <tr>
               <td> {{ $item.Name }}</td>
               <td>{{ $item.Type }}</td>
               <td><pre>{{ $item.Default }}</pre></td>
           </tr>
         {{ end }}
      {{ end }}
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

## Server.Monitor.Health

This is the main server health dashboard. It is shown on the
homescreen and enabled by default on all new installs.


Arg|Default|Description
---|------|-----------
Frequency|15|Return stats every this many seconds.

{{% expand  "View Artifact Source" %}}


```text
name: Server.Monitor.Health
description: |
  This is the main server health dashboard. It is shown on the
  homescreen and enabled by default on all new installs.

type: SERVER_EVENT

parameters:
  - name: Frequency
    description: Return stats every this many seconds.
    default: "15"

sources:
  - name: Prometheus
    queries:
      - |
        LET metrics_url <= SELECT format(format='http://%s:%d/metrics', args=[
              server_config.Monitoring.bind_address,
              server_config.Monitoring.bind_port]) as URL
        FROM scope()

      - |
        SELECT int(int=rate(x=process_cpu_seconds_total, y=Timestamp) * 100) As CPUPercent,
               process_resident_memory_bytes / 1000000 AS MemoryUse,
               process_cpu_seconds_total,
               client_comms_current_connections,
               client_comms_concurrency
        FROM foreach(
          row={
             SELECT UnixNano FROM clock(period=atoi(string=Frequency))
          },
          query={
             SELECT * FROM Artifact.Server.Monitor.VeloMetrics(MetricsURL=metrics_url.URL[0])
          })
        WHERE CPUPercent >= 0


reports:
  - type: SERVER_EVENT
    parameters:
      - name: Sample
        default: "4"

    template: |
      {{ define "CPU" }}
           SELECT * FROM sample(
             n=atoi(string=Sample),
             query={
               SELECT _ts as Timestamp,
                  CPUPercent,
                  MemoryUse
               FROM source(source="Prometheus",
                           artifact="Server.Monitor.Health")
             })
      {{ end }}

      {{ define "CurrentConnections" }}
           SELECT * FROM sample(
             n=atoi(string=Sample),
             query={
               SELECT _ts as Timestamp,
                  client_comms_current_connections,
                  client_comms_concurrency
               FROM source(source="Prometheus",
                           artifact="Server.Monitor.Health")
            })
      {{ end }}

      {{ $CurrentMetrics := Query "SELECT * FROM Artifact.Server.Monitor.VeloMetrics()" }}

      ## Server status

      Currently there are {{ Get $CurrentMetrics "0.client_comms_current_connections" }} clients connected.

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
  - queries:
    - |
      SELECT * FROM watch_monitoring(artifact="Shell")

# Reports can be MONITORING_DAILY, CLIENT
reports:
  - type: SERVER_EVENT
    template: |
      {{ .Description }}

      {{ $rows := Query "SELECT timestamp(epoch=Timestamp) AS Timestamp, Argv, Stdout FROM source()" }}

      {{ range $row := $rows }}

         * On {{ Get $row "Timestamp" }} we ran {{ Get $row "Argv" }}

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

Note: This is an automated system hunt. You do not need to start it.


{{% expand  "View Artifact Source" %}}


```text
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

