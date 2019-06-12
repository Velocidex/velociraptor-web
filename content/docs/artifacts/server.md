---
description: These artifacts are intended to run on the server.
linktitle: Server Artifacts
menu:
  docs: {parent: Artifacts, weight: 10}
title: Server Artifacts
toc: true

---
## Server.Alerts.PsExec

Send an email if execution of the psexec service was detected on
any client. This is a server side artifact.

Note this requires that the Windows.Event.ProcessCreation
monitoring artifact be collected from clients.


Arg|Default|Description
---|------|-----------
EmailAddress|admin@example.com|
MessageTemplate|PsExec execution detected at %v: %v for client %v\n|

{{% expand  "View Artifact Source" %}}


```
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

## Server.Analysis.Triage.PowershellConsole

This artifact post processes the artifact
Windows.Triage.Collectors.PowershellConsoleLogs. While that artifact
just uploads all the powershell console files, we sometimes want to
easily see all the files in the same output table.

This artifact simply post processes the uploaded files and puts
their content in the same table.


Arg|Default|Description
---|------|-----------
huntId||

{{% expand  "View Artifact Source" %}}


```
name: Server.Analysis.Triage.PowershellConsole
description: |
  This artifact post processes the artifact
  Windows.Triage.Collectors.PowershellConsoleLogs. While that artifact
  just uploads all the powershell console files, we sometimes want to
  easily see all the files in the same output table.

  This artifact simply post processes the uploaded files and puts
  their content in the same table.

type: SERVER

parameters:
  - name: huntId

precondition:
  SELECT * from server_config

sources:
  - queries:
      - |
        LET files = SELECT ClientId,
          file_store(path=Flow.FlowContext.uploaded_files) as LogFiles
        FROM hunt_results(
          hunt_id=huntId,
          artifact='Windows.Triage.Collectors.PowershellConsoleLogs')

      # A lookup between client id and FQDN
      - |
        LET clients <= SELECT ClientId, os_info.fqdn AS FQDN from clients()

      - |
        SELECT * FROM foreach(
          row=files,
          query={
            SELECT ClientId, {
                SELECT FQDN FROM clients where ClientId=ClientId_LU
              } As FQDN,
              Filename, Data
            FROM read_file(filenames=LogFiles)
        })
```
   {{% /expand %}}

## Server.Hunts.List

List Hunts currently scheduled on the server.


{{% expand  "View Artifact Source" %}}


```
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


```
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


```
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


```
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


```
name: Server.Internal.ArtifactDescription

reports:
  - type: INTERNAL
    template: |
      {{ $artifact := Scope "artifact" }}

      ## {{ $artifact.Name }}

      #### Type: {{ $artifact.Type }}

      {{ $artifact.Description }}

      {{ if $artifact.Parameters }}

      ### Parameters

      <table class="table table-striped table-hover">
      <thead><tr><th>Name</th><th>Default</th></tr></thead>
      <tbody>
      {{ range $item := $artifact.Parameters }}
         <tr><td> {{ $item.Name }}</td><td><pre>{{ $item.Default }}</pre></td></tr>
      {{ end }}
      </tbody></table>

      {{ end }}

      {{ range $source := $artifact.Sources }}

      ### Source {{ $source.Name }}
      ```sql
      {{ range $query := $source.Queries -}}
      {{- $query -}}
      {{ end }}
      ```
      {{ end }}
```
   {{% /expand %}}

## Server.Monitor.Health

This is the main server health dashboard. It is shown on the
homescreen and enabled by default on all new installs.


Arg|Default|Description
---|------|-----------
Frequency|15|Return stats every this many seconds.

{{% expand  "View Artifact Source" %}}


```
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
               FROM source(source="Prometheus")
             })
      {{ end }}

      {{ define "CurrentConnections" }}
           SELECT * FROM sample(
             n=atoi(string=Sample),
             query={
               SELECT _ts as Timestamp,
                  client_comms_current_connections,
                  client_comms_concurrency
               FROM source(source="Prometheus")
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


```
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


```
name: Server.Monitor.VeloMetrics
description: |
  Get Velociraptor server metrics.

parameters:
  - name: MetricsURL
    default: http://localhost:8003/metrics

sources:
  - queries:
      - |
        LET stats = SELECT parse_string_with_regex(string=Content,
           regex=[
             'process_resident_memory_bytes (?P<process_resident_memory_bytes>[^\\s]+)',
             'client_comms_concurrency (?P<client_comms_concurrency>[^\\s]+)',
             'client_comms_current_connections (?P<client_comms_current_connections>[^\\s]+)',
             'flow_completion (?P<flow_completion>[^\\s]+)',
             'process_open_fds (?P<process_open_fds>[^\\s]+)',
             'process_cpu_seconds_total (?P<process_cpu_seconds_total>[^\\s]+)',
             'stats_client_one_day_actives{version="[^"]+"} (?P<one_day_active>[^\\s]+)',
             'stats_client_seven_day_actives{version="[^"]+"} (?P<seven_day_active>[^\\s]+)'
           ]) AS Stat
        FROM  http_client(url=MetricsURL, chunk=50000)

      - |
        SELECT now() AS Timestamp,
               parse_float(string=Stat.process_resident_memory_bytes)
                      AS process_resident_memory_bytes,
               parse_float(string=Stat.client_comms_concurrency)
                      AS client_comms_concurrency,
               parse_float(string=Stat.client_comms_current_connections)
                      AS client_comms_current_connections,
               parse_float(string=Stat.flow_completion) AS flow_completion,
               parse_float(string=Stat.process_open_fds)
                     AS process_open_fds,
               parse_float(string=Stat.process_cpu_seconds_total)
                     AS process_cpu_seconds_total,
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


```
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


```
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
                regex='-encodedcommand (?P<Encoded>[^ ]+)'
             ).Encoded)) AS Script
        FROM watch_monitoring(artifact='Windows.Events.ProcessCreation')
        WHERE CommandLine =~ '-encodedcommand'

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

