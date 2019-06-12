---
description: These artifacts are intended to run on the server.
linktitle: Server Artifacts
menu:
  docs: {parent: Artifacts, weight: 10}
title: Server Artifacts
toc: true

---
## Server.Alerts.InteractiveShell

Velociraptor's interactive shell is a powerful feature. If you want
to monitor use of the shell on any clients, simply collect this
artifact.



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Server_Alerts_InteractiveShellDetails">View Artifact</a>
 <div class="collapse dn" id="Server_Alerts_InteractiveShellDetails" style="width: fit-content">


```
name: Server.Alerts.InteractiveShell
description: |
  Velociraptor's interactive shell is a powerful feature. If you want
  to monitor use of the shell on any clients, simply collect this
  artifact.

type: SERVER_EVENT

sources:
  - queries:
      - |
        SELECT * from watch_monitoring(artifact='Shell')
```
   </div></a>

## Server.Alerts.PsExec

Send an email if execution of the psexec service was detected on
any client. This is a server side artifact.

Note this requires that the Windows.Event.ProcessCreation
monitoring artifact be collected from clients.


Arg|Default|Description
---|------|-----------
EmailAddress|admin@example.com|
MessageTemplate|PsExec execution detected at %v: %v for client %v\n|


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Server_Alerts_PsExecDetails">View Artifact</a>
 <div class="collapse dn" id="Server_Alerts_PsExecDetails" style="width: fit-content">


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
   </div></a>

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


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Server_Analysis_Triage_PowershellConsoleDetails">View Artifact</a>
 <div class="collapse dn" id="Server_Analysis_Triage_PowershellConsoleDetails" style="width: fit-content">


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
      - LET files = SELECT ClientId,
                           file_store(path=Flow.FlowContext.uploaded_files) as LogFiles
        FROM hunt_results(
          hunt_id=huntId, artifact='Windows.Triage.Collectors.PowershellConsoleLogs')

      # A lookup between client id and FQDN
      - LET clients <= SELECT ClientId, os_info.fqdn AS FQDN from clients()

      - SELECT * FROM foreach(
          row=files,
          query={
            SELECT ClientId, {
                SELECT FQDN FROM clients where ClientId=ClientId_LU
              } As FQDN,
              Filename, Data
            FROM read_file(filenames=LogFiles)
        })
```
   </div></a>

## Server.Hunts.List

List Hunts currently scheduled on the server.



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Server_Hunts_ListDetails">View Artifact</a>
 <div class="collapse dn" id="Server_Hunts_ListDetails" style="width: fit-content">


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
   </div></a>

## Server.Hunts.Results

Show the results from each artifact collection hunt.


Arg|Default|Description
---|------|-----------
huntId|H.d05b2482|
ArtifactName|Linux.Mounts|


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Server_Hunts_ResultsDetails">View Artifact</a>
 <div class="collapse dn" id="Server_Hunts_ResultsDetails" style="width: fit-content">


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
   </div></a>

## Server.Powershell.EncodedCommand

It is possible to pass powershell an encoded script. This artifact
decodes the scripts.

NOTE: The client must be running the Windows.Events.ProcessCreation
event artifact to retrieve process execution logs.



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Server_Powershell_EncodedCommandDetails">View Artifact</a>
 <div class="collapse dn" id="Server_Powershell_EncodedCommandDetails" style="width: fit-content">


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
```
   </div></a>

