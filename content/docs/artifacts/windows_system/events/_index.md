---
description: These artifacts collect information related to the windows event logs.
linktitle: Event Logs
title: Event Logs
weight: 10

---
## Windows.EventLogs.AlternateLogon

Logon specifying alternate credentials - if NLA enabled on
destination Current logged-on User Name Alternate User Name
Destination Host Name/IP Process Name


Arg|Default|Description
---|------|-----------
securityLogFile|C:/Windows/System32/Winevt/Logs/Security.evtx|

{{% expand  "View Artifact Source" %}}


```text
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

## Windows.EventLogs.Cleared

Extract Event Logs related to EventLog clearing
- Security Log  - EventID 1102
- System Log - EventID 104


Arg|Default|Description
---|------|-----------
EvtxLookupTable|Glob\n%SystemRoot%\\System32\\Winevt\\Logs\\Securi ...|
SearchVSS||Add VSS into query.
DateAfter||search for events after this date. YYYY-MM-DDTmm:hh:ssZ
DateBefore||search for events before this date. YYYY-MM-DDTmm:hh:ssZ

{{% expand  "View Artifact Source" %}}


```text
name: Windows.EventLogs.Cleared

description: |
  Extract Event Logs related to EventLog clearing
  - Security Log  - EventID 1102
  - System Log - EventID 104

reference:
  - https://attack.mitre.org/versions/v6/techniques/T1070/

author: Matt Green - @mgreen27

precondition: SELECT OS From info() where OS = 'windows'

parameters:
  - name: EvtxLookupTable
    default: |
        Glob
        %SystemRoot%\System32\Winevt\Logs\Security.evtx
        %SystemRoot%\System32\Winevt\Logs\System.evtx
  - name: SearchVSS
    description: "Add VSS into query."
    type: bool
  - name: DateAfter
    type: timestamp
    description: "search for events after this date. YYYY-MM-DDTmm:hh:ssZ"
  - name: DateBefore
    type: timestamp
    description: "search for events before this date. YYYY-MM-DDTmm:hh:ssZ"

sources:
  - queries:
      # Date bounds for time box
      - LET DateAfterTime <= if(condition=DateAfter,
            then=timestamp(epoch=DateAfter), else=timestamp(epoch="1600-01-01"))
      - LET DateBeforeTime <= if(condition=DateBefore,
            then=timestamp(epoch=DateBefore), else=timestamp(epoch="2200-01-01"))

      # Extract all target paths from specified globs
      - LET evtxglobs <= SELECT expand(path=Glob) as EvtxGlob
                     FROM parse_csv(filename=EvtxLookupTable, accessor='data')

      - LET files = SELECT * FROM foreach(
            row=evtxglobs,
            query={
                SELECT * FROM if(condition=SearchVSS,
                    then= {
                        SELECT *
                        FROM Artifact.Windows.Search.VSS(SearchFilesGlob=EvtxGlob)
                    },
                    else= {
                        SELECT *, "" AS Source
                        FROM glob(globs=EvtxGlob)
                    })
                })

     # Parse all target files, order by source and add dedupe string
      - LET hits = SELECT *
            FROM foreach(
                row=files,
                query={
                    SELECT
                        timestamp(epoch=int(int=System.TimeCreated.SystemTime)) AS EventTime,
                        System.Computer as Computer,
                        System.EventID.Value as EventID,
                        System.EventRecordID as EventRecordID,
                        if(condition= System.EventID.Value = 1102,
                            then= System.Channel,
                            else= UserData.LogFileCleared.Channel) as Channel,
                        if(condition= System.EventID.Value = 1102,
                            then= UserData.LogFileCleared.SubjectDomainName + '\\' +
                                UserData.LogFileCleared.SubjectUserName,
                            else= UserData.LogFileCleared.SubjectDomainName + '\\' +
                                UserData.LogFileCleared.SubjectUserName) as UserName,
                        if(condition= System.EventID.Value = 1102,
                            then= UserData.LogFileCleared.SubjectUserSid,
                            else= System.Security.UserID) as SecurityID,
                        Message,
                        if(condition=Source, then=Source, else=FullPath) as Source,
                        format(format="%v-%v-%v",args=[System.EventID.Value,System.EventRecordID,
                            timestamp(epoch=int(int=System.TimeCreated.SystemTime))]) as _Group
                FROM parse_evtx(filename=FullPath)
                WHERE
                    EventTime < DateBeforeTime AND
                    EventTime > DateAfterTime AND
                    ( EventID = 1102 AND Channel = 'Security' ) OR
                    ( EventID = 104 AND Message =~ 'Log clear' )
            })
            ORDER BY Source DESC

      # Group results for deduplication
      - LET grouped = SELECT *
          FROM hits
          GROUP BY _Group

      # Output results
      - SELECT
            EventTime,
            Computer,
            EventID,
            EventRecordID,
            Channel,
            UserName,
            SecurityID,
            Message,
            Source
        FROM grouped
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


```text
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
    query: |
        LET files = SELECT * FROM glob(
            globs=eventDirGlob + adminLog,
            accessor=accessor)

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
    query: |
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


```text
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

## Windows.EventLogs.PowershellModule

This Artifact will search and extract Module events (Event ID 4103) from
Powershell-Operational Event Logs.

Powershell is commonly used by attackers accross all stages of the attack
lifecycle. Although quite noisy Module logging can provide valuable insight.

There are several parameter's availible for search leveraging regex.
  - DateAfter enables search for events after this date.
  - DateBefore enables search for events before this date.
  - ContextRegex enables regex search over ContextInfo text field.
  - PayloadRegex enables a regex search over Payload text field.
  - SearchVSS enables VSS search


Arg|Default|Description
---|------|-----------
EventLog|C:\\Windows\\system32\\winevt\\logs\\Microsoft-Win ...|
DateAfter||search for events after this date. YYYY-MM-DDTmm:hh:ss Z
DateBefore||search for events before this date. YYYY-MM-DDTmm:hh:ss Z
ContextRegex||regex search over Payload text field.
PayloadRegex||regex search over Payload text field.
SearchVSS||Add VSS into query.

{{% expand  "View Artifact Source" %}}


```text
name: Windows.EventLogs.PowershellModule
description: |
  This Artifact will search and extract Module events (Event ID 4103) from
  Powershell-Operational Event Logs.

  Powershell is commonly used by attackers accross all stages of the attack
  lifecycle. Although quite noisy Module logging can provide valuable insight.

  There are several parameter's availible for search leveraging regex.
    - DateAfter enables search for events after this date.
    - DateBefore enables search for events before this date.
    - ContextRegex enables regex search over ContextInfo text field.
    - PayloadRegex enables a regex search over Payload text field.
    - SearchVSS enables VSS search


author: Matt Green - @mgreen27

reference:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html

parameters:
  - name: EventLog
    default: C:\Windows\system32\winevt\logs\Microsoft-Windows-PowerShell%4Operational.evtx
  - name: DateAfter
    description: "search for events after this date. YYYY-MM-DDTmm:hh:ss Z"
    type: timestamp
  - name: DateBefore
    description: "search for events before this date. YYYY-MM-DDTmm:hh:ss Z"
    type: timestamp
  - name: ContextRegex
    description: "regex search over Payload text field."
  - name: PayloadRegex
    description: "regex search over Payload text field."
  - name: SearchVSS
    description: "Add VSS into query."
    type: bool
  - name: LogLevelMap
    type: hidden
    default: |
      Choice,Regex
      All,"."
      Warning,"3"
      Verbose,"5"

sources:
  - query: |
        -- Build time bounds
        LET DateAfterTime <= if(condition=DateAfter,
            then=timestamp(epoch=DateAfter), else=timestamp(epoch="1600-01-01"))
        LET DateBeforeTime <= if(condition=DateBefore,
            then=timestamp(epoch=DateBefore), else=timestamp(epoch="2200-01-01"))

        -- Parse Log level dropdown selection
        LET LogLevelRegex <= SELECT format(format="%v", args=Regex) as value
            FROM parse_csv(filename=LogLevelMap, accessor="data")
            WHERE Choice=LogLevel LIMIT 1

        -- Determine target files
        LET files = SELECT *
          FROM if(condition=SearchVSS,
            then= {
              SELECT *
              FROM Artifact.Windows.Search.VSS(SearchFilesGlob=EventLog)
            },
            else= {
              SELECT *
              FROM glob(globs=EventLog)
            })

        -- Main query
        LET hits = SELECT *
          FROM foreach(
            row=files,
            query={
              SELECT
                timestamp(epoch=System.TimeCreated.SystemTime) As EventTime,
                System.EventID.Value as EventID,
                System.Computer as Computer,
                System.Security.UserID as SecurityID,
                EventData.ContextInfo as ContextInfo,
                EventData.Payload as Payload,
                Message,
                System.EventRecordID as EventRecordID,
                System.Level as Level,
                System.Opcode as Opcode,
                System.Task as Task,
                if(condition=Source, then=Source, else=FullPath) as Source
              FROM parse_evtx(filename=FullPath)
              WHERE EventID = 4103
                AND EventTime > DateAfterTime
                AND EventTime < DateBeforeTime
                AND if(condition=ContextRegex,
                    then=ContextInfo=~ContextRegex,else=TRUE)
                AND if(condition=PayloadRegex,
                    then=ContextInfo=~PayloadRegex,else=TRUE)
            })
          ORDER BY Source DESC

        -- Group results for deduplication
        LET grouped = SELECT *
          FROM hits
          GROUP BY EventRecordID

        -- Output results
        SELECT
            EventTime,
            EventID,
            Computer,
            SecurityID,
            ContextInfo,
            Payload,
            Message,
            EventRecordID,
            Level,
            Opcode,
            Task,
            Source
        FROM grouped
```
   {{% /expand %}}

## Windows.EventLogs.PowershellScriptblock

This Artifact will search and extract ScriptBlock events (Event ID 4104) from
Powershell-Operational Event Logs.

Powershell is commonly used by attackers accross all stages of the attack
lifecycle. A valuable hunt is to search Scriptblock logs for signs of
malicious content.

There are several parameter's availible for search leveraging regex.
  - DateAfter enables search for events after this date.
  - DateBefore enables search for events before this date.
  - SearchStrings enables regex search over scriptblock text field.
  - StringWhiteList enables a regex whitelist for scriptblock text field.
  - PathWhitelist enables a regex whitelist for path of scriptblock.
  - LogLevel enables searching on type of log. Default is Warning level
    which is logged even if ScriptBlock logging is turned off when
    suspicious keywords detected in Powershell interpreter. See second
    reference for list of keywords.
  - SearchVSS enables VSS search


Arg|Default|Description
---|------|-----------
EventLog|C:\\Windows\\system32\\winevt\\logs\\Microsoft-Win ...|
DateAfter||search for events after this date. YYYY-MM-DDTmm:hh:ss Z
DateBefore||search for events before this date. YYYY-MM-DDTmm:hh:ss Z
SearchStrings||regex search over scriptblock text field.
StringWhitelist||Regex of string to witelist
PathWhitelist||Regex of path to whitelist.
LogLevel|Warning|Log level. Warning is Powershell default bad keyword list.
SearchVSS||Add VSS into query.

{{% expand  "View Artifact Source" %}}


```text
name: Windows.EventLogs.PowershellScriptblock
description: |
  This Artifact will search and extract ScriptBlock events (Event ID 4104) from
  Powershell-Operational Event Logs.

  Powershell is commonly used by attackers accross all stages of the attack
  lifecycle. A valuable hunt is to search Scriptblock logs for signs of
  malicious content.

  There are several parameter's availible for search leveraging regex.
    - DateAfter enables search for events after this date.
    - DateBefore enables search for events before this date.
    - SearchStrings enables regex search over scriptblock text field.
    - StringWhiteList enables a regex whitelist for scriptblock text field.
    - PathWhitelist enables a regex whitelist for path of scriptblock.
    - LogLevel enables searching on type of log. Default is Warning level
      which is logged even if ScriptBlock logging is turned off when
      suspicious keywords detected in Powershell interpreter. See second
      reference for list of keywords.
    - SearchVSS enables VSS search

author: Matt Green - @mgreen27

reference:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://github.com/PowerShell/PowerShell/blob/master/src/System.Management.Automation/engine/runtime/CompiledScriptBlock.cs#L1781-L1943

parameters:
  - name: EventLog
    default: C:\Windows\system32\winevt\logs\Microsoft-Windows-PowerShell%4Operational.evtx
  - name: DateAfter
    description: "search for events after this date. YYYY-MM-DDTmm:hh:ss Z"
    type: timestamp
  - name: DateBefore
    description: "search for events before this date. YYYY-MM-DDTmm:hh:ss Z"
    type: timestamp
  - name: SearchStrings
    description: "regex search over scriptblock text field."
  - name: StringWhitelist
    description: "Regex of string to witelist"
  - name: PathWhitelist
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
  - name: SearchVSS
    description: "Add VSS into query."
    type: bool

sources:
  - query: |
        -- Build time bounds
        LET DateAfterTime <= if(condition=DateAfter,
            then=timestamp(epoch=DateAfter), else=timestamp(epoch="1600-01-01"))
        LET DateBeforeTime <= if(condition=DateBefore,
            then=timestamp(epoch=DateBefore), else=timestamp(epoch="2200-01-01"))

        -- Parse Log level dropdown selection
        LET LogLevelRegex <= SELECT format(format="%v", args=Regex) as value
            FROM parse_csv(filename=LogLevelMap, accessor="data")
            WHERE Choice=LogLevel LIMIT 1

        -- Determine target files
        LET files = SELECT *
          FROM if(condition=SearchVSS,
            then= {
              SELECT *
              FROM Artifact.Windows.Search.VSS(SearchFilesGlob=EventLog)
            },
            else= {
              SELECT *, FullPath AS Source
              FROM glob(globs=EventLog)
            })

        -- Main query
        LET hits = SELECT *
          FROM foreach(
            row=files,
            query={
              SELECT timestamp(epoch=System.TimeCreated.SystemTime) As EventTime,
                System.EventID.Value as EventID,
                System.Computer as Computer,
                System.Security.UserID as SecurityID,
                EventData.Path as Path,
                EventData.ScriptBlockId as ScriptBlockId,
                EventData.ScriptBlockText as ScriptBlockText,
                Message,
                System.EventRecordID as EventRecordID,
                System.Level as Level,
                System.Opcode as Opcode,
                System.Task as Task,
                Source
              FROM parse_evtx(filename=FullPath)
              WHERE System.EventID.Value = 4104
                AND EventTime < DateBeforeTime
                AND EventTime > DateAfterTime
                AND format(format="%d", args=System.Level) =~ LogLevelRegex.value[0]
                AND if(condition=SearchStrings,
                    then=ScriptBlockText =~ SearchStrings,
                    else=TRUE)
                AND if(condition=StringWhitelist,
                    then= NOT ScriptBlockText =~ StringWhitelist,
                    else=TRUE)
                AND if(condition=PathWhitelist,
                    then= NOT Path =~ PathWhitelist,
                    else=TRUE)
          })
          ORDER BY Source DESC

        -- Group results for deduplication
        LET grouped = SELECT *
          FROM hits
          GROUP BY EventRecordID

        -- Output results
        SELECT
            EventTime,
            EventID,
            Computer,
            SecurityID,
            Path,
            ScriptBlockId,
            ScriptBlockText,
            Message,
            EventRecordID,
            Level,
            Opcode,
            Task,
            Source
        FROM grouped
```
   {{% /expand %}}

## Windows.EventLogs.ServiceCreationComspec


This Detection hts on the string "COMSPEC" (nocase) in Windows Service
Creation events. That is: EventID 7045 from the System event log.

This detects many hack tools that leverage SCM based lateral movement
including smbexec.

SearchVSS allows querying VSS instances of EventLog Path with event
deduplication.


Arg|Default|Description
---|------|-----------
EventLog|C:\\Windows\\system32\\winevt\\logs\\System.evtx|
ComspecRegex|(COMSPEC|cmd.exe)|
SearchVSS||Add VSS into query.

{{% expand  "View Artifact Source" %}}


```text
name: Windows.EventLogs.ServiceCreationComspec
description: |

  This Detection hts on the string "COMSPEC" (nocase) in Windows Service
  Creation events. That is: EventID 7045 from the System event log.

  This detects many hack tools that leverage SCM based lateral movement
  including smbexec.

  SearchVSS allows querying VSS instances of EventLog Path with event
  deduplication.

author: Matt Green - @mgreen27

parameters:
  - name: EventLog
    default: C:\Windows\system32\winevt\logs\System.evtx
  - name: ComspecRegex
    default: "(COMSPEC|cmd.exe)"
  - name: SearchVSS
    description: "Add VSS into query."
    type: bool

sources:
  - name: ServiceCreation
    queries:
      # Extract all target paths from glob
      - LET files = SELECT *
            FROM if(condition=SearchVSS,
                then= {
                    SELECT *
                    FROM Artifact.Windows.Search.VSS(SearchFilesGlob=EventLog)
                },
                else= {
                    SELECT *
                    FROM glob(globs=EventLog,accessor='ntfs')
                })

      # Parse all target files, order by source and add dedupe string
      - LET hits = SELECT *
            FROM foreach(
              row=files,
              query={
                SELECT timestamp(epoch=System.TimeCreated.SystemTime) as EventTime,
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
                  System.Task as Task,
                  if(condition=Source, then=Source, else=FullPath) as Source
                FROM parse_evtx(filename=FullPath, accessor='ntfs')
                WHERE System.EventID.Value = 7045 and
                  EventData.ImagePath =~ ComspecRegex
            })
            ORDER BY Source DESC

      # Group results for deduplication
      - LET grouped = SELECT *
          FROM hits
          GROUP BY EventRecordID

      # Output results
      - SELECT
            EventTime,
            EventID,
            Computer,
            SecurityID,
            ServiceAccount,
            ServiceName,
            ImagePath,
            ServiceType,
            StartType,
            EventRecordID,
            Source
        FROM grouped
```
   {{% /expand %}}

## Windows.EventLogs.Symantec

Query the Symantec Endpoint Protection Event Logs. The default artifact will 
return EventId 51 and high value strings with goals bubble up some events for 
triage.

Note:  
EventID selection is controlled by regex to allow multiple EID selections.  
If running a hunt, consider also hunting EventId 45 - Tamper Protection 
Detection (this will be noisy so whitelist is required).  
IgnoreRegex allows filtering out events relevant to the target environment.  


Arg|Default|Description
---|------|-----------
SymantecEventLog|C:\\Windows\\system32\\winevt\\logs\\Symantec Endp ...|
RegexEventIds|^51$|Regex of Event IDs to hunt for. Consider EID 45 for Tamper Protection Detection
TargetRegex|Infostealer|Hacktool|Mimi|SecurityRisk|WinCredEd|N ...|Regex to hunt for - default is high value SEP detections
IgnoreRegex||Regex to ignore events with EventData strings matching.
DateAfter||search for events after this date. YYYY-MM-DDTmm:hh:ssZ
DateBefore||search for events before this date. YYYY-MM-DDTmm:hh:ssZ

{{% expand  "View Artifact Source" %}}


```text
name: Windows.EventLogs.Symantec
description: |
  Query the Symantec Endpoint Protection Event Logs. The default artifact will 
  return EventId 51 and high value strings with goals bubble up some events for 
  triage.
  
  Note:  
  EventID selection is controlled by regex to allow multiple EID selections.  
  If running a hunt, consider also hunting EventId 45 - Tamper Protection 
  Detection (this will be noisy so whitelist is required).  
  IgnoreRegex allows filtering out events relevant to the target environment.  
  
reference: 
    - https://www.nextron-systems.com/wp-content/uploads/2019/10/Antivirus_Event_Analysis_CheatSheet_1.7.2.pdf
  
author: Matt Green - @mgreen27

parameters:
  - name: SymantecEventLog
    default: C:\Windows\system32\winevt\logs\Symantec Endpoint Protection Client.evtx
  - name: RegexEventIds
    description: "Regex of Event IDs to hunt for. Consider EID 45 for Tamper Protection Detection"
    default: ^51$
  - name: TargetRegex
    description: "Regex to hunt for - default is high value SEP detections"
    default: "Infostealer|Hacktool|Mimi|SecurityRisk|WinCredEd|NetCat|Backdoor|Pwdump|SuperScan|XScan|PasswordRevealer|Trojan|Malscript|Agent|Malware|Exploit|webshell|cobalt|Mpreter|sploit|Meterpreter|RAR|7z|encrypted|tsclient|PerfLogs" 
  - name: IgnoreRegex
    description: "Regex to ignore events with EventData strings matching."
  - name: DateAfter
    type: timestamp
    description: "search for events after this date. YYYY-MM-DDTmm:hh:ssZ"
  - name: DateBefore
    type: timestamp
    description: "search for events before this date. YYYY-MM-DDTmm:hh:ssZ"
    
sources:
    - queries:
      - LET DateAfterTime <= if(condition=DateAfter, 
            then=timestamp(epoch=DateAfter), else=timestamp(epoch="1600-01-01"))
      - LET DateBeforeTime <= if(condition=DateBefore, 
            then=timestamp(epoch=DateBefore), else=timestamp(epoch="2200-01-01"))
      - SELECT timestamp(epoch=System.TimeCreated.SystemTime) As EventTime,
              System.EventID.Value as EventId,
              System.Computer as Computer,
              EventData.Data[0] as EventData
        FROM parse_evtx(filename=SymantecEventLog)
        WHERE
            EventTime < DateBeforeTime AND
            EventTime > DateAfterTime AND
            format(format="%v",args=System.EventID.Value) =~ RegexEventIds AND
            EventData =~ TargetRegex AND
            if(condition=IgnoreRegex, 
                then= NOT EventData=~IgnoreRegex, 
                else= True)
                    
```
   {{% /expand %}}

