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


```text
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


```text
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

