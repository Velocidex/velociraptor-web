---
description: These event artifacts stream monitoring events from the endpoint. We
  collect these events on the server.
linktitle: Windows Monitoring
title: Windows Event Monitoring
toc: true
weight: 60

---
## Windows.Events.DNSQueries

Monitor all DNS Queries and responses.

This artifact monitors all DNS queries and their responses seen on
the endpoint. DNS is a critical source of information for intrusion
detection and the best place to collect it is on the endpoint itself
(Perimeter collection can only see DNS requests while the endpoint
or laptop is inside the enterprise network).

It is recommended to collect this artifact and just archive the
results. When threat intelligence emerges about a watering hole or a
bad C&C you can use this archive to confirm if any of your endpoints
have contacted this C&C.


Arg|Default|Description
---|------|-----------
whitelistRegex|wpad.home|We ignore DNS names that match this regex.

{{% expand  "View Artifact Source" %}}


```
name: Windows.Events.DNSQueries
description: |
  Monitor all DNS Queries and responses.

  This artifact monitors all DNS queries and their responses seen on
  the endpoint. DNS is a critical source of information for intrusion
  detection and the best place to collect it is on the endpoint itself
  (Perimeter collection can only see DNS requests while the endpoint
  or laptop is inside the enterprise network).

  It is recommended to collect this artifact and just archive the
  results. When threat intelligence emerges about a watering hole or a
  bad C&C you can use this archive to confirm if any of your endpoints
  have contacted this C&C.

type: CLIENT_EVENT

parameters:
  - name: whitelistRegex
    description: We ignore DNS names that match this regex.
    default: wpad.home

sources:
 - precondition:
     SELECT OS from info() where OS = "windows"

   queries:
      - |
        SELECT timestamp(epoch=Time) As Time, EventType, Name, CNAME, Answers
        FROM dns()
        WHERE not Name =~ whitelistRegex

reports:
- type: MONITORING_DAILY
  template: |
    {{ define "dns" }}
       SELECT count(items=Name) AS Total, Name
       FROM source(client_id=ClientId,
                   artifact='Windows.Events.DNSQueries')
      WHERE EventType = "Q" and not Name =~ ".home.$"
      GROUP BY Name
      ORDER BY Total desc
      LIMIT 1000
    {{ end }}

    {{ $client_info := Query "SELECT * FROM clients(client_id=ClientId) LIMIT 1" }}

    # DNS Questions for {{ Get $client_info "0.os_info.fqdn" }}

    The 1000 most common DNS Queries on this day are listed in the
    below table. Typically we are looking for two interesting
    anomalies:

    1. Sorting by count for the most frequently called domains. If you
       do not recognize these it may be possible that a malware is
       frequently calling out to its C&C.

    2. Examining some of the least commonly used DNS names might
       indicate DNS exfiltration.

    {{ Query "dns" | Table }}

    > The following domains are filtered out: `.home.`
```
   {{% /expand %}}

## Windows.Events.FailedLogBeforeSuccess

Sometimes attackers will brute force an local user's account's
password. If the account password is strong, brute force attacks are
not effective and might not represent a high value event in
themselves.

However, if the brute force attempt succeeds, then it is a very high
value event (since brute forcing a password is typically a
suspicious activity).

On the endpoint this looks like a bunch of failed logon attempts in
quick succession followed by a successful login.

NOTE: In order for this artifact to work we need Windows to be
logging failed account login. This is not on by default and should
be enabled via group policy.

https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-logon-events

You can set the policy in group policy managment console (gpmc):
Computer Configuration\Windows Settings\Security Settings\Local Policies\Audit Policy.


Arg|Default|Description
---|------|-----------
securityLogFile|C:/Windows/System32/Winevt/Logs/Security.evtx|
failureCount|3|Alert if there are this many failures before the successful logon.
failedLogonTimeWindow|3600|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Events.FailedLogBeforeSuccess
description: |
  Sometimes attackers will brute force an local user's account's
  password. If the account password is strong, brute force attacks are
  not effective and might not represent a high value event in
  themselves.

  However, if the brute force attempt succeeds, then it is a very high
  value event (since brute forcing a password is typically a
  suspicious activity).

  On the endpoint this looks like a bunch of failed logon attempts in
  quick succession followed by a successful login.

  NOTE: In order for this artifact to work we need Windows to be
  logging failed account login. This is not on by default and should
  be enabled via group policy.

  https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-logon-events

  You can set the policy in group policy managment console (gpmc):
  Computer Configuration\Windows Settings\Security Settings\Local Policies\Audit Policy.
type: CLIENT_EVENT

parameters:
  - name: securityLogFile
    default: >-
      C:/Windows/System32/Winevt/Logs/Security.evtx

  - name: failureCount
    description: Alert if there are this many failures before the successful logon.
    default: 3

  - name: failedLogonTimeWindow
    default: 3600

sources:
  - precondition:
      SELECT OS FROM info() where OS = 'windows'
    queries:
      - |
        LET failed_logon = SELECT EventData as FailedEventData,
           System as FailedSystem
        FROM watch_evtx(filename=securityLogFile)
        WHERE System.EventID.Value = 4625

      - |
        LET last_5_events = SELECT FailedEventData, FailedSystem
            FROM fifo(query=failed_logon,
                      max_rows=500,
                      max_age=atoi(string=failedLogonTimeWindow))

      # Force the fifo to materialize.
      - |
        LET foo <= SELECT * FROM last_5_events

      - |
        LET success_logon = SELECT EventData as SuccessEventData,
           System as SuccessSystem
        FROM watch_evtx(filename=securityLogFile)
        WHERE System.EventID.Value = 4624

      - |
        SELECT * FROM foreach(
          row=success_logon,
          query={
           SELECT SuccessSystem.TimeCreated.SystemTime AS LogonTime,
                  SuccessSystem, SuccessEventData,
                  enumerate(items=FailedEventData) as FailedEventData,
                  FailedSystem, count(items=SuccessSystem) as Count
           FROM last_5_events
           WHERE FailedEventData.SubjectUserName = SuccessEventData.SubjectUserName
           GROUP BY LogonTime
          })  WHERE Count > atoi(string=failureCount)
```
   {{% /expand %}}

## Windows.Events.Kerbroasting

**Description**:
This Artifact will monitor all successful Kerberos TGS Ticket events for
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


Monitor and alert on unusual events from an unexpected IP.
Note: There are potential false positives so whitelist normal source IPs and
manage risk of insecure ticket generation.


Arg|Default|Description
---|------|-----------
eventLog|C:\\Windows\\system32\\winevt\\logs\\Security.evtx|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Events.Kerbroasting
description: |
  **Description**:
  This Artifact will monitor all successful Kerberos TGS Ticket events for
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


  Monitor and alert on unusual events from an unexpected IP.
  Note: There are potential false positives so whitelist normal source IPs and
  manage risk of insecure ticket generation.


author: Matt Green - @mgreen27

type: CLIENT_EVENT

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
          async=TRUE,
          query={
            SELECT *
            FROM watch_evtx(filename=FullPath)
            WHERE System.EventID.Value = 4769
                AND EventData.TicketEncryptionType = 23
                AND EventData.Status = 0
                AND NOT EventData.ServiceName =~ "krbtgt|\\$$"
                AND NOT EventData.TargetUserName =~ "\\$@"
        })
```
   {{% /expand %}}

## Windows.Events.ProcessCreation

Collect all process creation events.


Arg|Default|Description
---|------|-----------
wmiQuery|SELECT * FROM __InstanceCreationEvent WITHIN 1 WHE ...|
eventQuery|SELECT * FROM Win32_ProcessStartTrace|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Events.ProcessCreation
description: |
  Collect all process creation events.

type: CLIENT_EVENT

parameters:
  # This query will not see processes that complete within 1 second.
  - name: wmiQuery
    default: SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE
      TargetInstance ISA 'Win32_Process'

  # This query is faster but contains less data. If the process
  # terminates too quickly we miss its commandline.
  - name: eventQuery
    default: SELECT * FROM Win32_ProcessStartTrace

sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'
    queries:
      - |
        // Convert the timestamp from WinFileTime to Epoch.
        SELECT timestamp(epoch=atoi(string=Parse.TIME_CREATED) / 10000000 - 11644473600 ) as Timestamp,
               Parse.ParentProcessID as PPID,
               Parse.ProcessID as PID,
               Parse.ProcessName as Name, {
                 SELECT CommandLine
                 FROM wmi(
                   query="SELECT * FROM Win32_Process WHERE ProcessID = " +
                    format(format="%v", args=Parse.ProcessID),
                   namespace="ROOT/CIMV2")
               } AS CommandLine,
               {
                 SELECT CommandLine
                 FROM wmi(
                   query="SELECT * FROM Win32_Process WHERE ProcessID = " +
                    format(format="%v", args=Parse.ParentProcessID),
                   namespace="ROOT/CIMV2")
               } AS ParentInfo
        FROM wmi_events(
           query=eventQuery,
           wait=5000000,   // Do not time out.
           namespace="ROOT/CIMV2")
```
   {{% /expand %}}

## Windows.Events.ServiceCreation

Monitor for creation of new services.

New services are typically created by installing new software or
kernel drivers. Attackers will sometimes install a new service to
either insert a malicious kernel driver or as a persistence
mechanism.

This event monitor extracts the service creation events from the
event log and records them on the server.


Arg|Default|Description
---|------|-----------
systemLogFile|C:/Windows/System32/Winevt/Logs/System.evtx|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Events.ServiceCreation
description: |
  Monitor for creation of new services.

  New services are typically created by installing new software or
  kernel drivers. Attackers will sometimes install a new service to
  either insert a malicious kernel driver or as a persistence
  mechanism.

  This event monitor extracts the service creation events from the
  event log and records them on the server.
type: CLIENT_EVENT

parameters:
  - name: systemLogFile
    default: >-
      C:/Windows/System32/Winevt/Logs/System.evtx

sources:
 - precondition:
     SELECT OS from info() where OS = "windows"

   queries:
      - |
        SELECT System.TimeCreated.SystemTime as Timestamp,
               System.EventID.Value as EventID,
               EventData.ImagePath as ImagePath,
               EventData.ServiceName as ServiceName,
               EventData.ServiceType as Type,
               System.Security.UserID as UserSID,
               EventData as _EventData,
               System as _System
        FROM watch_evtx(filename=systemLogFile) WHERE EventID = 7045
```
   {{% /expand %}}

