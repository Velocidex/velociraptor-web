---
description: These artifacts attempt to detect the presence of specific compromizes.
linktitle: Detection
title: Malware Detection
weight: 60

---
## Windows.Detection.Impersonation

An access token is an object that describes the security context of
a process or thread. The information in a token includes the
identity and privileges of the user account associated with the
process or thread. When a user logs on, the system verifies the
user's password by comparing it with information stored in a
security database.

Every process has a primary token that describes the security
context of the user account associated with the process. By default,
the system uses the primary token when a thread of the process
interacts with a securable object. Moreover, a thread can
impersonate a client account. Impersonation allows the thread to
interact with securable objects using the client's security
context. A thread that is impersonating a client has both a primary
token and an impersonation token.

This artfiact enumerates all threads on the system which have an
impersonation token. I.e. they are operating with a different token
then the token the entire process has. For example mimikatz has a
command called `token::elevate` to do just such a thing:

```
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

688     {0;000003e7} 1 D 42171          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
-> Impersonated !
* Process Token : {0;000195ad} 1 F 757658339   DESKTOP-NHNHT65\mic     S-1-5-21-2310288903-2791442386-3035081252-1001  (15g,24p)       Primary
* Thread Token  : {0;000003e7} 1 D 759094260   NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)
```


{{% expand  "View Artifact Source" %}}


```text
name: Windows.Detection.Impersonation
description: |
  An access token is an object that describes the security context of
  a process or thread. The information in a token includes the
  identity and privileges of the user account associated with the
  process or thread. When a user logs on, the system verifies the
  user's password by comparing it with information stored in a
  security database.

  Every process has a primary token that describes the security
  context of the user account associated with the process. By default,
  the system uses the primary token when a thread of the process
  interacts with a securable object. Moreover, a thread can
  impersonate a client account. Impersonation allows the thread to
  interact with securable objects using the client's security
  context. A thread that is impersonating a client has both a primary
  token and an impersonation token.

  This artfiact enumerates all threads on the system which have an
  impersonation token. I.e. they are operating with a different token
  then the token the entire process has. For example mimikatz has a
  command called `token::elevate` to do just such a thing:

  ```
  mimikatz # privilege::debug
  Privilege '20' OK

  mimikatz # token::elevate
  Token Id  : 0
  User name :
  SID name  : NT AUTHORITY\SYSTEM

  688     {0;000003e7} 1 D 42171          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
  -> Impersonated !
  * Process Token : {0;000195ad} 1 F 757658339   DESKTOP-NHNHT65\mic     S-1-5-21-2310288903-2791442386-3035081252-1001  (15g,24p)       Primary
  * Thread Token  : {0;000003e7} 1 D 759094260   NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)
  ```
reference:
  - https://github.com/kslgroup/TokenImp-Token_Impersonation_Detection/blob/master/TokenImp%20documentation.pdf


precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - LET processes = SELECT Pid AS ProcPid, Name AS ProcName,
               Username, OwnerSid, TokenIsElevated,
               CommandLine, Exe
        FROM pslist()
        WHERE log(message=format(format="Inspecting %s (%v)", args=[ProcName, Pid]))

      - SELECT * FROM foreach(row=processes,
          query={
             // List all the threads and check that their tokens are the
             // same as the process token.
             SELECT ProcPid, ProcName, Username, OwnerSid, TokenIsElevated,
               CommandLine, Exe, ThreadInfo.TokenInfo AS ImpersonationToken
             FROM handles(pid=ProcPid, types='Thread')
             WHERE ImpersonationToken.User AND ImpersonationToken.User != OwnerSid
          })
```
   {{% /expand %}}

## Windows.Detection.Mutants

Enumerate the mutants from selected processes.

Mutants are often used by malware to prevent re-infection.


Arg|Default|Description
---|------|-----------
processRegex|.|A regex applied to process names.
MutantNameRegex|.+|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Detection.Mutants
description: |
  Enumerate the mutants from selected processes.

  Mutants are often used by malware to prevent re-infection.

parameters:
  - name: processRegex
    description: A regex applied to process names.
    default: .
  - name: MutantNameRegex
    default: .+

sources:
  - name: Handles
    description: Open handles to mutants. This shows processes owning a handle open to the mutant.
    queries:
      - LET processes = SELECT Pid AS ProcPid, Name AS ProcName, Exe
        FROM pslist()
        WHERE ProcName =~ processRegex AND ProcPid > 0

      - SELECT * FROM foreach(
          row=processes,
          query={
            SELECT ProcPid, ProcName, Exe, Type, Name, Handle
            FROM handles(pid=ProcPid, types="Mutant")
          })
        WHERE Name =~ MutantNameRegex

  - name: ObjectTree
    description: Reveals all Mutant objects in the Windows Object Manager namespace.
    queries:
      - SELECT Name, Type FROM winobj()
        WHERE Type = 'Mutant' AND Name =~ MutantNameRegex
```
   {{% /expand %}}

## Windows.Detection.ProcessMemory

Scanning process memory for signals is powerfull technique. This
artifact scans processes for a yara signature and when detected, the
process memory is dumped and uploaded to the server.


Arg|Default|Description
---|------|-----------
processRegex|notepad|
yaraRule|wide nocase ascii: this is a secret|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Detection.ProcessMemory
description: |
  Scanning process memory for signals is powerfull technique. This
  artifact scans processes for a yara signature and when detected, the
  process memory is dumped and uploaded to the server.

precondition: SELECT OS From info() where OS = 'windows'

parameters:
  - name: processRegex
    default: notepad
  - name: yaraRule
    default: "wide nocase ascii: this is a secret"

sources:
  - queries:
      - |
        LET processes = SELECT Name as ProcessName, CommandLine, Pid
            FROM pslist()
            WHERE Name =~ processRegex

      - |
        LET hits = SELECT * FROM foreach(
          row=processes,
          query={
             SELECT ProcessName, CommandLine, Pid, String.Offset as Offsets
             FROM proc_yara(rules=yaraRule, pid=Pid)
          })

      - |
        SELECT * FROM foreach(
          row=hits,
          query={
            SELECT ProcessName, CommandLine, Pid, Offsets, FullPath,
                   upload(file=FullPath) as CrashDump
            FROM proc_dump(pid=Pid)
          })
```
   {{% /expand %}}

## Windows.Detection.PsexecService

PSExec works by installing a new service in the system. The service
can be renamed using the -r flag and therefore it is not enough to
just watch for a new service called psexecsvc.exe. This artifact
improves on this by scanning the service binary to detect the
original psexec binary.

NOTE that if the service is very quick we are unable to examine
the service binary in time and will miss it.


Arg|Default|Description
---|------|-----------
yaraRule|wide nocase ascii: psexec|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Detection.PsexecService
description: |
  PSExec works by installing a new service in the system. The service
  can be renamed using the -r flag and therefore it is not enough to
  just watch for a new service called psexecsvc.exe. This artifact
  improves on this by scanning the service binary to detect the
  original psexec binary.

  NOTE that if the service is very quick we are unable to examine
  the service binary in time and will miss it.

type: CLIENT_EVENT

parameters:
  - name: yaraRule
    default: "wide nocase ascii: psexec"

sources:
  - queries:
      - |
        LET file_scan = SELECT  Name AS ServiceName,
               PathName, File.ModTime AS Modified,
               File.Size AS FileSize,
               String.Offset AS StringOffset,
               String.HexData AS StringContext,
               now() AS Timestamp,
               ServiceType, PID,
               {
                  SELECT Name, Exe, CommandLine
                  FROM pslist() WHERE Ppid = PID
                  LIMIT 2
               } AS ChildProcess
        FROM yara(rules=yaraRule, files=PathName)
        WHERE Rule

      - |
        LET service_creation = SELECT Parse,
            Parse.TargetInstance.Name AS Name,
            Parse.TargetInstance.PathName As PathName,
            Parse.TargetInstance.ServiceType As ServiceType,
            Parse.TargetInstance.ProcessId AS PID
        FROM wmi_events(
           query="SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Service'",
           wait=5000000,
           namespace="ROOT/CIMV2")

      - |
        SELECT * FROM foreach(
          row=service_creation,
          query=file_scan)
```
   {{% /expand %}}

## Windows.Detection.PsexecService.Kill

Psexec can launch a service remotely. This artifact implements a
client side response plan whereby all the child processes of the
service are killed.

NOTE: There is an inherent race between detection and response. If
the psexec is very quick we will miss it.


Arg|Default|Description
---|------|-----------
yaraRule|wide nocase ascii: psexec|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Detection.PsexecService.Kill
description: |
    Psexec can launch a service remotely. This artifact implements a
    client side response plan whereby all the child processes of the
    service are killed.

    NOTE: There is an inherent race between detection and response. If
    the psexec is very quick we will miss it.

type: CLIENT_EVENT

parameters:
  - name: yaraRule
    default: "wide nocase ascii: psexec"

sources:
  - queries:
      - |
        SELECT * FROM foreach(
          row={ SELECT * FROM Artifact.Windows.Detection.PsexecService() },
          query={
             SELECT ServiceName, PathName, Modified, FileSize, Timestamp,
                    ServiceType, ChildProcess, Stdout, Stderr FROM execve(
               argv=["taskkill", "/PID", PID, "/T", "/F"])
        })
```
   {{% /expand %}}

## Windows.Detection.RemoteYara.Process

Scanning process memory for signals is powerful technique. This
artefact scans processes with a remote yara rule.

The User can define a rule URL or use the default Velociraptor "Public" share:
https://\<server\>/public/remote.yar

This content also provides the user the option to dump any process with hits,
and the rule summary information.

The user is also recommended to add any endpoint agents that may cause a false
positive into the hidden parameters pathWhitelist.

Output of the rule is process information, Yara rule name, metadata and hit
data.


Arg|Default|Description
---|------|-----------
pathWhitelist|Path\nC:\\Program Files\\Microsoft Security Client ...|Process paths to exclude. Default is common\nAntiVirus we have seen cause false positives with\nsignitures in memory.\n
processRegex|.|Process name to scan as regex. Default All.
pidRegex|.|Process PID to scan as regex. Default All.
yaraURL||URL of yara rule to scan with. If empty we use\nthe server's public directory/remote.yar"\n
collectProcess||Upload process of each successful hit for for\nfurther analysis.\n
printRule||Report yara rule collection summary

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Detection.RemoteYara.Process
description: |
  Scanning process memory for signals is powerful technique. This
  artefact scans processes with a remote yara rule.

  The User can define a rule URL or use the default Velociraptor "Public" share:
  https://\<server\>/public/remote.yar

  This content also provides the user the option to dump any process with hits,
  and the rule summary information.

  The user is also recommended to add any endpoint agents that may cause a false
  positive into the hidden parameters pathWhitelist.

  Output of the rule is process information, Yara rule name, metadata and hit
  data.

author: "@mgreen27"

precondition: SELECT OS From info() where OS = 'windows'

parameters:
  - name: pathWhitelist
    description: |
        Process paths to exclude. Default is common
        AntiVirus we have seen cause false positives with
        signitures in memory.
    type: csv
    default: |
      Path
      C:\Program Files\Microsoft Security Client\MsMpEng.exe
      C:\Program Files\Cybereason ActiveProbe\AmSvc.exe
      C:\Program Files\Common Files\McAfee\AMCore\mcshield.exe
  - name: processRegex
    description: "Process name to scan as regex. Default All."
    default: .
  - name: pidRegex
    description: "Process PID to scan as regex. Default All."
    default: .
  - name: yaraURL
    description: |
        URL of yara rule to scan with. If empty we use
        the server's public directory/remote.yar"
  - name: collectProcess
    description: |
        Upload process of each successful hit for for
        further analysis.
    type: bool
  - name: printRule
    description: "Report yara rule collection summary"
    type: bool

sources:
  - queries:
      - |
        LET yara_url <= SELECT URL
          FROM switch(
            a={
                SELECT yaraURL AS URL
                FROM scope()
                WHERE URL
              },
            b={
                SELECT config.ServerUrls[0] + "public/remote.yar" AS URL
                FROM scope()
                WHERE URL
              },
            c={
                SELECT log(
                    message="yaraURL not set and no server config."),
                  NULL AS URL
                FROM scope()
              })
      - |
        LET yara_data <= SELECT Url,
                format(format="%s", args=Content) as Content,
                Response
              FROM http_client(
                chunk_size=1000000, url=(yara_url[0]).URL)
          WHERE yara_url
      - |
        LET me <= SELECT Pid FROM pslist(pid=getpid())
      - |
        LET whitelist <= SELECT upcase(string=Path) AS Path
                FROM parse_csv(filename=pathWhitelist, accessor='data')
      - |
        LET processes <= SELECT Name as ProcessName, CommandLine, Pid
            FROM pslist()
            WHERE Name =~ processRegex
                AND format(format="%d", args=Pid) =~ pidRegex
                AND NOT Pid in me.Pid
                AND NOT upcase(string=Exe) in whitelist.Path
      - |
        LET hits <= SELECT * FROM foreach(
          row=processes,
          query={
             SELECT ProcessName,
                CommandLine,
                Pid,
                Strings.Offset as Offsets,
                Namespace,
                Rule,
                Meta,
                Strings.Name as IOCname,
                format(format='%#v %s', args=[Strings.Data, Strings.Data]) as IOCdata
             FROM proc_yara(rules=yara_data.Content, pid=Pid)
          })
      - |
        SELECT * FROM hits

  - name: Rule
    queries:
      - SELECT * FROM if(
                condition=printRule,
                then={ SELECT * FROM yara_data }
            )

  - name: Upload
    queries:
      - |
        SELECT * FROM if(condition=collectProcess,
            then={
                SELECT * FROM foreach(
                  row=hits,
                  query={
                    SELECT ProcessName,
                        Pid,
                        format(format="%d.dmp", args=Pid) as UploadName,
                        upload(file=FullPath,name=format(format="%d.dmp", args=Pid)) as MiniProcDump
                    FROM proc_dump(pid=Pid)
                    GROUP BY Pid
                })
            })
```
   {{% /expand %}}

## Windows.Detection.Service.Upload

When a new service is installed, upload the service binary to the server


{{% expand  "View Artifact Source" %}}


```text
name: Windows.Detection.Service.Upload
description: |
  When a new service is installed, upload the service binary to the server

type: CLIENT_EVENT

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      # Sometimes the image path contains the full command line - we
      # try to extract the first parameter as the binary itself. Deal
      # with two options - either quoted or not.
      - SELECT ServiceName, upload(file=regex_replace(
                    source=ImagePath,
                    replace="$2",
                    re='^("([^"]+)" .+|([^ ]+) .+)')) AS Upload,
               Timestamp, _EventData, _System
        FROM Artifact.Windows.Events.ServiceCreation()
```
   {{% /expand %}}

## Windows.Detection.Thumbdrives.List

Users inserting Thumb drives or other Removable drive pose a
constant security risk. The external drive may contain malware or
other undesirable content. Additionally thumb drives are an easy way
for users to exfiltrate documents.

This artifact watches for any removable drives and provides a
complete file listing to the server for any new drive inserted. It
also provides information about any addition to the thumb drive
(e.g. a new file copied onto the drive).

We exclude very large removable drives since they might have too
many files.


Arg|Default|Description
---|------|-----------
maxDriveSize|32000000000|We ignore removable drives larger than this size in bytes.

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Detection.Thumbdrives.List
description: |
  Users inserting Thumb drives or other Removable drive pose a
  constant security risk. The external drive may contain malware or
  other undesirable content. Additionally thumb drives are an easy way
  for users to exfiltrate documents.

  This artifact watches for any removable drives and provides a
  complete file listing to the server for any new drive inserted. It
  also provides information about any addition to the thumb drive
  (e.g. a new file copied onto the drive).

  We exclude very large removable drives since they might have too
  many files.

type: CLIENT_EVENT

parameters:
  - name: maxDriveSize
    description: We ignore removable drives larger than this size in bytes.
    default: "32000000000"


sources:
  - queries:
      - |
        LET removable_disks = SELECT Name AS Drive,
            atoi(string=Data.Size) AS Size
        FROM glob(globs="/*", accessor="file")
        WHERE Data.Description =~ "Removable" AND Size < atoi(string=maxDriveSize)

      - |
        LET file_listing = SELECT FullPath,
            timestamp(epoch=Mtime.Sec) As Modified,
            Size
        FROM glob(globs=Drive+"\\**", accessor="file")
        LIMIT 1000

      - |
        SELECT * FROM diff(
          query={
             SELECT * FROM foreach(
                 row=removable_disks,
                 query=file_listing)
          },
          key="FullPath",
          period=10)
          WHERE Diff = "added"
```
   {{% /expand %}}

## Windows.Detection.Thumbdrives.OfficeKeywords

Users inserting Thumb drives or other Removable drive pose a
constant security risk. The external drive may contain malware or
other undesirable content. Additionally thumb drives are an easy way
for users to exfiltrate documents.

This artifact automatically scans any office files copied to a
removable drive for keywords. This could be useful to detect
exfiltration attempts of restricted documents.

We exclude very large removable drives since they might have too
many files.


Arg|Default|Description
---|------|-----------
officeExtensions|\\.(xls|xlsm|doc|docx|ppt|pptm)$|
yaraRule|rule Hit {\n  strings:\n    $a = "this is my secre ...|This yara rule will be run on document contents.

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Detection.Thumbdrives.OfficeKeywords
description: |
  Users inserting Thumb drives or other Removable drive pose a
  constant security risk. The external drive may contain malware or
  other undesirable content. Additionally thumb drives are an easy way
  for users to exfiltrate documents.

  This artifact automatically scans any office files copied to a
  removable drive for keywords. This could be useful to detect
  exfiltration attempts of restricted documents.

  We exclude very large removable drives since they might have too
  many files.

type: CLIENT_EVENT

parameters:
  - name: officeExtensions
    default: "\\.(xls|xlsm|doc|docx|ppt|pptm)$"
  - name: yaraRule
    description: This yara rule will be run on document contents.
    default: |
      rule Hit {
        strings:
          $a = "this is my secret" wide nocase
          $b = "this is my secret" nocase

        condition:
          any of them
      }

sources:
  - queries:
      - |
        SELECT * FROM foreach(
          row = {
            SELECT * FROM Artifact.Windows.Detection.Thumbdrives.List()
            WHERE FullPath =~ officeExtensions
          },
          query = {
            SELECT * FROM Artifact.Generic.Applications.Office.Keywords(
              yaraRule=yaraRule, searchGlob=FullPath, documentGlobs="")
          })
```
   {{% /expand %}}

## Windows.Detection.Thumbdrives.OfficeMacros

Users inserting Thumb drives or other Removable drive pose a
constant security risk. The external drive may contain malware or
other undesirable content. Additionally thumb drives are an easy way
for users to exfiltrate documents.

This artifact watches for any removable drives and scans any added
office documents for VBA macros.

We exclude very large removable drives since they might have too
many files.


Arg|Default|Description
---|------|-----------
officeExtensions|\\.(xls|xlsm|doc|docx|ppt|pptm)$|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Detection.Thumbdrives.OfficeMacros
description: |
  Users inserting Thumb drives or other Removable drive pose a
  constant security risk. The external drive may contain malware or
  other undesirable content. Additionally thumb drives are an easy way
  for users to exfiltrate documents.

  This artifact watches for any removable drives and scans any added
  office documents for VBA macros.

  We exclude very large removable drives since they might have too
  many files.

type: CLIENT_EVENT

parameters:
  - name: officeExtensions
    default: "\\.(xls|xlsm|doc|docx|ppt|pptm)$"

sources:
  - queries:
      - |
        SELECT * FROM foreach(
          row = {
            SELECT * FROM Artifact.Windows.Detection.Thumbdrives.List()
            WHERE FullPath =~ officeExtensions
          },
          query = {
            SELECT * from olevba(file=FullPath)
          })
```
   {{% /expand %}}

## Windows.Detection.WMIProcessCreation

WMI Process creation is a common lateral movement technique. The
attacker simply uses WMI to call the Create() method on the
Win32_Process WMI object.

This can be easily done via the wmic.exe command or via powershell:

```bash
wmic process call create cmd.exe
```


{{% expand  "View Artifact Source" %}}


```text
name: Windows.Detection.WMIProcessCreation
description: |
  WMI Process creation is a common lateral movement technique. The
  attacker simply uses WMI to call the Create() method on the
  Win32_Process WMI object.

  This can be easily done via the wmic.exe command or via powershell:

  ```bash
  wmic process call create cmd.exe
  ```

type: CLIENT_EVENT

sources:
  - queries:
      - |
        SELECT Parse from wmi_events(
          query="SELECT * FROM MSFT_WmiProvider_ExecMethodAsyncEvent_Pre WHERE ObjectPath=\"Win32_Process\" AND MethodName=\"Create\"",
          namespace="ROOT/CIMV2",
          wait=50000000)
```
   {{% /expand %}}

## Windows.Persistence.Debug

Windows allows specific configuration of various executables via a
registry key. Some keys allow defining a debugger to attach to a
program as it is run. If this debugger is launched for commonly used
programs (e.g. notepad) then another program can be launched at the
same time (with the same privileges).


Arg|Default|Description
---|------|-----------
imageFileExecutionOptions|HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows N ...|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Persistence.Debug
description: |
  Windows allows specific configuration of various executables via a
  registry key. Some keys allow defining a debugger to attach to a
  program as it is run. If this debugger is launched for commonly used
  programs (e.g. notepad) then another program can be launched at the
  same time (with the same privileges).

reference:
  - https://attack.mitre.org/techniques/T1183/

parameters:
  - name: imageFileExecutionOptions
    default: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*

sources:
  - queries:
      - |
        SELECT Key.Name AS Program,
               Key.FullPath as Key,
               Debugger FROM read_reg_key(
                  globs=imageFileExecutionOptions)
        WHERE Debugger
```
   {{% /expand %}}

## Windows.Persistence.PermanentWMIEvents

Malware often registers a permanent event listener within WMI. When
the event fires, the WMI system itself will invoke the consumer to
handle the event. The malware does not need to be running at the
time the event fires. Malware can use this mechanism to re-infect
the machine for example.


Arg|Default|Description
---|------|-----------
namespaces|namespace\nroot/subscription\nroot/default\n|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Persistence.PermanentWMIEvents
description: |
   Malware often registers a permanent event listener within WMI. When
   the event fires, the WMI system itself will invoke the consumer to
   handle the event. The malware does not need to be running at the
   time the event fires. Malware can use this mechanism to re-infect
   the machine for example.

parameters:
   - name: namespaces
     type: csv
     default: |
       namespace
       root/subscription
       root/default

sources:
 - precondition:
     SELECT OS from info() where OS = "windows"

   queries:
     - LET FilterToConsumerBinding = SELECT * FROM foreach(
        row={
                SELECT *
                FROM parse_csv(filename=namespaces, accessor='data')
        },
        query={
                SELECT parse_string_with_regex(string=Consumer,
                    regex=['((?P<namespace>^[^:]+):)?(?P<Type>.+?)\\.Name="(?P<Name>.+)"']) as Consumer,
                    parse_string_with_regex(string=Filter,regex=['((?P<namespace>^[^:]+):)?(?P<Type>.+?)\\.Name="(?P<Name>.+)"']) as Filter
                FROM wmi(
                    query="SELECT * FROM __FilterToConsumerBinding",namespace=namespace)
        })

     - SELECT * FROM foreach(
            row={
                    SELECT *
                    FROM parse_csv(filename=namespaces, accessor='data')
            },
            query={
                 SELECT {
                     SELECT * FROM wmi(
                       query="SELECT * FROM " + Consumer.Type,
                       namespace=if(condition=Consumer.namespace,
                          then=Consumer.namespace,
                          else=namespace)) WHERE Name = Consumer.Name
                   } AS ConsumerDetails,
                   {
                     SELECT * FROM wmi(
                       query="SELECT * FROM " + Filter.Type,
                       namespace=if(condition=Filter.namespace,
                          then=Filter.namespace,
                          else=namespace)) WHERE Name = Filter.Name
                   } AS FilterDetails,
                   namespace as Namespace
                 FROM FilterToConsumerBinding
                 WHERE (FilterDetails AND ConsumerDetails)
            })
```
   {{% /expand %}}

## Windows.Persistence.PowershellRegistry

A common way of persistence is to install a hook into a user profile
registry hive, using powershell. When the user logs in, the
powershell script downloads a payload and executes it.

This artifact searches the user's profile registry hive for
signatures related to general Powershell execution. We use a yara
signature specifically targeting the user's profile which we extract
using raw NTFS parsing (in case the user is currently logged on and
the registry hive is locked).


Arg|Default|Description
---|------|-----------
yaraRule|rule PowerShell {\n  strings:\n    $a = /ActiveXOb ...|
userRegex|.|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Persistence.PowershellRegistry
description: |
  A common way of persistence is to install a hook into a user profile
  registry hive, using powershell. When the user logs in, the
  powershell script downloads a payload and executes it.

  This artifact searches the user's profile registry hive for
  signatures related to general Powershell execution. We use a yara
  signature specifically targeting the user's profile which we extract
  using raw NTFS parsing (in case the user is currently logged on and
  the registry hive is locked).

parameters:
  - name: yaraRule
    default: |
      rule PowerShell {
        strings:
          $a = /ActiveXObject.{,500}eval/ wide nocase

        condition:
          any of them
      }
  - name: userRegex
    default: .

sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'
    queries:
      - |
        SELECT * from foreach(
        row={
          SELECT Name, Directory as HomeDir from Artifact.Windows.Sys.Users()
          WHERE Directory and Gid AND Name =~ userRegex
        },
        query={
          SELECT File.FullPath As FullPath,
                 String.Offset AS Off,
                 String.HexData As Hex,
                 upload(file=File.FullPath, accessor="ntfs") AS Upload
              FROM yara(
              files="\\\\.\\" + HomeDir + "\\ntuser.dat",
              accessor="ntfs",
              rules=yaraRule, context=50)
        })
```
   {{% /expand %}}

## Windows.Persistence.Wow64cpu

Checks for wow64cpu.dll replacement Autorun in Windows 10.
http://www.hexacorn.com/blog/2019/07/11/beyond-good-ol-run-key-part-108-2/


Arg|Default|Description
---|------|-----------
TargetRegKey|HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Wow64\\**|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Persistence.Wow64cpu
description: |
  Checks for wow64cpu.dll replacement Autorun in Windows 10.
  http://www.hexacorn.com/blog/2019/07/11/beyond-good-ol-run-key-part-108-2/

author: Matt Green - @mgreen27

parameters:
   - name: TargetRegKey
     default: HKEY_LOCAL_MACHINE\Software\Microsoft\Wow64\**
sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'

    queries:
    - |
      SELECT dirname(path=FullPath) as KeyPath,
        Name as KeyName,
        Data.value as Value,
        timestamp(epoch=Mtime.Sec) AS LastModified
      FROM glob(globs=split(string=TargetRegKey, sep=","), accessor="reg")
      WHERE Data.value and
        not (Name = "@" and (Data.value =~ "(wow64cpu.dll|wowarmhw.dll|xtajit.dll)"))
```
   {{% /expand %}}

