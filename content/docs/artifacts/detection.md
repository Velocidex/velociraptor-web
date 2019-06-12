---
description: These artifacts attempt to detect the presence of specific compromizes.
linktitle: Windows Detection
menu:
  docs: {parent: Artifacts, weight: 20}
title: Windows Malware Detection
toc: true

---
## Windows.Detection.ProcessMemory

Scanning process memory for signals is powerfull technique. This
artifact scans processes for a yara signature and when detected, the
process memory is dumped and uploaded to the server.


Arg|Default|Description
---|------|-----------
processRegex|notepad|
yaraRule|rule Process {\n   strings:\n     $a = "this is a secret" nocase wide\n     $b = "this is a secret" nocase\n   condition:\n     any of them\n}\n|

{{% expand  "View Artifact Source" %}}


```
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
    default: |
      rule Process {
         strings:
           $a = "this is a secret" nocase wide
           $b = "this is a secret" nocase
         condition:
           any of them
      }

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
             SELECT ProcessName, CommandLine, Pid, Strings.Offset as Offsets
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


Arg|Default|Description
---|------|-----------
yaraRule|rule PsExec {\n  strings:\n    $a = "psexec" nocase\n    $b = "psexec" nocase wide\n\n  condition:\n    any of them\n}\n|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Detection.PsexecService
description: |
  PSExec works by installing a new service in the system. The service
  can be renamed using the -r flag and therefore it is not enough to
  just watch for a new service called psexecsvc.exe. This artifact
  improves on this by scanning the service binary to detect the
  original psexec binary.

type: CLIENT_EVENT

parameters:
  - name: yaraRule
    default: |
      rule PsExec {
        strings:
          $a = "psexec" nocase
          $b = "psexec" nocase wide

        condition:
          any of them
      }

sources:
  - queries:
      - |
        LET file_scan = SELECT File, Rule, Strings, now() AS Timestamp,
               Name, ServiceType
        FROM yara(rules=yaraRule, files=PathName)
        WHERE Rule

      - |
        LET service_creation = SELECT Parse.TargetInstance.Name AS Name,
               Parse.TargetInstance.PathName As PathName,
               Parse.TargetInstance.ServiceType As ServiceType
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


```
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
        WHERE Data.Description =~ "Removable" AND
           Size < atoi(string=maxDriveSize)

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
yaraRule|rule Hit {\n  strings:\n    $a = "this is my secret" wide nocase\n    $b = "this is my secret" nocase\n\n  condition:\n    any of them\n}\n|This yara rule will be run on document contents.

{{% expand  "View Artifact Source" %}}


```
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


```
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

```
wmic process create cmd.exe
```


{{% expand  "View Artifact Source" %}}


```
name: Windows.Detection.WMIProcessCreation
description: |
  WMI Process creation is a common lateral movement technique. The
  attacker simply uses WMI to call the Create() method on the
  Win32_Process WMI object.

  This can be easily done via the wmic.exe command or via powershell:

  ```
  wmic process create cmd.exe
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
imageFileExecutionOptions|HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*|

{{% expand  "View Artifact Source" %}}


```
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
namespace|root/subscription|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Persistence.PermanentWMIEvents
description: |
   Malware often registers a permanent event listener within WMI. When
   the event fires, the WMI system itself will invoke the consumer to
   handle the event. The malware does not need to be running at the
   time the event fires. Malware can use this mechanism to re-infect
   the machine for example.

parameters:
  - name: namespace
    default: root/subscription

sources:
 - precondition:
     SELECT OS from info() where OS = "windows"
   queries:
   - |
     LET FilterToConsumerBinding = SELECT parse_string_with_regex(
        string=Consumer,
        regex=['((?P<namespace>^[^:]+):)?(?P<Type>.+?)\\.Name="(?P<Name>.+)"']) as Consumer,
          parse_string_with_regex(
        string=Filter,
        regex=['((?P<namespace>^[^:]+):)?(?P<Type>.+?)\\.Name="(?P<Name>.+)"']) as Filter
     FROM wmi(
         query="SELECT * FROM __FilterToConsumerBinding",
         namespace=namespace)
   - |
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
       } AS FilterDetails
     FROM FilterToConsumerBinding
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
yaraRule|rule PowerShell {\n  strings:\n    $a = /ActiveXObject.{,500}eval/ wide nocase\n\n  condition:\n    any of them\n}\n|

{{% expand  "View Artifact Source" %}}


```
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

sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'
    queries:
      - |
        SELECT * from foreach(
        row={
          SELECT Name, Directory as HomeDir from Artifact.Windows.Sys.Users()
          WHERE Directory and Gid
        },
        query={
          SELECT File.FullPath As FullPath,
                 Strings.Offset AS Off,
                 Strings.HexData As Hex,
                 upload(file=File.FullPath, accessor="ntfs") AS Upload
              FROM yara(
              files="\\\\.\\" + HomeDir + "\\ntuser.dat",
              accessor="ntfs",
              rules=yaraRule, context=50)
        })
```
   {{% /expand %}}

