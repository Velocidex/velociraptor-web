---
description: These artifacts collect information related to the windows system itself.
linktitle: Windows System
menu:
  docs: {parent: Artifacts, weight: 5}
title: Windows System
toc: true

---
## Windows.Sys.AppcompatShims

Application Compatibility shims are a way to persist malware. This
table presents the AppCompat Shim information from the registry in a
nice format.


Arg|Default|Description
---|------|-----------
shimKeys|HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB\\*|
customKeys|HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom\\*\\*|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Sys.AppcompatShims
description: |
  Application Compatibility shims are a way to persist malware. This
  table presents the AppCompat Shim information from the registry in a
  nice format.

reference:
  - http://files.brucon.org/2015/Tomczak_and_Ballenthin_Shims_for_the_Win.pdf

parameters:
  - name: shimKeys
    default: >-
      HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\*
  - name: customKeys
    default: >-
      HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\*\*

sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'
    queries:
      - |
        LET installed_sdb <=
           SELECT Key, Key.Name as SdbGUID, DatabasePath,
                  DatabaseType, DatabaseDescription,
                  -- Convert windows file time to unix epoch.
                  (DatabaseInstallTimeStamp / 10000000) - 11644473600 AS DatabaseInstallTimeStamp
           FROM read_reg_key(
             globs=split(string=shimKeys, sep=",[\\s]*"),
             accessor="reg")
      - |
        LET result = SELECT * from foreach(
          row={
            SELECT regex_replace(
               source=FullPath,
               replace="$1",
               re="^.+\\\\([^\\\\]+)\\\\[^\\\\]+$") as Executable,
              regex_replace(
               source=Name,
               replace="$1",
               re="(\\{[^}]+\\}).*$") as SdbGUIDRef,
               Name as ExeName from glob(
              globs=split(string=customKeys, sep=",[\\s]*"),
              accessor="reg")
          },
          query={
            SELECT Executable, DatabasePath, DatabaseType,
                   DatabaseDescription, DatabaseInstallTimeStamp, SdbGUID
            FROM installed_sdb
            WHERE SdbGUID = SdbGUIDRef
          })
      - |
        SELECT * from result
```
   {{% /expand %}}

## Windows.Sys.CertificateAuthorities

Certificate Authorities installed in Keychains/ca-bundles.

{{% expand  "View Artifact Source" %}}


```
name: Windows.Sys.CertificateAuthorities
description: Certificate Authorities installed in Keychains/ca-bundles.
sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'
    queries:
      - |
        select Store, IsCA, Subject,
               encode(string=SubjectKeyId, type='hex') AS SubjectKeyId,
               encode(string=AuthorityKeyId, type='hex') AS AuthorityKeyId,
               Issuer, KeyUsageString,
               IsSelfSigned, SHA1, SignatureAlgorithm, PublicKeyAlgorithm, KeyStrength,
               NotBefore, NotAfter, HexSerialNumber
               from certificates()
```
   {{% /expand %}}

## Windows.Sys.DiskInfo

Retrieve basic information about the physical disks of a system.

{{% expand  "View Artifact Source" %}}


```
name: Windows.Sys.DiskInfo
description: Retrieve basic information about the physical disks of a system.
sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'
    queries:
      - |
        SELECT Partitions,
               Index as DiskIndex,
               InterfaceType as Type,
               PNPDeviceID,
               DeviceID,
               Size,
               Manufacturer,
               Model,
               Name,
               SerialNumber,
               Description
        FROM wmi(
           query="SELECT * from Win32_DiskDrive",
           namespace="ROOT\\CIMV2")
```
   {{% /expand %}}

## Windows.Sys.Drivers

Details for in-use Windows device drivers. This does not display installed but unused drivers.

{{% expand  "View Artifact Source" %}}


```
name: Windows.Sys.Drivers
description: Details for in-use Windows device drivers. This does not display installed but unused drivers.
sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'
    queries:
      - |
        SELECT * from wmi(
            query="select * from Win32_PnPSignedDriver",
            namespace="ROOT\\CIMV2")
```
   {{% /expand %}}

## Windows.Sys.FirewallRules

List windows firewall rules.

Arg|Default|Description
---|------|-----------
regKey|HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\**\\FirewallRules\\*|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Sys.FirewallRules
description: List windows firewall rules.
reference:
  - https://social.technet.microsoft.com/Forums/azure/en-US/aaed9c6a-fb8b-4d43-8b69-9f4e0f619a8c/how-to-check-the-windows-firewall-settings-from-netsh-command?forum=winserverGP

parameters:
  - name: regKey
    default: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\**\FirewallRules\*

sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'
    queries:
      - |
        LET rules = SELECT Name as Value,
               parse_string_with_regex(string=Data,
                 regex=["Action=(?P<Action>[^|]+)",
                        "Active=(?P<Active>[^|]+)",
                        "Dir=(?P<Dir>[^|]+)",
                        "Protocol=(?P<Protocol>[^|]+)",
                        "LPort=(?P<LPort>[^|]+)",
                        "Name=(?P<Name>[^|]+)",
                        "Desc=(?P<Desc>[^|]+)",
                        "App=(?P<App>[^|]+)"]) as Record,
               Data,
               FullPath
        FROM glob(globs=regKey, accessor="reg")

      - |
        SELECT Value,
               Record.Action as Action,
               Record.Name as Name,
               Record.Desc as Desc,
               Record.App as App,
               Record.Action as Action,
               Record.Dir as Dir,
               if(condition=Record.Protocol = "6",
                  then="TCP",
                  else=if(condition=Record.Protocol = "17",
                          then="UDP",
                          else=Record.Protocol)) as Protocol,
               if(condition=Record.LPort = NULL,
                  then="Any",
                  else=Record.LPort) as LPort,
               Record.Name as Name
        FROM rules
```
   {{% /expand %}}

## Windows.Sys.Interfaces

Report information about the systems interfaces. This artifact
simply parses the output from ipconfig /all.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Sys.Interfaces
description: |
  Report information about the systems interfaces. This artifact
  simply parses the output from ipconfig /all.

sources:
 - precondition:
     SELECT OS from info() where OS = "windows"
   queries:
   - |
     // Run ipconfig to get all information about interfaces.
     LET ipconfig = SELECT * FROM execve(argv=['ipconfig', '/all'])
   - |
     // This produces a single row per interface.
     LET interfaces = SELECT Name, Data FROM parse_records_with_regex(
        file=ipconfig.Stdout,
        accessor='data',      // This makes the data appear as a file.
        regex='(?s)Ethernet adapter (?P<Name>[^:]+?):\r\n\r\n(?P<Data>.+?)\r\n(\r\n|$)')
   - |
     // Now extract interesting things from each interface definition.
     SELECT Name, parse_string_with_regex(
        string=Data,
        regex=[
          "Description[^:]+: (?P<Description>.+)\r\n",
          "Physical Address[^:]+: (?P<MAC>.+)\r\n",
          "IPv4 Address[^:]+: (?P<IP>[0-9.]+)",
          "Default Gateway[^:]+: (?P<Gateway>.+)\r\n",
          "DNS Servers[^:]+: (?P<DNS>.+)\r\n",
          "DHCP Server[^:]+: (?P<DHCP>.+)\r\n"
        ]
     ) As Details FROM interfaces
```
   {{% /expand %}}

## Windows.Sys.PhysicalMemoryRanges

List Windows physical memory ranges.

Arg|Default|Description
---|------|-----------
physicalMemoryKey|HKEY_LOCAL_MACHINE\\HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory\\.Translated|
Profile|{\n  "CM_RESOURCE_LIST": [0, {\n    "Count": [0, ["uint32"]],\n    "List": [4, ["CM_FULL_RESOURCE_DESCRIPTOR"]]\n   }],\n   "CM_FULL_RESOURCE_DESCRIPTOR": [0, {\n     "PartialResourceList": [8, ["CM_PARTIAL_RESOURCE_LIST"]]\n   }],\n\n   "CM_PARTIAL_RESOURCE_LIST": [0, {\n     "Version": [0, ["uint16"]],\n     "Revision": [2, ["uint16"]],\n     "Count": [4, ["uint32"]],\n     "PartialDescriptors": [8, ["Array", {\n        "Target": "CM_PARTIAL_RESOURCE_DESCRIPTOR"\n     }]]\n   }],\n\n   "CM_PARTIAL_RESOURCE_DESCRIPTOR": [20, {\n     "Type": [0, ["char"]],\n     "ShareDisposition": [1, ["char"]],\n     "Flags": [2, ["uint16"]],\n     "Start": [4, ["int64"]],\n     "Length": [12, ["uint32"]]\n   }]\n}\n|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Sys.PhysicalMemoryRanges
description: List Windows physical memory ranges.
reference:
  - https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/ns-wdm-_cm_resource_list

parameters:
  - name: physicalMemoryKey
    default: HKEY_LOCAL_MACHINE\HARDWARE\RESOURCEMAP\System Resources\Physical Memory\.Translated

  - name: Profile
    default: |
      {
        "CM_RESOURCE_LIST": [0, {
          "Count": [0, ["uint32"]],
          "List": [4, ["CM_FULL_RESOURCE_DESCRIPTOR"]]
         }],
         "CM_FULL_RESOURCE_DESCRIPTOR": [0, {
           "PartialResourceList": [8, ["CM_PARTIAL_RESOURCE_LIST"]]
         }],

         "CM_PARTIAL_RESOURCE_LIST": [0, {
           "Version": [0, ["uint16"]],
           "Revision": [2, ["uint16"]],
           "Count": [4, ["uint32"]],
           "PartialDescriptors": [8, ["Array", {
              "Target": "CM_PARTIAL_RESOURCE_DESCRIPTOR"
           }]]
         }],

         "CM_PARTIAL_RESOURCE_DESCRIPTOR": [20, {
           "Type": [0, ["char"]],
           "ShareDisposition": [1, ["char"]],
           "Flags": [2, ["uint16"]],
           "Start": [4, ["int64"]],
           "Length": [12, ["uint32"]]
         }]
      }

sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'
    queries:
      - |
        SELECT Type.AsInteger as Type,
               format(format="%#0x", args=Start.AsInteger) as Start,
               format(format="%#0x", args=Length.AsInteger) as Length
        FROM foreach(
          row={
            SELECT Data
              FROM stat(filename=physicalMemoryKey, accessor='reg')
          },
          query={
            SELECT Type, Start, Length, Data FROM binary_parse(
              string=Data.value,
              profile=Profile,
              target="CM_RESOURCE_LIST",
              start="List.PartialResourceList.PartialDescriptors")
          })
```
   {{% /expand %}}

## Windows.Sys.Programs

Represents products as they are installed by Windows Installer. A product generally
correlates to one installation package on Windows. Some fields may be blank as Windows
installation details are left to the discretion of the product author.


Arg|Default|Description
---|------|-----------
programKeys|HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Sys.Programs
description: |
  Represents products as they are installed by Windows Installer. A product generally
  correlates to one installation package on Windows. Some fields may be blank as Windows
  installation details are left to the discretion of the product author.
reference:
  - https://github.com/facebook/osquery/blob/master/specs/windows/programs.table

parameters:
  - name: programKeys
    default: >-
      HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*,
      HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
      HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Uninstall\*

sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'
    queries:
      - |
        SELECT Key.Name as Name,
               DisplayName,
               DisplayVersion,
               InstallLocation,
               InstallSource,
               Language,
               Publisher,
               UninstallString,
               InstallDate
        FROM read_reg_key(globs=split(string=programKeys, sep=',[\\s]*'))
```
   {{% /expand %}}

## Windows.Sys.StartupItems

Applications that will be started up from the various run key locations.

Arg|Default|Description
---|------|-----------
runKeyGlobs|HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*\\*, HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run*\\*, HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run*\\* HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*\\*, HKEY_USERS\\*\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run*\\*, HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run*\\*\n|
startupApprovedGlobs|HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\**, HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\**\n|
startupFolderDirectories|C:/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/**, C:/Users/*/AppData/Roaming/Microsoft/Windows/StartMenu/Programs/Startup/**\n|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Sys.StartupItems
description: Applications that will be started up from the various run key locations.
reference:
  - https://docs.microsoft.com/en-us/windows/desktop/setupapi/run-and-runonce-registry-keys

parameters:
  - name: runKeyGlobs
    default: >
      HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*\*,
      HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run*\*,
      HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run*\*
      HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*\*,
      HKEY_USERS\*\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run*\*,
      HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run*\*
  - name: startupApprovedGlobs
    default: >
      HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\**,
      HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\**
  - name: startupFolderDirectories
    default: >
      C:/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/**,
      C:/Users/*/AppData/Roaming/Microsoft/Windows/StartMenu/Programs/Startup/**

sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'
    queries:
      - |
        /* We need to search this multiple times so we materialize it
           into a variable (using the <= operator)
         */
        LET approved <=
           SELECT Name as ApprovedName,
                  encode(string=Data, type="hex") as Enabled
           FROM glob(globs=split(
                     string=startupApprovedGlobs, sep="[, ]+"),
                     accessor="reg")
           WHERE Enabled =~ "^0[0-9]0+$"

      - |
        LET registry_runners = SELECT Name,
          FullPath, Data.value as Command,
          if(
           condition={
                SELECT Enabled from approved
                WHERE Name = ApprovedName
           },
           then="enabled", else="disabled") as Enabled
          FROM glob(
           globs=split(string=runKeyGlobs, sep="[, ]+"),
           accessor="reg")

      - |
        LET file_runners = SELECT * FROM foreach(
           row={
              SELECT Name, FullPath
              FROM glob(
                 globs=split(string=startupFolderDirectories,
                 sep=",\\s*"))
           }, query={
              SELECT Name, FullPath, "enable" as Enabled,
                  encode(string=Data, type='utf16') as Command
              FROM read_file(filenames=FullPath)
           })

      - |
        SELECT * from chain(
           first=registry_runners,
           second=file_runners)
```
   {{% /expand %}}

## Windows.Sys.Users

List User accounts. We combine two data sources - the output from
the NetUserEnum() call and the list of SIDs in the registry.


Arg|Default|Description
---|------|-----------
remoteRegKey|HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\*|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Sys.Users
description: |
  List User accounts. We combine two data sources - the output from
  the NetUserEnum() call and the list of SIDs in the registry.

parameters:
  - name: remoteRegKey
    default: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*

sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'
    queries:
      - |
        LET roaming_users <= SELECT "" as Uid, "" as Gid,
               lookupSID(
                 sid=basename(path=Key.FullPath)
               ) as Name,
               Key.FullPath as Description,
               ProfileImagePath as Directory,
               basename(path=Key.FullPath) as UUID,
               Key.Mtime.Sec as Mtime,
               "roaming" as Type
           FROM read_reg_key(globs=remoteRegKey, accessor="reg")
      - |
        LET local_users <= select User_id as Uid, Primary_group_id as Gid, Name,
               Comment as Description, {
                 SELECT Directory from roaming_users WHERE User_sid = UUID
               } as Directory, User_sid as UUID, 0 AS Mtime, "local" AS Type
        FROM users()

      - |
        LET local_users_with_mtime = SELECT Uid, Gid, Name, Description,
            Directory, UUID, {
                SELECT Mtime.Sec FROM stat(filename=expand(path=Directory))
            } As Mtime, Type
        FROM local_users

      - |
        SELECT * from chain(
         q1=local_users_with_mtime,
         q2={
           -- Only show users not already shown in the local_users above.
           SELECT * from roaming_users
           where not UUID in local_users.UUID
         })


reports:
  - type: HUNT
    template: |
      # Users Hunt

      Enumerating all the users on all endpoints can reveal machines
      which had an unexpected login activity. For example, if a user
      from an unrelated department is logging into an endpoint by
      virtue of domain credentials, this could mean their account is
      compromised and the attackers are laterally moving through the
      network.

      {{ define "users" }}
         SELECT Name, UUID, Fqdn, timestamp(epoch=Mtime) as LastMod FROM source()
         WHERE NOT UUID =~ "(-5..$|S-1-5-18|S-1-5-19|S-1-5-20)"
      {{ end }}

      {{ Query "users" | Table }}

  - type: CLIENT
    template: |

      System Users
      ============

      {{ .Description }}

      The following table shows basic information about the users on this system.

      * Remote users also show the modification timestamp from the
        registry key.

      * Local users show the mtime of their home directory.

      {{ define "users" }}
         LET users <= SELECT Name, UUID, Type,
               timestamp(epoch=Mtime) as Mtime
         FROM source()
      {{ end }}
      {{ Query "users" "SELECT Name, UUID, Type, Mtime FROM users" | Table }}
```
   {{% /expand %}}

## Windows.System.Amcache

Get information from the system's amcache.

The Amcache.hve file is a registry file that stores the information
of executed applications. Amcache.hve records the recent processes
that were run and lists the path of the files that’s executed which
can then be used to find the executed program.

This artifact works on Windows 10 1607 version.

References:
  https://www.andreafortuna.org/cybersecurity/amcache-and-shimcache-in-forensic-analysis/
  https://www.ssi.gouv.fr/uploads/2019/01/anssi-coriin_2019-analysis_amcache.pdf


Arg|Default|Description
---|------|-----------
amCacheGlob|%SYSTEMROOT%/appcompat/Programs/Amcache.hve|
amCacheRegPath|/Root/InventoryApplicationFile/*|

{{% expand  "View Artifact Source" %}}


```
name: Windows.System.Amcache
description: |
  Get information from the system's amcache.

  The Amcache.hve file is a registry file that stores the information
  of executed applications. Amcache.hve records the recent processes
  that were run and lists the path of the files that’s executed which
  can then be used to find the executed program.

  This artifact works on Windows 10 1607 version.

  References:
    https://www.andreafortuna.org/cybersecurity/amcache-and-shimcache-in-forensic-analysis/
    https://www.ssi.gouv.fr/uploads/2019/01/anssi-coriin_2019-analysis_amcache.pdf

parameters:
  - name: amCacheGlob
    default: "%SYSTEMROOT%/appcompat/Programs/Amcache.hve"
  - name: amCacheRegPath
    default: /Root/InventoryApplicationFile/*

precondition: |
  SELECT OS From info() where OS = 'windows'

sources:
  - name: InventoryApplicationFile
    queries:
      - |
        SELECT FileId,
               Key.FullPath as Key,
               timestamp(epoch=Key.Mtime.Sec) as LastModified,
               Key.Mtime.Sec as _LastModified,
               LowerCaseLongPath as Binary,
               Name,
               Size,
               ProductName,
               Publisher,
               Version,
               BinFileVersion
        FROM foreach(
          row={
            SELECT FullPath from glob(globs=expand(path=amCacheGlob))
          }, query={
            SELECT * from read_reg_key(
               globs=url(scheme='ntfs', path=FullPath,
                         fragment=amCacheRegPath).String,
               accessor='raw_reg'
            )
        })

  - name: File
    queries:
      - |
        SELECT * FROM foreach(
          row={
            SELECT FullPath from glob(globs=expand(path=amCacheGlob))
          }, query={
            SELECT get(item=scope(), member="100") As ProductId,
                   get(item=scope(), member="101") As SHA1,
                   get(item=scope(), member="15") As FullPath,
                   timestamp(epoch=Key.Mtime.Sec) as LastModifiedKey
            FROM read_reg_key(
               globs=url(scheme='ntfs', path=FullPath,
                         fragment='/Root/File/*/*').String,
               accessor='raw_reg'
            )
        })

reports:
  - type: CLIENT
    template: |
      {{define "recent_executions"}}
           LET recent_executions <= SELECT LastModified, Name, count(items=Name) As Count,
                  int(int=_LastModified/3600) AS Hour
           FROM source(source="InventoryApplicationFile")
           GROUP BY Hour
           LIMIT 500
      {{ end }}

      {{ define "timeline" }}
         SELECT LastModified,
                format(format="%s (%d)", args=[Name, Count]) As TotalCount
         FROM recent_executions
      {{ end }}

      The AMCache file
      ================

      {{ .Description }}

      ## Execution clusters

      The AMCache artifact only shows us the time of first execution
      of a binary. We get an idea when it was installed. Typically
      execution artifacts are clustered in time - if an attacker
      copies a bunch of new tools they will all start running at about
      the same time.

      The below timeline shows a summary of execution clusters. The
      binaries are grouped in an hour interval. The label is the first
      binary name and the total number of binaries within that hour.

      > For clarity we hide the names of all other binaries, and just
        show the total count.

      {{ Query "recent_executions" "timeline" | Timeline }}


      Here is the same data in tabular form.

      {{ Query "timeline" | Table }}
```
   {{% /expand %}}

## Windows.System.Pslist

List processes and their running binaries.


Arg|Default|Description
---|------|-----------
processRegex|.|

{{% expand  "View Artifact Source" %}}


```
name: Windows.System.Pslist
description: |
  List processes and their running binaries.

parameters:
  - name: processRegex
    default: .

sources:
  - queries:
      - |
        SELECT Pid, Ppid, Name, CommandLine, Exe,
               hash(path=Exe) as Hash,
               authenticode(filename=Exe) AS Authenticode,
               Username, WorkingSetSize
        FROM pslist()
        WHERE Name =~ processRegex
```
   {{% /expand %}}

## Windows.System.SVCHost

Typically a windows system will have many svchost.exe
processes. Sometimes attackers name their processes svchost.exe to
try to hide. Typically svchost.exe is spawned by services.exe.

This artifact lists all the processes named svchost.exe and their
parents if the parent is not also named services.exe.


{{% expand  "View Artifact Source" %}}


```
name: Windows.System.SVCHost
description: |
  Typically a windows system will have many svchost.exe
  processes. Sometimes attackers name their processes svchost.exe to
  try to hide. Typically svchost.exe is spawned by services.exe.

  This artifact lists all the processes named svchost.exe and their
  parents if the parent is not also named services.exe.

sources:
  - precondition: |
      SELECT OS From info() where OS = 'windows'

    queries:
      - |
        // Cache the pslist output in memory.
        LET processes <= SELECT * FROM pslist()

      - |
        // Get the pids of all procecesses named services.exe
        LET services <= SELECT Pid FROM processes where Name =~ "services.exe"

      - |
        // The interesting processes are those which are not spawned by services.exe
        LET suspicious = SELECT Pid As SVCHostPid,
            Ppid As SVCHostPpid,
            Exe as SVCHostExe,
            CommandLine as SVCHostCommandLine
        FROM processes
        WHERE Name =~ "svchost" AND NOT Ppid in services.Pid

      - |
        // Now for each such process we display its actual parent.
        SELECT * from foreach(
           row=suspicious,
           query={
              SELECT SVCHostPid, SVCHostPpid, SVCHostExe,
                     SVCHostCommandLine, Name as ParentName,
                     Exe As ParentExe
              FROM processes
              WHERE Pid=SVCHostPpid
          })
```
   {{% /expand %}}

## Windows.System.Services

List all the installed services.


Arg|Default|Description
---|------|-----------
servicesKeyGlob|HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\|

{{% expand  "View Artifact Source" %}}


```
name: Windows.System.Services
description: |
  List all the installed services.

parameters:
  - name: servicesKeyGlob
    default: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\

sources:
  - precondition: |
      SELECT OS From info() where OS = 'windows'

    queries:
      - |
        SELECT State, Name, DisplayName, Status,
               ProcessId as Pid, ExitCode, StartMode,
               PathName, ServiceType, StartName as UserAccount,
               {
                  SELECT timestamp(epoch=Mtime.Sec) as Created
                  FROM stat(filename=servicesKeyGlob + Name, accessor='reg')
               } AS Created,
               {
                 SELECT ServiceDll FROM read_reg_key(globs=servicesKeyGlob + Name + "\\Parameters")
               } AS ServiceDll
        FROM wmi(query="SELECT * From Win32_service", namespace="root/CIMV2")
```
   {{% /expand %}}

## Windows.System.UntrustedBinaries

Windows runs a number of services and binaries as part of the
operating system. Sometimes malware pretends to run as those well
known names in order to hide itself in plain sight. For example, a
malware service might call itself svchost.exe so it shows up in the
process listing as a benign service.

This artifact checks that the common systems binaries are
signed. If a malware replaces these files or names itself in this
way their signature might not be correct.

Note that unfortunately Microsoft does not sign all their common
binaries so many will not be signed (e.g. conhost.exe).


Arg|Default|Description
---|------|-----------
processNamesRegex|(?i)lsass|svchost|conhost|taskmgr|winlogon|wmiprv|dwm|csrss|velociraptor|A regex to select running processes which we consider should be trusted.

{{% expand  "View Artifact Source" %}}


```
name: Windows.System.UntrustedBinaries
description: |
  Windows runs a number of services and binaries as part of the
  operating system. Sometimes malware pretends to run as those well
  known names in order to hide itself in plain sight. For example, a
  malware service might call itself svchost.exe so it shows up in the
  process listing as a benign service.

  This artifact checks that the common systems binaries are
  signed. If a malware replaces these files or names itself in this
  way their signature might not be correct.

  Note that unfortunately Microsoft does not sign all their common
  binaries so many will not be signed (e.g. conhost.exe).

parameters:
  - name: processNamesRegex
    description: A regex to select running processes which we consider should be trusted.
    default: (?i)lsass|svchost|conhost|taskmgr|winlogon|wmiprv|dwm|csrss|velociraptor

sources:
  - precondition: |
      SELECT OS From info() where OS = 'windows'
    queries:
      - |
        LET binaries = SELECT lowcase(string=Exe) As Binary
          FROM pslist()
          WHERE Exe =~ processNamesRegex
          GROUP BY Binary

      - |
        LET auth = SELECT authenticode(filename=Binary) As Authenticode
        FROM binaries
      - |
        SELECT Authenticode.Filename As Filename,
               Authenticode.IssuerName as Issuer,
               Authenticode.SubjectName as Subject,
               Authenticode.Trusted as Trusted from auth
```
   {{% /expand %}}

