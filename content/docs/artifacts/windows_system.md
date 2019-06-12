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


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Sys_AppcompatShimsDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Sys_AppcompatShimsDetails" style="width: fit-content">


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
   </div></a>

## Windows.Sys.CertificateAuthorities

Certificate Authorities installed in Keychains/ca-bundles.


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Sys_CertificateAuthoritiesDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Sys_CertificateAuthoritiesDetails" style="width: fit-content">


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
   </div></a>

## Windows.Sys.DiskInfo

Retrieve basic information about the physical disks of a system.


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Sys_DiskInfoDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Sys_DiskInfoDetails" style="width: fit-content">


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
   </div></a>

## Windows.Sys.Drivers

Details for in-use Windows device drivers. This does not display installed but unused drivers.


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Sys_DriversDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Sys_DriversDetails" style="width: fit-content">


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
   </div></a>

## Windows.Sys.FirewallRules

List windows firewall rules.

Arg|Default|Description
---|------|-----------
regKey|HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\**\\FirewallRules\\*|


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Sys_FirewallRulesDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Sys_FirewallRulesDetails" style="width: fit-content">


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
   </div></a>

## Windows.Sys.Interfaces

Report information about the systems interfaces. This artifact
simply parses the output from ipconfig /all.



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Sys_InterfacesDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Sys_InterfacesDetails" style="width: fit-content">


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
   </div></a>

## Windows.Sys.PhysicalMemoryRanges

List Windows physical memory ranges.

Arg|Default|Description
---|------|-----------
physicalMemoryKey|HKEY_LOCAL_MACHINE\\HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory\\.Translated|
Profile|{\n  "CM_RESOURCE_LIST": [0, {\n    "Count": [0, ["uint32"]],\n    "List": [4, ["CM_FULL_RESOURCE_DESCRIPTOR"]]\n   }],\n   "CM_FULL_RESOURCE_DESCRIPTOR": [0, {\n     "PartialResourceList": [8, ["CM_PARTIAL_RESOURCE_LIST"]]\n   }],\n\n   "CM_PARTIAL_RESOURCE_LIST": [0, {\n     "Version": [0, ["uint16"]],\n     "Revision": [2, ["uint16"]],\n     "Count": [4, ["uint32"]],\n     "PartialDescriptors": [8, ["Array", {\n        "Target": "CM_PARTIAL_RESOURCE_DESCRIPTOR"\n     }]]\n   }],\n\n   "CM_PARTIAL_RESOURCE_DESCRIPTOR": [20, {\n     "Type": [0, ["char"]],\n     "ShareDisposition": [1, ["char"]],\n     "Flags": [2, ["uint16"]],\n     "Start": [4, ["int64"]],\n     "Length": [12, ["uint32"]]\n   }]\n}\n|


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Sys_PhysicalMemoryRangesDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Sys_PhysicalMemoryRangesDetails" style="width: fit-content">


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
   </div></a>

## Windows.Sys.Programs

Represents products as they are installed by Windows Installer. A product generally
correlates to one installation package on Windows. Some fields may be blank as Windows
installation details are left to the discretion of the product author.


Arg|Default|Description
---|------|-----------
programKeys|HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*|


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Sys_ProgramsDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Sys_ProgramsDetails" style="width: fit-content">


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
   </div></a>

## Windows.Sys.StartupItems

Applications that will be started up from the various run key locations.

Arg|Default|Description
---|------|-----------
runKeyGlobs|HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*\\*, HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run*\\*, HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run*\\* HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*\\*, HKEY_USERS\\*\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run*\\*, HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run*\\*\n|
startupApprovedGlobs|HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\**, HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\**\n|
startupFolderDirectories|C:/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/**, C:/Users/*/AppData/Roaming/Microsoft/Windows/StartMenu/Programs/Startup/**\n|


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Sys_StartupItemsDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Sys_StartupItemsDetails" style="width: fit-content">


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

      - SELECT * from chain(
           first=registry_runners,
           second=file_runners)
```
   </div></a>

## Windows.Sys.Users

List User accounts. We combine two data sources - the output from
the NetUserEnum() call and the list of SIDs in the registry.


Arg|Default|Description
---|------|-----------
remoteRegKey|HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\*|


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_Sys_UsersDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_Sys_UsersDetails" style="width: fit-content">


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
        LET roaming_users <=
           SELECT "" as Uid, "" as Gid,
               lookupSID(
                 sid=basename(path=Key.FullPath)
               ) as Name,
               Key.FullPath as Description,
               ProfileImagePath as Directory,
               basename(path=Key.FullPath) as UUID, "roaming" as Type
           FROM read_reg_key(globs=remoteRegKey, accessor="reg")
      - |
        LET local_users <= select User_id as Uid, Primary_group_id as Gid, Name,
               Comment as Description, {
                 SELECT Directory from roaming_users WHERE User_sid = UUID
               } as Directory, User_sid as UUID, "local" AS Type
        FROM users()

      - |
        SELECT * from chain(
         q1=local_users,
         q2={
           -- Only show users not already shown in the local_users above.
           SELECT * from roaming_users
           where not UUID in local_users.UUID
         })
```
   </div></a>

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


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_System_AmcacheDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_System_AmcacheDetails" style="width: fit-content">


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

sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'
    queries:
      - |
        SELECT FileId,
               Key.FullPath as Key,
               timestamp(epoch=Key.Mtime.Sec) as LastModified,
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
               globs=url(scheme='ntfs', path=FullPath, fragment=amCacheRegPath).String,
               accessor='raw_reg'
            )
        })
```
   </div></a>

## Windows.System.Pslist

List processes and their running binaries.


Arg|Default|Description
---|------|-----------
processRegex|.|


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_System_PslistDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_System_PslistDetails" style="width: fit-content">


```
name: Windows.System.Pslist
description: |
  List processes and their running binaries.

parameters:
  - name: processRegex
    default: .

sources:
  - queries:
      - SELECT Pid, Ppid, Name, CommandLine, Exe,
               hash(path=Exe) as Hash,
               authenticode(filename=Exe) AS Authenticode,
               Username, WorkingSetSize
        FROM pslist()
        WHERE Name =~ processRegex
```
   </div></a>

## Windows.System.SVCHost

Typically a windows system will have many svchost.exe
processes. Sometimes attackers name their processes svchost.exe to
try to hide. Typically svchost.exe is spawned by services.exe.

This artifact lists all the processes named svchost.exe and their
parents if the parent is not also named services.exe.



 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_System_SVCHostDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_System_SVCHostDetails" style="width: fit-content">


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
   </div></a>

## Windows.System.Services

List all the installed services.


Arg|Default|Description
---|------|-----------
servicesKeyGlob|HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\|


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_System_ServicesDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_System_ServicesDetails" style="width: fit-content">


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
   </div></a>

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


 <a href="javascript:void(0)" class="js-toggle dib w-100 link mid-gray hover-accent-color-light pl2 pr2 pv2 "
    data-target="#Windows_System_UntrustedBinariesDetails">View Artifact</a>
 <div class="collapse dn" id="Windows_System_UntrustedBinariesDetails" style="width: fit-content">


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
   </div></a>

