---
description: These artifacts collect information related to the windows registry.
linktitle: Registry
title: Registry
weight: 30

---
## Windows.Registry.AppCompatCache

Parses the system's app compatibility cache.


Arg|Default|Description
---|------|-----------
AppCompatCacheKey|HKEY_LOCAL_MACHINE/System/ControlSet*/Control/Sess ...|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Registry.AppCompatCache
description: |
  Parses the system's app compatibility cache.

parameters:
  - name: AppCompatCacheKey
    default: HKEY_LOCAL_MACHINE/System/ControlSet*/Control/Session Manager/AppCompatCache/AppCompatCache

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - LET AppCompatKeys = SELECT * FROM glob(globs=AppCompatCacheKey, accessor='reg')
      - SELECT * FROM foreach(
          row={
              SELECT Filename, Data FROM read_file(
                  filenames=AppCompatKeys.FullPath, accessor='reg')
          }, query={
              SELECT Filename AS Key, name as Name, epoch, time
              FROM appcompatcache(value=Data)
        }) WHERE epoch < 2000000000
```
   {{% /expand %}}

## Windows.Registry.EnableUnsafeClientMailRules

Checks for Outlook EnableUnsafeClientMailRules = 1 (turned on).
This registry key enables execution from Outlook inbox rules which can be used as a persistence mechanism.
Microsoft has released a patch to disable execution but attackers can reenable by changing this value to 1.

HKEY_USERS\*\Software\Microsoft\Office\*\Outlook\Security\EnableUnsafeClientMailRules = 0 (expected)
https://support.microsoft.com/en-us/help/3191893/how-to-control-the-rule-actions-to-start-an-application-or-run-a-macro


Arg|Default|Description
---|------|-----------
KeyGlob|Software\\Microsoft\\Office\\*\\Outlook\\Security\ ...|
userRegex|.|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Registry.EnableUnsafeClientMailRules
description: |
  Checks for Outlook EnableUnsafeClientMailRules = 1 (turned on).
  This registry key enables execution from Outlook inbox rules which can be used as a persistence mechanism.
  Microsoft has released a patch to disable execution but attackers can reenable by changing this value to 1.

  HKEY_USERS\*\Software\Microsoft\Office\*\Outlook\Security\EnableUnsafeClientMailRules = 0 (expected)
  https://support.microsoft.com/en-us/help/3191893/how-to-control-the-rule-actions-to-start-an-application-or-run-a-macro

author: "@mgreen27"

precondition: SELECT OS From info() where OS = 'windows'

parameters:
   - name: KeyGlob
     default: Software\Microsoft\Office\*\Outlook\Security\
   - name: userRegex
     default: .

sources:
  - queries:
      - |
        LET UserProfiles = Select Name as Username,
            {
                SELECT FullPath FROM glob(globs=expand(path=Directory) + "//NTUSER.DAT", accessor="file")
            } as NTUser,
            expand(path=Directory) as Directory
        FROM Artifact.Windows.Sys.Users()
        WHERE Directory and NTUser and Name =~ userRegex
      - |
         SELECT * FROM foreach(
           row={
              SELECT Username, NTUser FROM UserProfiles
           },
           query={
              SELECT Username,
                NTUser as Userhive,
                url(parse=key.FullPath).fragment as Key,
                timestamp(epoch=key.Mtime.Sec) AS LastModified,
                EnableUnsafeClientMailRules,
                OutlookSecureTempFolder
              FROM read_reg_key(
                 globs=url(scheme="ntfs",
                    path=FullPath,
                    fragment=KeyGlob).String,
                 accessor="raw_reg")
              WHERE EnableUnsafeClientMailRules = 1
           })
```
   {{% /expand %}}

## Windows.Registry.EnabledMacro

Checks for Registry key indicating macro was enabled by user.

HKEY_USERS\*\Software\Microsoft\Office\*\Security\Trusted Documents\TrustRecords reg keys for values ending in FFFFFF7F
http://az4n6.blogspot.com/2016/02/more-on-trust-records-macros-and.html


Arg|Default|Description
---|------|-----------
KeyGlob|Software\\Microsoft\\Office\\*\\*\\Security\\Trust ...|
userRegex|.|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Registry.EnabledMacro
description: |
  Checks for Registry key indicating macro was enabled by user.

  HKEY_USERS\*\Software\Microsoft\Office\*\Security\Trusted Documents\TrustRecords reg keys for values ending in FFFFFF7F
  http://az4n6.blogspot.com/2016/02/more-on-trust-records-macros-and.html

author: "@mgreen27"

precondition: SELECT OS From info() where OS = 'windows'

parameters:
 - name: KeyGlob
   default: Software\Microsoft\Office\*\*\Security\Trusted Documents\TrustRecords\*
 - name: userRegex
   default: .

sources:
 - queries:
      - |
        LET UserProfiles = Select Name as Username,
            {
                SELECT FullPath FROM glob(globs=expand(path=Directory) + "//NTUSER.DAT", accessor="file")
            } as NTUser,
            expand(path=Directory) as Directory
        FROM Artifact.Windows.Sys.Users()
        WHERE Directory and NTUser and Name =~ userRegex
      - |
        SELECT * FROM foreach(
          row={
            SELECT Username,NTUser FROM UserProfiles
          },
          query={
            SELECT Name as Document,
              Username,
              NTUser as Userhive,
              dirname(path=url(parse=FullPath).fragment) as Key,
              timestamp(epoch=Mtime.Sec) AS LastModified
            FROM glob(
              globs=url(scheme="ntfs",
                path=NTUser,
                fragment=KeyGlob).String,
              accessor="raw_reg")
            WHERE Data.type = "REG_BINARY" and encode(string=Data.value, type="hex") =~ "ffffff7f$"
          })
```
   {{% /expand %}}

## Windows.Registry.MountPoints2

This detection will collect any items in the MountPoints2 registry key.
With a "$" in the share path. This key will store all remotely mapped
drives unless removed so is a great hunt for simple admin $ mapping based
lateral movement.


Arg|Default|Description
---|------|-----------
KeyGlob|Software\\Microsoft\\Windows\\CurrentVersion\\Expl ...|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Registry.MountPoints2
description: |
    This detection will collect any items in the MountPoints2 registry key.
    With a "$" in the share path. This key will store all remotely mapped
    drives unless removed so is a great hunt for simple admin $ mapping based
    lateral movement.
    
author: Matt Green - @mgreen27

precondition: SELECT OS From info() where OS = 'windows'

parameters:
 - name: KeyGlob
   default: Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\*

sources:
 - queries:
     - |
        SELECT regex_replace(source=basename(path=url(parse=FullPath).Fragment), 
          re="#", replace="\\") as MountPoint,
          timestamp(epoch=Mtime) as ModifiedTime,
          Username,
          url(parse=FullPath).Path as Hive,
          url(parse=FullPath).Fragment as Key
        FROM Artifact.Windows.Registry.NTUser(KeyGlob=KeyGlob)
        WHERE FullPath =~ "\\$"
```
   {{% /expand %}}

## Windows.Registry.NTUser

This artifact searches for keys or values within the user's
NTUser.dat registry hives.

When a user logs into a windows machine the system creates their own
"profile" which consists of a registry hive mapped into the
HKEY_USERS hive. This hive file is locked as long as the user is
logged in. If the user is not logged in, the file is not mapped at
all.

This artifact bypasses the locking mechanism by parsing the raw NTFS
filesystem to recover the registry hives. We then parse the registry
hives to search for the glob provided.

This artifact is designed to be reused by other artifacts that need
to access user data.

{{% notice note %}}

  Any artifacts that look into the HKEY_USERS registry hive should
  be using the `Windows.Registry.NTUser` artifact instead of
  accessing the hive via the API. The API only makes the currently
  logged in users available in that hive and so if we rely on the
  windows API we will likely miss any settings for users not
  currently logged on.

{{% /notice %}}


Arg|Default|Description
---|------|-----------
KeyGlob|Software\\Microsoft\\Windows\\CurrentVersion\\Expl ...|
userRegex|.|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Registry.NTUser
description: |
  This artifact searches for keys or values within the user's
  NTUser.dat registry hives.

  When a user logs into a windows machine the system creates their own
  "profile" which consists of a registry hive mapped into the
  HKEY_USERS hive. This hive file is locked as long as the user is
  logged in. If the user is not logged in, the file is not mapped at
  all.

  This artifact bypasses the locking mechanism by parsing the raw NTFS
  filesystem to recover the registry hives. We then parse the registry
  hives to search for the glob provided.

  This artifact is designed to be reused by other artifacts that need
  to access user data.

  {{% notice note %}}

    Any artifacts that look into the HKEY_USERS registry hive should
    be using the `Windows.Registry.NTUser` artifact instead of
    accessing the hive via the API. The API only makes the currently
    logged in users available in that hive and so if we rely on the
    windows API we will likely miss any settings for users not
    currently logged on.

  {{% /notice %}}

precondition: SELECT OS From info() where OS = 'windows'

parameters:
 - name: KeyGlob
   default: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\**
 - name: userRegex
   default: .

sources:
 - queries:
     - |
        LET UserProfiles = SELECT Uid,
            Gid,
            Name as Username,
            Description,
            UUID,
            {
                SELECT FullPath FROM glob(globs=expand(path=Directory) + "//NTUSER.DAT", accessor="file")
            } as FullPath,
            expand(path=Directory) as Directory
        FROM Artifact.Windows.Sys.Users()
        WHERE Directory and FullPath AND Name =~ userRegex
     - |
       SELECT * FROM foreach(
            row={
                SELECT * FROM UserProfiles
            },
            query={
                SELECT FullPath, Data, Mtime.Sec AS Mtime, Username, Description, Uid, Gid, UUID, Directory
                FROM glob(
                    globs=url(scheme="ntfs",
                    path=FullPath,
                    fragment=KeyGlob).String,
                    accessor="raw_reg")
            })
```
   {{% /expand %}}

## Windows.Registry.NTUser.Upload

This artifact collects all the user's NTUser.dat registry hives.

When a user logs into a windows machine the system creates their own
"profile" which consists of a registry hive mapped into the
HKEY_USERS hive. This hive file is locked as long as the user is
logged in.

This artifact bypasses the locking mechanism by extracting the
registry hives using raw NTFS parsing. We then just upload all hives
to the server.


Arg|Default|Description
---|------|-----------
userRegex|.|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Registry.NTUser.Upload
description: |
  This artifact collects all the user's NTUser.dat registry hives.

  When a user logs into a windows machine the system creates their own
  "profile" which consists of a registry hive mapped into the
  HKEY_USERS hive. This hive file is locked as long as the user is
  logged in.

  This artifact bypasses the locking mechanism by extracting the
  registry hives using raw NTFS parsing. We then just upload all hives
  to the server.

parameters:
  - name: userRegex
    default: .

sources:
  - precondition: |
      SELECT OS From info() where OS = 'windows'
    queries:
      - |
        LET users = SELECT Name, Directory as HomeDir
            FROM Artifact.Windows.Sys.Users()
            WHERE Directory AND Name =~ userRegex

      - |
        SELECT upload(file=expand(path=HomeDir) + "\\ntuser.dat",
                      accessor="ntfs") as Upload
        FROM users
```
   {{% /expand %}}

## Windows.Registry.PortProxy

**Description**: 
This artifact will return any items in the Windows PortProxy service 
registry path. The most common configuration of this service is via the
lolbin netsh.exe; Metaspoit and other common attack tools also have 
configuration modules.

**Reference**: [Port Proxy detection]
(http://www.dfirnotes.net/portproxy_detection/)  

**ATT&CK**: [T1090 - Connection Proxy](https://attack.mitre.org/techniques/T1090/)  
Adversaries may use a connection proxy to direct network traffic between
systems or act as an intermediary for network communications to a command 
and control server to avoid direct connections to their infrastructure.


Arg|Default|Description
---|------|-----------
KeyGlob|HKEY_LOCAL_MACHINE\\SYSTEM\\*ControlSet*\\services ...|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Registry.PortProxy
description: |
    **Description**: 
    This artifact will return any items in the Windows PortProxy service 
    registry path. The most common configuration of this service is via the
    lolbin netsh.exe; Metaspoit and other common attack tools also have 
    configuration modules.

    **Reference**: [Port Proxy detection]
    (http://www.dfirnotes.net/portproxy_detection/)  

    **ATT&CK**: [T1090 - Connection Proxy](https://attack.mitre.org/techniques/T1090/)  
    Adversaries may use a connection proxy to direct network traffic between
    systems or act as an intermediary for network communications to a command 
    and control server to avoid direct connections to their infrastructure.
    
author: Matt Green - @mgreen27

precondition: SELECT OS From info() where OS = 'windows'

parameters:
 - name: KeyGlob
   default: HKEY_LOCAL_MACHINE\SYSTEM\*ControlSet*\services\PortProxy\**

sources:
 - name: PortProxy
   queries:
     - SELECT FullPath,
         basename(path=dirname(path=dirname(path=FullPath))) as ProxyType,
         basename(path=dirname(path=FullPath)) as Protocol,
         regex_replace(source=basename(path=FullPath),re="/",replace=":") as Listening,
         regex_replace(source=Data.value,re="/",replace=":") as Destination,
         timestamp(epoch=Mtime.sec) as ModifiedTime,
         Type
       FROM glob(globs=KeyGlob, accessor="reg")
       WHERE Type


reports:
  - type: CLIENT
    template: |

      Port Forwarding: PortProxy
      ==========================
      {{ .Description }}
      
      {{ define "report" }}
         LET report = SELECT Protocol, 
            ProxyType, 
            Listening, 
            Destination, 
            ModifiedTime,
            ProxyType + Protocol + Listening + Destination as ServiceKey
         FROM source(source='PortProxy')
         GROUP BY ServiceKey
      {{ end }}
      
      {{ Query "report"  "SELECT ProxyType, Protocol, Listening, Destination, ModifiedTime FROM report" | Table }}
      
  - type: HUNT
    template: |

      Port Forwarding: PortProxy
      ==========================
      {{ .Description }}
      
      {{ define "report" }}
         LET report = SELECT Fqdn,
            Protocol, 
            ProxyType, 
            Listening, 
            Destination, 
            ModifiedTime,
            ProxyType + Protocol + Listening + Destination as ServiceKey
         FROM source(source='PortProxy')
         GROUP BY ServiceKey
      {{ end }}
      
      {{ Query "report"  "SELECT Fqdn, ProxyType, Protocol, Listening, Destination, ModifiedTime FROM report" | Table }}
```
   {{% /expand %}}

## Windows.Registry.Sysinternals.Eulacheck

Checks for the Accepted Sysinternals EULA from the registry key
"HKCU\Software\Sysinternals\[TOOL]\".  When a Sysinternals tool is
first run on a system, the EULA must be accepted. This writes a
value called EulaAccepted under that key.

Note: This artifact uses HKEY_USERS and therefore will not detect
users that are not currently logged on.


Arg|Default|Description
---|------|-----------
Sysinternals_Reg_Key|HKEY_USERS\\*\\Software\\Sysinternals\\*|
userRegex|.|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Registry.Sysinternals.Eulacheck
description: |
  Checks for the Accepted Sysinternals EULA from the registry key
  "HKCU\Software\Sysinternals\[TOOL]\".  When a Sysinternals tool is
  first run on a system, the EULA must be accepted. This writes a
  value called EulaAccepted under that key.

  Note: This artifact uses HKEY_USERS and therefore will not detect
  users that are not currently logged on.

parameters:
   - name: Sysinternals_Reg_Key
     default: HKEY_USERS\*\Software\Sysinternals\*
   - name: userRegex
     default: .

sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'

    queries:
    - |
      LET users <= SELECT Name, UUID
          FROM Artifact.Windows.Sys.Users()
          WHERE Name =~ userRegex
    - |
      SELECT Key.Name as ProgramName,
             Key.FullPath as Key,
             timestamp(epoch=Key.Mtime.Sec) AS TimeAccepted,
             {
                SELECT Name FROM users WHERE UUID=regex_replace(
                   source=Key.FullPath, re=".+\\\\(S-[^\\\\]+)\\\\.+", replace="$1")
             } as User,
             EulaAccepted
      FROM read_reg_key(globs=split(string=Sysinternals_Reg_Key, sep=',[\\s]*'))
```
   {{% /expand %}}

## Windows.Registry.UserAssist

Windows systems maintain a set of keys in the registry database
(UserAssist keys) to keep track of programs that executed. The
number of executions and last execution date and time are available
in these keys.

The information within the binary UserAssist values contains only
statistical data on the applications launched by the user via
Windows Explorer. Programs launched via the command­line (cmd.exe)
do not appear in these registry keys.

From a forensics perspective, being able to decode this information
can be very useful.


Arg|Default|Description
---|------|-----------
UserFilter||If specified we filter by this user ID.
ExecutionTimeAfter||If specified only show executions after this time.
UserAssistKey|Software\\Microsoft\\Windows\\CurrentVersion\\Expl ...|
userAssistProfile|{\n  "Win10": [0, {\n    "NumberOfExecutions": [4, ...|

{{% expand  "View Artifact Source" %}}


```text
name: Windows.Registry.UserAssist
description: |
  Windows systems maintain a set of keys in the registry database
  (UserAssist keys) to keep track of programs that executed. The
  number of executions and last execution date and time are available
  in these keys.

  The information within the binary UserAssist values contains only
  statistical data on the applications launched by the user via
  Windows Explorer. Programs launched via the command­line (cmd.exe)
  do not appear in these registry keys.

  From a forensics perspective, being able to decode this information
  can be very useful.

reference:
  - https://www.aldeid.com/wiki/Windows-userassist-keys

precondition: SELECT OS From info() where OS = 'windows'

parameters:
  - name: UserFilter
    default: ""
    description: If specified we filter by this user ID.

  - name: ExecutionTimeAfter
    default: ""
    type: timestamp
    description: If specified only show executions after this time.

  - name: UserAssistKey
    default: Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*\Count\*

  - name: userAssistProfile
    default: |
      {
        "Win10": [0, {
          "NumberOfExecutions": [4, ["unsigned int"]],
          "LastExecution": [60, ["unsigned long long"]]
        }]
      }

sources:
  - queries:
      - LET TMP = SELECT rot13(string=regex_replace(
             source=url(parse=FullPath).Fragment,
             re="^.+/Count/",
             replace="")) AS Name,
             binary_parse(
               string=Data.value,
               profile=userAssistProfile,
               target="Win10"
             ) As UserAssist,
             parse_string_with_regex(
               string=FullPath,
               regex="Users/(?P<User>[^/]+)/NTUSER").User AS User
        FROM Artifact.Windows.Registry.NTUser(KeyGlob=UserAssistKey)
      - LET UserAssist = SELECT Name,
               User,
               timestamp(
                  winfiletime=UserAssist.LastExecution.AsInteger) As LastExecution,
               timestamp(
                  winfiletime=UserAssist.LastExecution.AsInteger).Unix AS LastExecutionTS,
               UserAssist.NumberOfExecutions.AsInteger AS NumberOfExecutions
        FROM TMP
      - LET A1 = SELECT * FROM if(
          condition=UserFilter,
          then={
            SELECT * FROM UserAssist WHERE User =~ UserFilter
          }, else=UserAssist)
      - SELECT * FROM if(
          condition=ExecutionTimeAfter,
          then={
            SELECT * FROM A1 WHERE LastExecutionTS > ExecutionTimeAfter
          }, else=A1)
```
   {{% /expand %}}

