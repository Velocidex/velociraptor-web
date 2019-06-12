---
description: Triage artifacts simply collect various files as quickly as possible.
linktitle: Windows Triage
menu:
  docs: {parent: Artifacts, weight: 15}
title: Windows Triage Artifacts
toc: true

---
## Windows.Triage.Collectors.Amcache



{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.Amcache

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Amcache",
               accessor="ntfs",
               path="C:\\Windows\\AppCompat\\Programs\\Amcache.hve")
          },
          a2={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Amcache transaction files",
               accessor="ntfs",
               path="C:\\Windows\\AppCompat\\Programs\\Amcache.hve.LOG*")
          })
```
   {{% /expand %}}

## Windows.Triage.Collectors.BCD

Boot Configuration Files.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.BCD
description: |
  Boot Configuration Files.

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="BCD",
               path=[
                  "C:\\Boot\\BCD",
                  "C:\\Boot\\BCD.LOG*"
               ])
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.Chrome

Collect Chrome related artifacts.


Arg|Default|Description
---|------|-----------
baseLocations|C:\\Documents and Settings\\*\\Local Settings\\Application Data\\Google\\Chrome\\User Data\\*\\,C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\|Globs for different possible locations of firefox profiles.

{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.Chrome
description: |
  Collect Chrome related artifacts.

precondition: SELECT OS From info() where OS = 'windows'

parameters:
  - name: baseLocations
    description: Globs for different possible locations of firefox profiles.
    default: C:\Documents and Settings\*\Local Settings\Application Data\Google\Chrome\User Data\*\,C:\Users\*\AppData\Local\Google\Chrome\User Data\*\

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Chrome bookmarks",
               path=split(string=baseLocations, sep=",") + "Bookmarks*")
          },
          a2={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Chrome Cookies",
               path=split(string=baseLocations, sep=",") + "Cookies*")
          },
          a3={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Chrome Current Session",
               path=split(string=baseLocations, sep=",") + "Current Session")
          },
          a4={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Chrome Current Tabs",
               path=split(string=baseLocations, sep=",") + "Current Tabs")
          },
          a5={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Chrome Favicons",
               path=split(string=baseLocations, sep=",") + "Favicons*")
          },
          a6={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Chrome History",
               path=split(string=baseLocations, sep=",") + "History*")
          },
          a7={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Chrome Last Session",
               path=split(string=baseLocations, sep=",") + "Last Session")
          },
          a8={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Chrome Last Tabs",
               path=split(string=baseLocations, sep=",") + "Last Tabs")
          },
          a9={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Chrome Preferences",
               path=split(string=baseLocations, sep=",") + "Preferences")
          },
          b1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Chrome Shortcuts",
               path=split(string=baseLocations, sep=",") + "Shortcuts*")
          },
          b2={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Chrome Top Sites",
               path=split(string=baseLocations, sep=",") + "Top Sites*")
          },
          b3={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Chrome Visited Links",
               path=split(string=baseLocations, sep=",") + "Visited Links")
          },
          b4={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Chrome Web Data",
               path=split(string=baseLocations, sep=",") + "Web Data*")
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.Edge

Collect Edge related artifacts.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.Edge
description: |
  Collect Edge related artifacts.

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Edge folder",
               path="C:\\Users\\*\\AppData\\Local\\Packages\\Microsoft.MicrosoftEdge_*\\**")
          },
          a2={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="WebcacheV01.dat",
               path="C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\WebCache\\**")
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.EventLogs

Collect event log files.


Arg|Default|Description
---|------|-----------
EventLogGlobs|C:\\Windows\\system32\\config\\*.evt,C:\\Windows\\system32\\winevt\\logs\\*.evtx|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.EventLogs
description: |
  Collect event log files.

parameters:
  - name: EventLogGlobs
    default: C:\Windows\system32\config\*.evt,C:\Windows\system32\winevt\logs\*.evtx

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM Artifact.Triage.Collection.Upload(
           type="EventLogs",
           path=split(string=EventLogGlobs, sep=","))
```
   {{% /expand %}}

## Windows.Triage.Collectors.EventTraceLogs

Collect event trace log files.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.EventTraceLogs
description: |
  Collect event trace log files.

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
            type="WDI Trace Logs",
            path=[
              "C:\\Windows\\System32\\WDI\\LogFiles\\*.etl*",
              "C:\\Windows\\System32\\WDI\\{*"
            ])
          },
          a2={ SELECT * FROM Artifact.Triage.Collection.Upload(
            type="WMI Trace Logs",
            path="C:\\Windows\\System32\\LogFiles\\WMI\\*")
          },
          a3={ SELECT * FROM Artifact.Triage.Collection.Upload(
            type="SleepStudy Trace Logs",
            path="C:\\Windows\\System32\\SleepStudy*")
          },
          a4={ SELECT * FROM Artifact.Triage.Collection.Upload(
            type="Energy-NTKL Trace Logs",
            path="C:\\ProgramData\\Microsoft\\Windows\\PowerEfficiency Diagnostics\\energy-ntkl.etl")
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.EvidenceOfExecution



{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.EvidenceOfExecution

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Prefetch",
               path="C:\\Windows\\prefetch\\*.pf")
          },
          a2={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="RecentFileCache",
               path="C:\\Windows\\AppCompat\\Programs\\RecentFileCache.bcf")
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.Firefox

Collect Firefox related artifacts.


Arg|Default|Description
---|------|-----------
baseLocations|C:\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\\,C:\\Documents and Settings\\*\\Application Data\\Mozilla\\Firefox\\Profiles\\*\\|Globs for different possible locations of firefox profiles.

{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.Firefox
description: |
  Collect Firefox related artifacts.

precondition: SELECT OS From info() where OS = 'windows'

parameters:
  - name: baseLocations
    description: Globs for different possible locations of firefox profiles.
    default: C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\,C:\Documents and Settings\*\Application Data\Mozilla\Firefox\Profiles\*\

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Places",
               path=split(string=baseLocations, sep=",") + "places.sqlite*")
          },
          a2={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Downloads",
               path=split(string=baseLocations, sep=",") + "downloads.sqlite*")
          },
          a3={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Form history",
               path=split(string=baseLocations, sep=",") + "formhistory.sqlite*")
          },
          a4={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Cookies",
               path=split(string=baseLocations, sep=",") + "cookies.sqlite*")
          },
          a5={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Signons",
               path=split(string=baseLocations, sep=",") + "signons.sqlite*")
          },
          a6={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Webappstore",
               path=split(string=baseLocations, sep=",") + "webappstore.sqlite*")
          },
          a7={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Favicons",
               path=split(string=baseLocations, sep=",") + "favicons.sqlite*")
          },
          a8={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Addons",
               path=split(string=baseLocations, sep=",") + "addons.sqlite*")
          },
          a9={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Search",
               path=split(string=baseLocations, sep=",") + "search.sqlite*")
          }
          )
```
   {{% /expand %}}

## Windows.Triage.Collectors.InternetExplorer

Collect Firefox related artifacts.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.InternetExplorer
description: |
  Collect Firefox related artifacts.

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Index.dat History",
               path=[
                 "C:\\Documents and Settings\\*\\Local Settings\\History\\History.IE5\\index.dat",
                 "C:\\Documents and Settings\\*\\Local Settings\\History\\History.IE5\\*\\index.dat"
               ])
          },
          a2={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Index.dat temp internet files",
               path="C:\\Documents and Settings\\*\\Local Settings\\Temporary Internet Files\\Content.IE5\\index.dat")
          },
          a3={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Index.dat cookies",
               path="C:\\Documents and Settings\\*\\Cookies\\index.dat")
          },
          a4={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Index.dat UserData",
               path="C:\\Documents and Settings\\*\\Application Data\\Microsoft\\Internet Explorer\\UserData\\index.dat")
          },
          a5={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Index.dat Office XP",
               path="C:\\Documents and Settings\\*\\Application Data\\Microsoft\\Office\\Recent\\index.dat")
          },
          a6={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Index.dat Office",
               path="C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Office\\Recent\\index.dat")
          },
          a7={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Local Internet Explorer folder",
               path="C:\\Users\\*\\AppData\\Local\\Microsoft\\Internet Explorer\\**")
          },
          a8={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Roaming Internet Explorer folder",
               path="C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Internet Explorer\\**")
          },
          a9={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="IE 9/10 History",
               path="C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\History\\**")
          },
          b1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="IE 9/10 Cache",
               path="C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\**")
          },
          b2={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="IE 9/10 Cookies",
               path="C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\Cookies\\**")
          },
          b3={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="IE 9/10 Download History",
               path="C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\IEDownloadHistory\\**")
          },
          b4={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="IE 11 Metadata",
               accessor="ntfs",
               path="C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\WebCache\\**")
          },
          b5={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="IE 11 Cache",
               accessor="ntfs",
               path="C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\**")
          },
          b6={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="IE 11 Cookies",
               path="C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCookies\\**")
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.Jabber

Jabber.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.Jabber
description: |
  Jabber.

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Cisco Jabber Database",
               accessor="ntfs",
               path=[
                 "C:\\Users\\*\\AppData\\Local\\Cisco\\Unified Communications\\Jabber\\CSF\\History\\*.db"
               ])
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.LnkFiles

Lnk files and jump lists.

{{ Query "SELECT * FROM Rows" }}


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.LnkFiles
description: |
  Lnk files and jump lists.

  {{ Query "SELECT * FROM Rows" }}

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Lnk files from Recent",
               path=[
                 "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\**",
                 "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Office\\Recent\\**",
                 "C:\\Documents and Settings\\*\\Recent\\**"
               ])
          },
          a2={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Desktop lnk files",
               path=[
                 "C:\\Documents and Settings\\*\\Desktop\\*.lnk",
                 "C:\\Users\\*\\Desktop\\*.lnk"
              ])
          },
          a3={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Restore point lnk files XP",
               path="C:\\System Volume Information\\_restore*\\RP*\\*.lnk")
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.NTFSMetadata

{{ Query "SELECT * FROM Rows" }}


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.NTFSMetadata
description: |
  {{ Query "SELECT * FROM Rows" }}

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - name: NTFS Metadata Files
    queries:
      - |
        SELECT * FROM Artifact.Triage.Collection.Upload(
        type="NTFS Metadata Files",
        accessor="ntfs",
        path=[
            "C:\\$MFT",
            "C:\\$LogFile",
            "C:\\$Extend\\$UsnJrnl:$J",
            "C:\\$Extend\\$UsnJrnl:$Max",
            "C:\\$Secure:$SDS",
            "C:\\$Boot",
            "C:\\$Extend\\$RmMetadata\\$TxfLog\\$Tops:$T"
        ])
```
   {{% /expand %}}

## Windows.Triage.Collectors.OutlookPST

Outlook PST and OST files.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.OutlookPST
description: |
  Outlook PST and OST files.

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="PST",
               path=[
                 "C:\\Documents and Settings\\*\\Local Settings\\Application Data\\Microsoft\\Outlook\\*.pst",
                 "C:\\Users\\*\\AppData\\Local\\Microsoft\\Outlook\\*.pst"
               ])
          },
          a2={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="OST",
               path=[
                 "C:\\Documents and Settings\\*\\Local Settings\\Application Data\\Microsoft\\Outlook\\*.ost",
                 "C:\\Users\\*\\AppData\\Local\\Microsoft\\Outlook\\*.ost"
              ])
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.PowershellConsoleLogs

PowerShell Console Log File.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.PowershellConsoleLogs
description: |
  PowerShell Console Log File.

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="PowerShell Console Log",
               path="C:\\users\\*\\Appdata\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt")
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.RecycleBin

Collect contents of Recycle Bin.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.RecycleBin
description: |
  Collect contents of Recycle Bin.


precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Recycle.Bin",
               path=[
                 "C:\\$Recycle.Bin\\**",
                 "C:\\RECYCLER\\**"
               ])
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.RegistryHives

System and user related Registry hives.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.RegistryHives
description: |
  System and user related Registry hives.

precondition: SELECT OS From info() where OS = 'windows'
reference:
  - https://github.com/EricZimmerman/KapeFiles

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="ntuser.dat registry hive",
               accessor="ntfs",
               path=[
                 "C:\\Documents and Settings\\*\\ntuser.dat",
                 "C:\\Users\\*\\ntuser.dat"
               ])
          },
          a2={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="ntuser.dat registry transaction files",
               accessor="ntfs",
               path="C:\\Users\\*\\ntuser.dat.LOG*")
          },
          a3={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="UsrClass.dat registry hive",
               accessor="ntfs",
               path="C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat")
          },
          a4={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="UsrClass.dat registry transaction files",
               accessor="ntfs",
               path="C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat.LOG*")
          },
          a5={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="SAM registry transaction files",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\SAM.LOG*")
          },
          a6={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="SECURITY registry transaction files",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\SECURITY.LOG*")
          },
          a7={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="SOFTWARE registry transaction files",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\SOFTWARE.LOG*")
          },
          a8={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="SYSTEM registry transaction files",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\SYSTEM.LOG*")
          },
          a9={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="SAM registry hive",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\SAM")
          },
          b1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="SECURITY registry hive",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\SECURITY")
          },
          b2={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="SOFTWARE registry hive",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\SOFTWARE")
          },
          b3={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="SYSTEM registry hive",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\SYSTEM")
          },
          b4={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="RegBack registry transaction files",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\RegBack\\*.LOG*")
          },
          b5={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="SAM registry hive (RegBack)",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\RegBack\\SAM")
          },
          b6={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="SECURITY registry hive (RegBack)",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\RegBack\\SECURITY")
          },
          b7={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="SOFTWARE registry hive (RegBack)",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\RegBack\\SOFTWARE")
          },
          b8={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="SYSTEM registry hive (RegBack)",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\RegBack\\SYSTEM")
          },
          b9={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="SYSTEM registry hive (RegBack)",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\RegBack\\SYSTEM")
          },
          ba={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="System Profile registry hive",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\systemprofile\\ntuser.dat")
          },
          c1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="System Profile registry transaction files",
               accessor="ntfs",
               path="C:\\Windows\\System32\\config\\systemprofile\\ntuser.dat.LOG*")
          },
          c2={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Local Service registry hive",
               accessor="ntfs",
               path="C:\\Windows\\ServiceProfiles\\LocalService\\ntuser.dat")
          },
          c3={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Local Service registry transaction files",
               accessor="ntfs",
               path="C:\\Windows\\ServiceProfiles\\LocalService\\ntuser.dat.LOG*")
          },
          c4={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Network Service registry hive",
               accessor="ntfs",
               path="C:\\Windows\\ServiceProfiles\\NetworkService\\ntuser.dat")
          },
          c5={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Network Service registry transaction files",
               accessor="ntfs",
               path="C:\\Windows\\ServiceProfiles\\NetworkService\\ntuser.dat.LOG*")
          },
          c6={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="System Restore Points Registry Hives (XP)",
               accessor="ntfs",
               path="C:\\System Volume Information\\_restore*\\RP*\\snapshot\\_REGISTRY_*")
          }

        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.SRUM

System Resource Usage Monitor (SRUM) Data.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.SRUM
description: |
  System Resource Usage Monitor (SRUM) Data.

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="SRUM",
               path="C:\\Windows\\System32\\SRU\\**")
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.ScheduledTasks

Scheduled tasks (*.job and XML).


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.ScheduledTasks
description: |
  Scheduled tasks (*.job and XML).

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="at .job",
               path="C:\\Windows\\Tasks\\*.job")
          },
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="at SchedLgU.txt",
               path="C:\\Windows\\SchedLgU.txt")
          },
          a2={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="XML",
               path="C:\\Windows\\system32\\Tasks\\**")
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.Skype

Skype.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.Skype
description: |
  Skype.

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="main.db",
               path=[
                  "C:\\Users\\*\\AppData\\Local\\Packages\\Microsoft.SkypeApp_*\\LocalState\\*\\main.db",
                  "C:\\Documents and Settings\\*\\Application Data\\Skype\\*\\main.db",
                  "C:\\Users\\*\\AppData\\Roaming\\Skype\\*\\main.db"
               ])
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.StartupInfo

StartupInfo XML Files.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.StartupInfo
description: |
  StartupInfo XML Files.

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="StartupInfo XML Files",
               path=[
                  "C:\\Windows\\System32\\WDI\\LogFiles\\StartupInfo\\*.xml"
               ])
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.TeraCopy

TeraCopy log history.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.TeraCopy
description: |
  TeraCopy log history.

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="TeraCopy",
               path=[
                  "C:\\Users\\*\\AppData\\Roaming\\TeraCopy"
               ])
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.ThumbDB

Thumbcache DB.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.ThumbDB
description: |
  Thumbcache DB.

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Thumbcache DB",
               path=[
                  "C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\Explorer\\thumbcache_*.db"
               ])
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.USBDeviceLogs

USB devices log files.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.USBDeviceLogs
description: |
  USB devices log files.

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Setupapi.log",
               path=[
                  "C:\\Windows\\setupapi.log",
                  "C:\\Windows\\inf\\setupapi.dev.log"
               ])
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.WBEM

Web-Based Enterprise Management (WBEM).


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.WBEM
description: |
  Web-Based Enterprise Management (WBEM).

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="WBEM",
               path=[
                 "C:\\Windows\\System32\\wbem\\Repository"
               ])
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.WindowsFirewall

Windows Firewall Logs.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.WindowsFirewall
description: |
  Windows Firewall Logs.

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="Windows Firewall Logs",
               path="C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.*")
          }
        )
```
   {{% /expand %}}

## Windows.Triage.Collectors.WindowsIndex

Windows Index Search.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.Collectors.WindowsIndex
description: |
  Windows Index Search.

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Triage.Collection.Upload(
               type="WindowsIndexSearch",
               path="C:\\programdata\\microsoft\\search\\data\\applications\\windows\\Windows.edb")
          }
        )
```
   {{% /expand %}}

## Windows.Triage.ProcessMemory

Dump process memory and upload to the server


Arg|Default|Description
---|------|-----------
processRegex|notepad|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.ProcessMemory
description: |
  Dump process memory and upload to the server

precondition: SELECT OS From info() where OS = 'windows'

parameters:
  - name: processRegex
    default: notepad

sources:
  - queries:
      - |
        LET processes = SELECT Name as ProcessName, CommandLine, Pid
            FROM pslist()
            WHERE Name =~ processRegex

      - |
        SELECT * FROM foreach(
          row=processes,
          query={
            SELECT ProcessName, CommandLine, Pid, FullPath,
                   upload(file=FullPath) as CrashDump
            FROM proc_dump(pid=Pid)
          })
```
   {{% /expand %}}

## Windows.Triage.WebBrowsers

A high level artifact for selecting all browser related artifacts.


{{% expand  "View Artifact Source" %}}


```
name: Windows.Triage.WebBrowsers
description: |
  A high level artifact for selecting all browser related artifacts.

precondition: SELECT OS From info() where OS = 'windows'

sources:
  - queries:
      - |
        SELECT * FROM chain(
          a1={ SELECT * FROM Artifact.Windows.Triage.Collectors.Chrome() },
          a2={ SELECT * FROM Artifact.Windows.Triage.Collectors.Firefox() },
          a3={ SELECT * FROM Artifact.Windows.Triage.Collectors.Edge() },
          a4={ SELECT * FROM Artifact.Windows.Triage.Collectors.InternetExplorer() }
        )
```
   {{% /expand %}}

## Triage.Collection.Upload

A Generic uploader used by triaging artifacts.


Arg|Default|Description
---|------|-----------
path||This is the glob of the files we use.
type||The type of files these are.
accessor|file|

{{% expand  "View Artifact Source" %}}


```
name: Triage.Collection.Upload
description: |
  A Generic uploader used by triaging artifacts.

parameters:
  - name: path
    description: This is the glob of the files we use.
  - name: type
    description: The type of files these are.
  - name: accessor
    default: file

sources:
  - queries:
      - |
        LET results = SELECT FullPath, Size,
               timestamp(epoch=Mtime.Sec) As Modifed,
               type AS Type, {
                 SELECT * FROM upload(files=FullPath, accessor=accessor)
               } AS FileDetails
        FROM glob(globs=path, accessor=accessor)
        WHERE NOT IsDir
      - |
        SELECT FullPath, Size, Modifed, Type,
               FileDetails.Path AS ZipPath,
               FileDetails.Md5 as Md5,
               FileDetails.Sha256 as SHA256
        FROM results
```
   {{% /expand %}}

## Windows.Forensics.Bam

The Background Activity Moderator (BAM) is a Windows service that
Controls activity of background applications.  This service exists
in Windows 10 only after Fall Creators update – version 1709.

It provides full path of the executable file that was run on the
system and last execution date/time


Arg|Default|Description
---|------|-----------
bamKeys|HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings\\*|

{{% expand  "View Artifact Source" %}}


```
name: Windows.Forensics.Bam
description: |
  The Background Activity Moderator (BAM) is a Windows service that
  Controls activity of background applications.  This service exists
  in Windows 10 only after Fall Creators update – version 1709.

  It provides full path of the executable file that was run on the
  system and last execution date/time

reference:
  - https://www.andreafortuna.org/dfir/forensic-artifacts-evidences-of-program-execution-on-windows-systems/

parameters:
    - name: bamKeys
      default: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\UserSettings\*

sources:
  - precondition:
      SELECT OS from info() where OS = "windows"
    queries:
      - |
        LET users <= SELECT Name, UUID FROM Artifact.Windows.Sys.Users()
      - |
        SELECT basename(path=dirname(path=FullPath)) as SID, {
            SELECT Name FROM users WHERE UUID = basename(path=dirname(path=FullPath))
          } As UserName,
          Name as Binary,
          timestamp(winfiletime=binary_parse(
          string=Data.value, target="int64").AsInteger) as Bam_time
        FROM glob(globs=bamKeys + "\\*", accessor="reg")
        WHERE Data.type = "BINARY"
```
   {{% /expand %}}

